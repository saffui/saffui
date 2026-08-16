//! Applying what is pending, once, under the lock.

use crypto::provider::DigestProvider;
use tokio::task::JoinHandle;
use tokio_postgres::{Client, Config};

use crate::advisory_lock::{AdvisoryLock, AdvisoryLockKey, connect};
use crate::tls::PgConnector;

use super::error::MigrationError;
use super::migration::{AppliedRecord, Migration, plan};

/// How the run behaves against a database that is in use.
#[derive(Debug, Clone, Default)]
pub struct MigrationOptions {
    /// How long a statement waits for a lock before giving up.
    ///
    /// Unset means wait forever, which on a live database is how a migration
    /// takes the application down with it: the statement queues behind a long
    /// read and everything else queues behind the statement.
    pub lock_timeout_ms: Option<u64>,
}

/// What a run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    pub applied: Vec<i32>,
}

impl MigrationReport {
    pub fn is_up_to_date(&self) -> bool {
        self.applied.is_empty()
    }
}

/// The set, and how to apply it.
pub struct MigrationRunner {
    migrations: Vec<Migration>,
    options: MigrationOptions,
}

impl MigrationRunner {
    pub fn new(migrations: Vec<Migration>) -> Self {
        Self {
            migrations,
            options: MigrationOptions::default(),
        }
    }

    pub fn with_options(mut self, options: MigrationOptions) -> Self {
        self.options = options;
        self
    }

    /// Apply what is pending.
    ///
    /// The lock is taken first and held for the whole run, so two processes
    /// starting together do not both decide the same migration is pending.
    pub async fn run(
        &self,
        config: &Config,
        tls: &PgConnector,
        digest: &dyn DigestProvider,
    ) -> Result<MigrationReport, MigrationError> {
        let _lock = AdvisoryLock::acquire(config, tls, AdvisoryLockKey::MIGRATION_RUNNER)
            .await
            .map_err(|_| MigrationError::Lock)?;

        let mut connection = MaintConnection::open(config, tls).await?;
        connection.ensure_history_table().await?;

        let applied = connection.load_applied().await?;
        let pending = plan(&self.migrations, &applied, digest)?;

        let mut report = MigrationReport::default();
        for migration in pending {
            connection
                .set_lock_timeout(self.options.lock_timeout_ms)
                .await?;
            connection.apply(migration, digest).await?;
            report.applied.push(migration.version());
        }

        Ok(report)
        // The lock drops here, its session ends, and the server releases it.
    }
}

/// The connection a run works on: its own, never the pool's.
struct MaintConnection {
    client: Client,
    driver: JoinHandle<()>,
}

impl MaintConnection {
    async fn open(config: &Config, tls: &PgConnector) -> Result<Self, MigrationError> {
        let (client, driver) = connect(config, tls)
            .await
            .map_err(|_| MigrationError::Connect)?;

        Ok(Self { client, driver })
    }

    /// The history table, created if this is a fresh database.
    ///
    /// Shaped after the one every runner uses, so a database migrated by one can
    /// be read by another.
    async fn ensure_history_table(&self) -> Result<(), MigrationError> {
        self.client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (\
                     version    integer PRIMARY KEY,\
                     name       text NOT NULL,\
                     checksum   text NOT NULL,\
                     applied_at timestamptz NOT NULL DEFAULT now()\
                 )",
            )
            .await
            .map_err(|_| MigrationError::History)
    }

    async fn load_applied(&self) -> Result<Vec<AppliedRecord>, MigrationError> {
        let rows = self
            .client
            .query(
                "SELECT version, name, checksum FROM schema_migrations ORDER BY version",
                &[],
            )
            .await
            .map_err(|_| MigrationError::History)?;

        Ok(rows
            .iter()
            .map(|row| AppliedRecord {
                version: row.get(0),
                name: row.get(1),
                checksum: row.get(2),
            })
            .collect())
    }

    /// Bound how long a statement waits for a lock.
    ///
    /// Set before every migration rather than once, because a backfill is free
    /// to change it and the next migration should not inherit whatever it left.
    async fn set_lock_timeout(&self, ms: Option<u64>) -> Result<(), MigrationError> {
        let statement = match ms {
            Some(ms) => format!("SET lock_timeout = {ms}"),
            None => "SET lock_timeout = 0".to_string(),
        };

        self.client
            .batch_execute(&statement)
            .await
            .map_err(|_| MigrationError::History)
    }

    async fn apply(
        &mut self,
        migration: &Migration,
        digest: &dyn DigestProvider,
    ) -> Result<(), MigrationError> {
        let failed = || MigrationError::Apply {
            version: migration.version(),
            name: migration.name().to_string(),
        };

        match migration {
            // Applied and recorded together: a crash between the two would
            // leave a schema the history does not know about, and the next run
            // would try to apply it again.
            Migration::Sql(sql) if sql.transactional => {
                let transaction = self.client.transaction().await.map_err(|_| failed())?;

                transaction
                    .batch_execute(sql.sql)
                    .await
                    .map_err(|_| failed())?;
                transaction
                    .execute(
                        "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
                        &[&migration.version(), &migration.name(), &migration.checksum(digest)],
                    )
                    .await
                    .map_err(|_| failed())?;

                transaction.commit().await.map_err(|_| failed())
            }

            // Outside a transaction because the statement refuses to be in one.
            // The record lands after, so an interruption re-runs the migration
            // rather than skipping it — which is why one written this way has to
            // tolerate that.
            Migration::Sql(sql) => {
                self.client
                    .batch_execute(sql.sql)
                    .await
                    .map_err(|_| failed())?;
                self.record(migration, digest).await
            }

            Migration::Data(hook) => {
                hook.apply(&mut self.client).await?;
                self.record(migration, digest).await
            }
        }
    }

    async fn record(
        &self,
        migration: &Migration,
        digest: &dyn DigestProvider,
    ) -> Result<(), MigrationError> {
        self.client
            .execute(
                "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
                &[
                    &migration.version(),
                    &migration.name(),
                    &migration.checksum(digest),
                ],
            )
            .await
            .map(|_| ())
            .map_err(|_| MigrationError::History)
    }
}

impl Drop for MaintConnection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crypto::provider::openssl::hashing::OpenSslDigest;

    use super::super::migration::SqlMigration;

    fn config() -> Config {
        std::env::var("SAFFUI_TEST_PG")
            .unwrap_or_else(|_| {
                panic!("these tests need a database: set SAFFUI_TEST_PG to a connection string")
            })
            .parse()
            .expect("SAFFUI_TEST_PG is a connection string")
    }

    fn sql(version: i32, name: &'static str, body: &'static str) -> Migration {
        Migration::Sql(SqlMigration {
            version,
            name,
            sql: body,
            transactional: true,
        })
    }

    /// Wipe what these tests create, so a failure does not decide the next run.
    async fn clean(config: &Config, tls: &PgConnector) {
        let (client, driver) = connect(config, tls).await.unwrap();
        let _ = client
            .batch_execute(
                "DROP TABLE IF EXISTS schema_migrations; DROP TABLE IF EXISTS runner_probe;",
            )
            .await;
        driver.abort();
    }

    /// A first run applies everything and records it; a second does nothing.
    ///
    /// The second half is the one that matters: a runner that reapplied on every
    /// boot would work on a fresh database and fail on every deployment after.
    #[tokio::test]
    #[ignore = "needs a database (SAFFUI_TEST_PG)"]
    async fn a_run_applies_once_and_then_stops() {
        let (config, tls) = (config(), PgConnector::disabled());
        clean(&config, &tls).await;

        let set = vec![
            sql(1, "probe", "CREATE TABLE runner_probe (id int PRIMARY KEY)"),
            sql(
                2,
                "probe_column",
                "ALTER TABLE runner_probe ADD COLUMN note text",
            ),
        ];
        let runner = MigrationRunner::new(set.clone());

        let first = runner.run(&config, &tls, &OpenSslDigest).await.unwrap();
        assert_eq!(first.applied, vec![1, 2]);
        assert!(!first.is_up_to_date());

        let second = runner.run(&config, &tls, &OpenSslDigest).await.unwrap();
        assert!(
            second.is_up_to_date(),
            "the runner applied {:?} twice",
            second.applied
        );

        // And the schema is really there.
        let (client, driver) = connect(&config, &tls).await.unwrap();
        let row = client
            .query_one(
                "SELECT count(*) FROM information_schema.columns WHERE table_name = 'runner_probe'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 2, "both migrations reached the table");
        driver.abort();

        clean(&config, &tls).await;
    }

    /// What the history records is what the plan compares against.
    #[tokio::test]
    #[ignore = "needs a database (SAFFUI_TEST_PG)"]
    async fn an_edit_after_the_fact_stops_the_next_run() {
        let (config, tls) = (config(), PgConnector::disabled());
        clean(&config, &tls).await;

        let original = vec![sql(
            1,
            "probe",
            "CREATE TABLE runner_probe (id int PRIMARY KEY)",
        )];
        MigrationRunner::new(original)
            .run(&config, &tls, &OpenSslDigest)
            .await
            .unwrap();

        // The same version, a different body — a file edited after release.
        let edited = vec![sql(
            1,
            "probe",
            "CREATE TABLE runner_probe (id bigint PRIMARY KEY)",
        )];
        let outcome = MigrationRunner::new(edited)
            .run(&config, &tls, &OpenSslDigest)
            .await;

        assert_eq!(
            outcome.unwrap_err(),
            MigrationError::ChecksumDrift {
                version: 1,
                name: "probe".to_string()
            }
        );

        clean(&config, &tls).await;
    }

    /// A migration that fails leaves nothing behind, and is still pending.
    ///
    /// The transaction is what makes that true: without it the half that ran
    /// would stay, and the next run would apply the whole thing again on top.
    #[tokio::test]
    #[ignore = "needs a database (SAFFUI_TEST_PG)"]
    async fn a_failed_migration_records_nothing() {
        let (config, tls) = (config(), PgConnector::disabled());
        clean(&config, &tls).await;

        let broken = vec![sql(
            1,
            "half broken",
            "CREATE TABLE runner_probe (id int PRIMARY KEY); SELECT nonexistent_function();",
        )];

        let outcome = MigrationRunner::new(broken)
            .run(&config, &tls, &OpenSslDigest)
            .await;
        assert!(matches!(
            outcome,
            Err(MigrationError::Apply { version: 1, .. })
        ));

        // Neither the table nor the record survived.
        let (client, driver) = connect(&config, &tls).await.unwrap();
        let tables: i64 = client
            .query_one(
                "SELECT count(*) FROM information_schema.tables WHERE table_name = 'runner_probe'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let recorded: i64 = client
            .query_one("SELECT count(*) FROM schema_migrations", &[])
            .await
            .unwrap()
            .get(0);
        driver.abort();

        assert_eq!(tables, 0, "a failed migration left its table behind");
        assert_eq!(recorded, 0, "a failed migration was recorded as applied");

        clean(&config, &tls).await;
    }

    /// An empty set is a valid run against a database with no history.
    #[tokio::test]
    #[ignore = "needs a database (SAFFUI_TEST_PG)"]
    async fn a_set_with_nothing_in_it_is_up_to_date() {
        let (config, tls) = (config(), PgConnector::disabled());
        clean(&config, &tls).await;

        let report = MigrationRunner::new(Vec::new())
            .run(&config, &tls, &OpenSslDigest)
            .await
            .unwrap();

        assert!(report.is_up_to_date());

        clean(&config, &tls).await;
    }
}
