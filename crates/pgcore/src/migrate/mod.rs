pub mod history;
pub mod plan;
pub mod window;

use tokio_postgres::Client;

use crate::connect::{ConnectionPlan, DirectConnectionError};
use crate::lock::{LockError, MIGRATION_LOCK, SessionLock};
use crate::{APP_ROLE, MAINTENANCE_ROLE};
use plan::{PlanError, plan_pending};

macro_rules! embed {
    ($version:literal, $name:literal) => {
        Migration {
            version: $version,
            name: $name,
            sql: include_str!(concat!("../../migrations/", $name, ".sql")),
        }
    };
}

/// The schema of the product, in order.
pub const EMBEDDED: &[Migration] = &[embed!(1, "0001_tenancy")];

/// One numbered step of the schema, as SQL text.
#[derive(Clone, Copy, Debug)]
pub struct Migration {
    pub version: i32,
    pub name: &'static str,
    pub sql: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct MigrationReport {
    pub applied: Vec<i32>,
    pub schema_version: i32,
}

#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    #[error(transparent)]
    Connection(#[from] DirectConnectionError),
    #[error("another migration run holds the lock")]
    AlreadyRunning,
    #[error("the role {0} does not exist: provision the roles of the cluster first")]
    MissingRole(&'static str),
    #[error(
        "the role {0} bypasses row security, and every SECURITY DEFINER function of the migrations would run with its rights: migrate as the role that owns the tables"
    )]
    RunnerBypassesRowSecurity(String),
    #[error(transparent)]
    Plan(#[from] PlanError),
    #[error("migration {version} failed and was rolled back")]
    Failed {
        version: i32,
        #[source]
        source: tokio_postgres::Error,
    },
    #[error("the database refused a statement of the runner")]
    Database(#[from] tokio_postgres::Error),
}

impl From<LockError> for MigrateError {
    fn from(error: LockError) -> Self {
        match error {
            LockError::Held => Self::AlreadyRunning,
            LockError::Database(source) => Self::Database(source),
        }
    }
}

/// Applies what is pending, each migration in its own transaction, under a
/// session lock held on a direct connection.
///
/// # Errors
///
/// Returns why nothing more was applied. What was applied before stays applied.
pub async fn apply_pending(
    connection: &ConnectionPlan,
    migrations: &[Migration],
) -> Result<MigrationReport, MigrateError> {
    let client = connection.connect_directly().await?;
    let lock = SessionLock::try_acquire(client, MIGRATION_LOCK).await?;
    let outcome = apply_under_lock(lock.client(), migrations).await;
    // The connection closes either way, which releases the lock: an unlock
    // that fails after a failed run must not hide the first error.
    let _ = lock.release().await;
    outcome
}

async fn apply_under_lock(
    client: &Client,
    migrations: &[Migration],
) -> Result<MigrationReport, MigrateError> {
    // A migration waits behind a long transaction instead of queueing every
    // other statement behind its own lock request. Its objects go to public,
    // where the pool looks for them, whatever schema bears the name of the role.
    // Without pg_temp, a database that has no public refuses the first table
    // instead of keeping it until the end of the session.
    client
        .batch_execute("SET lock_timeout = '5s'; SET search_path = public")
        .await?;
    for role in [APP_ROLE, MAINTENANCE_ROLE] {
        let known = client
            .query_opt(
                "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1",
                &[&role],
            )
            .await?;
        if known.is_none() {
            return Err(MigrateError::MissingRole(role));
        }
    }
    // Each function a migration creates is owned by the current role, and
    // runs with its attributes alone: the node refuses to serve through one
    // owned by a role that bypasses row security.
    let runner = client
        .query_one(
            "SELECT rolname::text, rolsuper OR rolbypassrls FROM pg_catalog.pg_roles \
             WHERE rolname = current_user",
            &[],
        )
        .await?;
    if runner.get::<_, bool>(1) {
        return Err(MigrateError::RunnerBypassesRowSecurity(runner.get(0)));
    }
    history::create_history_table(client).await?;

    let embedded = history::fingerprint_embedded(client, migrations).await?;
    let applied = history::read_applied(client).await?;
    let pending = plan_pending(&embedded, &applied)?;

    for version in &pending {
        let migration = migrations
            .iter()
            .find(|m| m.version == *version)
            .ok_or(PlanError::EmbeddedOutOfOrder)?;
        if let Err(source) = apply_one(client, migration).await {
            let _ = client.batch_execute("ROLLBACK").await;
            return Err(MigrateError::Failed {
                version: *version,
                source,
            });
        }
    }
    Ok(MigrationReport {
        schema_version: history::read_schema_version(client).await?,
        applied: pending,
    })
}

async fn apply_one(client: &Client, migration: &Migration) -> Result<(), tokio_postgres::Error> {
    client.batch_execute("BEGIN").await?;
    client.batch_execute(migration.sql).await?;
    history::record_applied(client, migration).await?;
    client.batch_execute("COMMIT").await
}
