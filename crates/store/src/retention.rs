//! Retention, on Postgres. The one place of this crate that removes across
//! tenants: it connects under the retention role, which row security does
//! not bind and which may do nothing else, never under the role that serves.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use pgcore::connect::ConnectionPlan;
use saffui_core::ports::storage::{StorageError, StorageUnavailable};
use saffui_core::retention::{PurgeCutoffs, PurgeReport, Retention};
use time::OffsetDateTime;
use tokio_postgres::Client;

/// The lock of the pass, held by one node at a time for the session of its
/// link: it spares the others the same work, and guards nothing.
pub const RETENTION_LOCK: i64 = 0x7361_6666_7569_0003;

/// The tables a pass removes from, and the only ones its role may.
const PURGED_TABLES: [&str; 6] = [
    "authorization_requests",
    "authorization_codes",
    "refresh_tokens",
    "sessions",
    "known_browsers",
    "login_failures",
];

pub struct PgRetention {
    plan: ConnectionPlan,
}

impl PgRetention {
    /// A connection is opened for each pass and closed after it: a pass
    /// runs every few minutes, and keeps nothing between two.
    #[must_use]
    pub fn new(plan: ConnectionPlan) -> Self {
        Self {
            plan: plan.named("saffui-retention"),
        }
    }
}

impl PgRetention {
    /// Opens the link and refuses it unless its role is the retention one.
    /// Under a role that row security binds, every statement of a pass would
    /// remove nothing and report a success. Under a role that may do more,
    /// a flaw of this file could do more too.
    async fn connect_as_retention(&self) -> Result<Client, StorageError> {
        let mut client = self.plan.connect_directly().await.map_err(|error| {
            tracing::error!(%error, "the retention link cannot reach the database");
            StorageError::Unavailable(StorageUnavailable::Unreachable)
        })?;
        let (role, fits) = read_retention_fitness(&mut client)
            .await
            .map_err(|error| report_failure(&error))?;
        if !fits {
            tracing::error!(%role, "retention runs under a role that may purge and do nothing else");
            return Err(StorageError::Failed);
        }
        Ok(client)
    }

    /// Checks, before a node serves, that the link can purge and do nothing
    /// else: a node told to purge never serves under a link that cannot.
    ///
    /// # Errors
    ///
    /// Returns the failure of the link, or `Failed` for a role that is not
    /// the retention one.
    pub async fn verify_role(&self) -> Result<(), StorageError> {
        self.connect_as_retention().await.map(drop)
    }
}

/// Whether the role of the session may purge and do nothing else: bypass
/// row security, read and remove the rows of each purged table, and hold no
/// other attribute, membership or right. A membership is refused whatever it
/// is: a role that belongs to none inherits nothing and can become no other.
const RETENTION_FITNESS: &str = "
    SELECT role.rolname::text,
           role.rolbypassrls
       AND (SELECT count(*) FROM pg_class AS class
            JOIN pg_namespace AS space ON space.oid = class.relnamespace
            WHERE space.nspname = 'public' AND class.relname = ANY ($1)
              AND has_table_privilege(role.oid, class.oid, 'SELECT')
              AND has_table_privilege(role.oid, class.oid, 'DELETE')) = cardinality($1)
       AND NOT (role.rolsuper OR role.rolcreaterole OR role.rolcreatedb OR role.rolreplication)
       AND session_user = current_user
       AND NOT EXISTS (SELECT 1 FROM pg_auth_members AS held WHERE held.member = role.oid)
       AND NOT EXISTS (
           SELECT 1 FROM pg_class AS class
           JOIN pg_namespace AS space ON space.oid = class.relnamespace
           WHERE space.nspname NOT IN ('pg_catalog', 'information_schema')
             AND space.nspname NOT LIKE 'pg\\_toast%'
             AND class.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
             AND CASE
                 WHEN class.relkind = 'S'
                     THEN has_sequence_privilege(role.oid, class.oid, 'USAGE, SELECT, UPDATE')
                 WHEN space.nspname = 'public' AND class.relname = ANY ($1)
                     THEN has_table_privilege(role.oid, class.oid,
                              'INSERT, UPDATE, TRUNCATE, REFERENCES, TRIGGER')
                       OR has_any_column_privilege(role.oid, class.oid,
                              'INSERT, UPDATE, REFERENCES')
                 ELSE has_table_privilege(role.oid, class.oid,
                          'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                   OR has_any_column_privilege(role.oid, class.oid,
                          'SELECT, INSERT, UPDATE, REFERENCES')
             END)
       AND NOT has_database_privilege(role.oid, current_database(), 'CREATE')
       AND NOT EXISTS (
           SELECT 1 FROM pg_namespace AS space
           WHERE space.nspname NOT LIKE 'pg\\_%' AND space.nspname <> 'information_schema'
             AND has_schema_privilege(role.oid, space.oid, 'CREATE'))
       AND NOT EXISTS (
           SELECT 1 FROM pg_proc AS proc
           JOIN pg_namespace AS space ON space.oid = proc.pronamespace
           WHERE proc.prosecdef AND space.nspname NOT IN ('pg_catalog', 'information_schema')
             AND has_function_privilege(role.oid, proc.oid, 'EXECUTE'))
    FROM pg_roles AS role
    WHERE role.rolname = current_user";

/// Reads the name of the role of the session and whether it fits retention,
/// in a transaction of its own whose search path holds the catalog alone:
/// nothing a role created can stand in for what the check reads.
async fn read_retention_fitness(
    client: &mut Client,
) -> Result<(String, bool), tokio_postgres::Error> {
    let transaction = client.transaction().await?;
    transaction
        .batch_execute("SET LOCAL search_path = pg_catalog")
        .await?;
    let row = transaction
        .query_one(RETENTION_FITNESS, &[&PURGED_TABLES.as_slice()])
        .await?;
    transaction.commit().await?;
    Ok((row.get(0), row.get(1)))
}

fn report_failure(error: &tokio_postgres::Error) -> StorageError {
    // The text of the database goes to the journal and stops there.
    tracing::error!(%error, "a retention pass failed");
    StorageError::Failed
}

/// How many rows one statement removes: a statement holds its locks for the
/// time of a thousand rows, never of a table.
const BATCH_ROWS: i64 = 1_000;

/// How a table comes out of a pass.
enum Purged {
    /// Its last batch came back short: nothing the pass removes is left.
    Emptied(u64),
    /// The pass spent its time, or a batch failed: the rest waits.
    RowsLeft(u64),
}

impl Purged {
    fn count_removed(&self) -> u64 {
        match self {
            Self::Emptied(removed) | Self::RowsLeft(removed) => *removed,
        }
    }
}

/// Removes the rows a statement finds, a batch at a time, as long as the
/// batches come back full and the pass has time left. Each batch is a
/// transaction of its own: a batch that fails keeps what the others removed.
async fn purge_table(
    client: &Client,
    table: &str,
    statement: &str,
    before: OffsetDateTime,
    started: Instant,
    budget: Duration,
) -> Purged {
    let mut removed = 0;
    loop {
        match client.execute(statement, &[&before, &BATCH_ROWS]).await {
            Ok(batch) if batch < BATCH_ROWS.unsigned_abs() => {
                return Purged::Emptied(removed + batch);
            }
            Ok(batch) => removed += batch,
            Err(error) => {
                // The text of the database goes to the journal and stops there.
                tracing::error!(%error, table, "a retention batch failed");
                return Purged::RowsLeft(removed);
            }
        }
        if started.elapsed() >= budget {
            tracing::warn!(
                table,
                "a retention pass spent its time: the next one goes on"
            );
            return Purged::RowsLeft(removed);
        }
    }
}

#[async_trait]
impl Retention for PgRetention {
    async fn purge_expired(
        &self,
        cutoffs: PurgeCutoffs,
        budget: Duration,
    ) -> Result<Option<PurgeReport>, StorageError> {
        let client = self.connect_as_retention().await?;
        // A statement that runs longer than this is given up: its table
        // waits for the next pass, and serving never waits on it.
        client
            .batch_execute("SET statement_timeout = '10s'")
            .await
            .map_err(|error| report_failure(&error))?;
        // Held for the session of this link, released when it closes.
        let held: bool = client
            .query_one("SELECT pg_try_advisory_lock($1)", &[&RETENTION_LOCK])
            .await
            .map_err(|error| report_failure(&error))?
            .get(0);
        if !held {
            return Ok(None);
        }
        let started = Instant::now();
        // Constant SQL, across realms on purpose: each statement names what
        // has no use left, and nothing else, and finds it by an index. Each
        // table gets a batch at least, so that none waits on the others.
        let pending_requests = purge_table(
            &client,
            "authorization_requests",
            "DELETE FROM authorization_requests WHERE ctid = ANY (ARRAY(
                 SELECT ctid FROM authorization_requests WHERE expires_at < $1 LIMIT $2))",
            cutoffs.expired_before,
            started,
            budget,
        )
        .await;
        let codes = purge_table(
            &client,
            "authorization_codes",
            "DELETE FROM authorization_codes WHERE ctid = ANY (ARRAY(
                 SELECT ctid FROM authorization_codes WHERE expires_at < $1 LIMIT $2))",
            cutoffs.codes_before,
            started,
            budget,
        )
        .await;
        let refresh_tokens = purge_table(
            &client,
            "refresh_tokens",
            "DELETE FROM refresh_tokens WHERE ctid = ANY (ARRAY(
                 SELECT ctid FROM refresh_tokens WHERE expires_at < $1 LIMIT $2))",
            cutoffs.expired_before,
            started,
            budget,
        )
        .await;
        // A session takes its refresh tokens along in the statement that
        // removes it. None outlives its session: once the expired tokens are
        // gone, a batch of sessions takes no more. Until then, sessions wait.
        let sessions = match refresh_tokens {
            Purged::Emptied(_) => {
                purge_table(
                    &client,
                    "sessions",
                    "DELETE FROM sessions WHERE ctid = ANY (ARRAY(
                         SELECT ctid FROM sessions WHERE expires_at < $1 LIMIT $2))",
                    cutoffs.expired_before,
                    started,
                    budget,
                )
                .await
            }
            Purged::RowsLeft(_) => Purged::RowsLeft(0),
        };
        let known_browsers = purge_table(
            &client,
            "known_browsers",
            "DELETE FROM known_browsers WHERE ctid = ANY (ARRAY(
                 SELECT ctid FROM known_browsers WHERE expires_at < $1 LIMIT $2))",
            cutoffs.expired_before,
            started,
            budget,
        )
        .await;
        let failure_counters = purge_table(
            &client,
            "login_failures",
            "DELETE FROM login_failures WHERE ctid = ANY (ARRAY(
                 SELECT ctid FROM login_failures WHERE bucket_start < $1 LIMIT $2))",
            cutoffs.counters_before,
            started,
            budget,
        )
        .await;
        Ok(Some(PurgeReport {
            pending_requests: pending_requests.count_removed(),
            codes: codes.count_removed(),
            refresh_tokens: refresh_tokens.count_removed(),
            sessions: sessions.count_removed(),
            known_browsers: known_browsers.count_removed(),
            failure_counters: failure_counters.count_removed(),
        }))
    }
}
