//! Retention, on Postgres. The one place of this crate that removes across
//! tenants: it connects under the retention role, which row security does
//! not bind and which may do nothing else, never under the role that serves.

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
/// row security, read and remove the rows of the purged tables, and hold no
/// other attribute, membership or right. A membership is refused whatever it
/// is: a role that belongs to none inherits nothing and can become no other.
const RETENTION_FITNESS: &str = "
    SELECT role.rolname::text,
           role.rolbypassrls
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
/// How many statements a pass gives one table. What is left waits for the
/// next pass.
const BATCHES_PER_TABLE: u32 = 50;

/// Removes the rows a statement finds, a batch at a time. Each batch is a
/// transaction of its own: a pass that fails keeps what it removed.
async fn remove_in_batches(
    client: &Client,
    statement: &str,
    before: OffsetDateTime,
) -> Result<u64, StorageError> {
    let mut removed = 0;
    for _ in 0..BATCHES_PER_TABLE {
        let batch = client
            .execute(statement, &[&before, &BATCH_ROWS])
            .await
            .map_err(|error| report_failure(&error))?;
        removed += batch;
        if batch < BATCH_ROWS.unsigned_abs() {
            break;
        }
    }
    Ok(removed)
}

#[async_trait]
impl Retention for PgRetention {
    async fn purge_expired(
        &self,
        cutoffs: PurgeCutoffs,
    ) -> Result<Option<PurgeReport>, StorageError> {
        let client = self.connect_as_retention().await?;
        // A statement that runs longer than this is given up: the pass
        // fails, and serving never waits on it.
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
        // Constant SQL, across realms on purpose: each statement names what
        // has no use left, and nothing else, and finds it by an index.
        let report = PurgeReport {
            pending_requests: remove_in_batches(
                &client,
                "DELETE FROM authorization_requests WHERE ctid = ANY (ARRAY(
                     SELECT ctid FROM authorization_requests WHERE expires_at < $1 LIMIT $2))",
                cutoffs.expired_before,
            )
            .await?,
            codes: remove_in_batches(
                &client,
                "DELETE FROM authorization_codes WHERE ctid = ANY (ARRAY(
                     SELECT ctid FROM authorization_codes WHERE expires_at < $1 LIMIT $2))",
                cutoffs.codes_before,
            )
            .await?,
            refresh_tokens: remove_in_batches(
                &client,
                "DELETE FROM refresh_tokens WHERE ctid = ANY (ARRAY(
                     SELECT ctid FROM refresh_tokens WHERE expires_at < $1 LIMIT $2))",
                cutoffs.expired_before,
            )
            .await?,
            sessions: remove_in_batches(
                &client,
                "DELETE FROM sessions WHERE ctid = ANY (ARRAY(
                     SELECT ctid FROM sessions WHERE expires_at < $1 LIMIT $2))",
                cutoffs.expired_before,
            )
            .await?,
            known_browsers: remove_in_batches(
                &client,
                "DELETE FROM known_browsers WHERE ctid = ANY (ARRAY(
                     SELECT ctid FROM known_browsers WHERE expires_at < $1 LIMIT $2))",
                cutoffs.expired_before,
            )
            .await?,
            failure_counters: remove_in_batches(
                &client,
                "DELETE FROM login_failures WHERE ctid = ANY (ARRAY(
                     SELECT ctid FROM login_failures WHERE bucket_start < $1 LIMIT $2))",
                cutoffs.counters_before,
            )
            .await?,
        };
        Ok(Some(report))
    }
}
