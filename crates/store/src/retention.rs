//! Retention, on Postgres. The one place of this crate that removes across
//! tenants: it connects under the retention role, which row security does
//! not bind and which may do nothing else, never under the role that serves.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use pgcore::connect::ConnectionPlan;
use saffui_core::ports::storage::{StorageError, StorageUnavailable};
use saffui_core::retention::{PurgeCutoffs, PurgeOutcome, PurgeReport, Retention, TablePurge};
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
/// row security, reach the schema, read and remove the rows of each purged
/// table, and hold no other attribute, membership or right. A membership is
/// refused whatever it is: a role that belongs to none inherits nothing and
/// can become no other. Grants are read as written, to the role or to all:
/// a right not named here, or one it may grant on, is a right more.
const RETENTION_FITNESS: &str = "
    SELECT role.rolname::text,
           role.rolbypassrls
       AND has_schema_privilege(role.oid, 'public', 'USAGE')
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
           CROSS JOIN LATERAL aclexplode(coalesce(class.relacl, acldefault(
               CASE class.relkind WHEN 'S' THEN 's'::\"char\" ELSE 'r'::\"char\" END,
               class.relowner))) AS granted
           WHERE space.nspname NOT IN ('pg_catalog', 'information_schema')
             AND space.nspname NOT LIKE 'pg\\_toast%'
             AND class.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
             AND granted.grantee IN (role.oid, 0::oid)
             AND (granted.is_grantable
                  OR granted.privilege_type NOT IN ('SELECT', 'DELETE')
                  OR space.nspname <> 'public' OR class.relname <> ALL ($1)))
       AND NOT EXISTS (
           SELECT 1 FROM pg_attribute AS attribute
           JOIN pg_class AS class ON class.oid = attribute.attrelid
           JOIN pg_namespace AS space ON space.oid = class.relnamespace
           CROSS JOIN LATERAL aclexplode(attribute.attacl) AS granted
           WHERE space.nspname NOT IN ('pg_catalog', 'information_schema')
             AND granted.grantee IN (role.oid, 0::oid))
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

/// Constant SQL, across realms on purpose, one statement for each purged
/// table and in its order. Each names what has no use left, and nothing else,
/// finds it by an index, and asks again of each row it removes whether it
/// still has none: a row made to live longer meanwhile stays. Names are
/// qualified: the link sets no search path.
const PURGES: [&str; 6] = [
    "DELETE FROM public.authorization_requests
     WHERE ctid = ANY (ARRAY(SELECT ctid FROM public.authorization_requests
                             WHERE expires_at < $1 LIMIT $2))
       AND expires_at < $1",
    "DELETE FROM public.authorization_codes
     WHERE ctid = ANY (ARRAY(SELECT ctid FROM public.authorization_codes
                             WHERE expires_at < $1 LIMIT $2))
       AND expires_at < $1",
    "DELETE FROM public.refresh_tokens
     WHERE ctid = ANY (ARRAY(SELECT ctid FROM public.refresh_tokens
                             WHERE expires_at < $1 LIMIT $2))
       AND expires_at < $1",
    // A session takes its refresh tokens along in the statement that removes
    // it: one that still has some waits for them to go, so that no batch
    // removes more than its rows.
    "DELETE FROM public.sessions
     WHERE ctid = ANY (ARRAY(
               SELECT ctid FROM public.sessions AS session
               WHERE expires_at < $1
                 AND NOT EXISTS (SELECT 1 FROM public.refresh_tokens AS token
                                 WHERE token.tenant_id = session.tenant_id
                                   AND token.realm_id = session.realm_id
                                   AND token.session_id = session.session_id)
               LIMIT $2))
       AND expires_at < $1",
    "DELETE FROM public.known_browsers
     WHERE ctid = ANY (ARRAY(SELECT ctid FROM public.known_browsers
                             WHERE expires_at < $1 LIMIT $2))
       AND expires_at < $1",
    "DELETE FROM public.login_failures
     WHERE ctid = ANY (ARRAY(SELECT ctid FROM public.login_failures
                             WHERE bucket_start < $1 LIMIT $2))
       AND bucket_start < $1",
];

/// Removes the rows a statement finds, a batch at a time, as long as the
/// batches come back full and `share` is not spent. Each batch is a
/// transaction of its own: a batch that fails keeps what the others removed.
async fn purge_table(
    client: &Client,
    table: &str,
    statement: &str,
    before: OffsetDateTime,
    share: Duration,
) -> TablePurge {
    let started = Instant::now();
    let failed = |removed| TablePurge {
        removed,
        outcome: PurgeOutcome::Failed,
    };
    // The text of the database goes to the journal and stops there.
    let statement = match client.prepare(statement).await {
        Ok(statement) => statement,
        Err(error) => {
            tracing::error!(%error, table, "a retention statement cannot be prepared");
            return failed(0);
        }
    };
    let mut removed = 0;
    loop {
        match client.execute(&statement, &[&before, &BATCH_ROWS]).await {
            Ok(batch) if batch < BATCH_ROWS.unsigned_abs() => {
                return TablePurge {
                    removed: removed + batch,
                    outcome: PurgeOutcome::Done,
                };
            }
            Ok(batch) => removed += batch,
            Err(error) => {
                tracing::error!(%error, table, "a retention batch failed");
                return failed(removed);
            }
        }
        if started.elapsed() >= share {
            return TablePurge {
                removed,
                outcome: PurgeOutcome::RowsLeft,
            };
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
        let cutoff_of_each = [
            cutoffs.expired_before,
            cutoffs.codes_before,
            cutoffs.expired_before,
            cutoffs.expired_before,
            cutoffs.expired_before,
            cutoffs.counters_before,
        ];
        let started = Instant::now();
        let mut purged = [TablePurge::default(); 6];
        // Each table is given an equal part of what is left: one that anybody
        // can fill spends its own part only, and one done early leaves its
        // part to the tables after it. Each gets a batch at least.
        let mut tables_left = 6_u32;
        let tables = PURGED_TABLES.into_iter().zip(PURGES).zip(cutoff_of_each);
        for (slot, ((table, statement), before)) in purged.iter_mut().zip(tables) {
            let share = budget.saturating_sub(started.elapsed()) / tables_left;
            tables_left -= 1;
            *slot = purge_table(&client, table, statement, before, share).await;
            if slot.outcome == PurgeOutcome::Failed && client.is_closed() {
                tracing::error!(table, "the retention link closed during a pass");
                return Err(StorageError::Unavailable(StorageUnavailable::Unreachable));
            }
        }
        if purged
            .iter()
            .all(|table| table.outcome == PurgeOutcome::Failed)
        {
            return Err(StorageError::Failed);
        }
        let [
            pending_requests,
            codes,
            refresh_tokens,
            sessions,
            known_browsers,
            failure_counters,
        ] = purged;
        Ok(Some(PurgeReport {
            pending_requests,
            codes,
            refresh_tokens,
            sessions,
            known_browsers,
            failure_counters,
        }))
    }
}
