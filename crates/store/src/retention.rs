//! Retention, on Postgres. The one place of this crate that reads and
//! writes across tenants: it connects under the maintenance role, which row
//! security does not bind, and never under the role that serves.

use async_trait::async_trait;
use pgcore::connect::ConnectionPlan;
use pgcore::role::{Privilege, read_role_facts};
use saffui_core::ports::storage::{StorageError, StorageUnavailable};
use saffui_core::retention::{PurgeCutoffs, PurgeReport, Retention};
use time::OffsetDateTime;
use tokio_postgres::Client;

/// The lock of the pass, held by one node at a time for the session of its
/// link: it spares the others the same work, and guards nothing.
pub const RETENTION_LOCK: i64 = 0x7361_6666_7569_0003;

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
    /// Opens the link and refuses it unless its role is the maintenance one.
    /// Under a role that row security binds, every statement of a pass would
    /// remove nothing and report a success.
    async fn connect_as_maintenance(&self) -> Result<Client, StorageError> {
        let client = self.plan.connect_directly().await.map_err(|error| {
            tracing::error!(%error, "the retention link cannot reach the database");
            StorageError::Unavailable(StorageUnavailable::Unreachable)
        })?;
        let role = read_role_facts(&client)
            .await
            .map_err(|error| report_failure(&error))?;
        // Bypassing row security, and no more: a superuser may do anything
        // else too, and nothing here needs it.
        let superuser: bool = client
            .query_one(
                "SELECT rolsuper FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .map_err(|error| report_failure(&error))?
            .get(0);
        if role.privilege != Some(Privilege::BypassesRowSecurity) || superuser {
            tracing::error!(role = %role.name, "retention runs under the maintenance role only");
            return Err(StorageError::Failed);
        }
        Ok(client)
    }

    /// Checks, before a node serves, that the link can purge: a node told to
    /// purge never serves under a link that cannot.
    ///
    /// # Errors
    ///
    /// Returns the failure of the link, or `Failed` for a role that is not
    /// the maintenance one.
    pub async fn verify_role(&self) -> Result<(), StorageError> {
        self.connect_as_maintenance().await.map(drop)
    }
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
        let client = self.connect_as_maintenance().await?;
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
