//! Retention, on Postgres. The one place of this crate that reads and
//! writes across tenants: it connects under the maintenance role, which row
//! security does not bind, and never under the role that serves.

use async_trait::async_trait;
use pgcore::connect::ConnectionPlan;
use pgcore::role::{Privilege, read_role_facts};
use saffui_core::ports::storage::{StorageError, StorageUnavailable};
use saffui_core::retention::{PurgeReport, Retention};
use time::OffsetDateTime;
use tokio_postgres::{Client, Transaction};

/// The transaction lock of the pass. Held by one node at a time: it spares
/// the others the same work, and guards nothing.
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

async fn remove_expired(
    transaction: &Transaction<'_>,
    statement: &str,
    before: OffsetDateTime,
) -> Result<u64, StorageError> {
    transaction
        .execute(statement, &[&before])
        .await
        .map_err(|error| report_failure(&error))
}

#[async_trait]
impl Retention for PgRetention {
    async fn purge_expired(
        &self,
        expired_before: OffsetDateTime,
        counters_before: OffsetDateTime,
    ) -> Result<Option<PurgeReport>, StorageError> {
        let mut client = self.connect_as_maintenance().await?;

        let transaction = client
            .transaction()
            .await
            .map_err(|error| report_failure(&error))?;
        let held: bool = transaction
            .query_one("SELECT pg_try_advisory_xact_lock($1)", &[&RETENTION_LOCK])
            .await
            .map_err(|error| report_failure(&error))?
            .get(0);
        if !held {
            return Ok(None);
        }
        // Constant SQL, across realms on purpose: each statement names what
        // has no use left, and nothing else.
        let report = PurgeReport {
            pending_requests: remove_expired(
                &transaction,
                "DELETE FROM authorization_requests WHERE expires_at < $1",
                expired_before,
            )
            .await?,
            codes: remove_expired(
                &transaction,
                "DELETE FROM authorization_codes WHERE expires_at < $1",
                expired_before,
            )
            .await?,
            failure_counters: remove_expired(
                &transaction,
                "DELETE FROM login_failures WHERE bucket_start < $1",
                counters_before,
            )
            .await?,
        };
        transaction
            .commit()
            .await
            .map_err(|error| report_failure(&error))?;
        Ok(Some(report))
    }
}
