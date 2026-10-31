//! The unit of work: one transaction, on a connection it owns, bound to one
//! tenant and one realm for as long as it lives.

use async_trait::async_trait;
use deadpool_postgres::{Object, Pool};
use pgcore::probe::classify_pool_error;
use saffui_core::ports::storage::{StorageError, StorageUnavailable, UnitOfWork};
use saffui_core::tenancy::RealmScope;
use tokio_postgres::Row;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

use crate::query::bind::{Built, Value};
use crate::translate_probe_failure;

pub struct PgUnitOfWork {
    /// Taken by `commit`. Still here when the value is dropped: abandoned.
    client: Option<Object>,
    scope: RealmScope,
    /// A statement failed: Postgres has aborted the transaction, and a commit
    /// after that would report a success that kept nothing.
    failed: bool,
}

impl PgUnitOfWork {
    pub(crate) async fn open(pool: &Pool, scope: RealmScope) -> Result<Self, StorageError> {
        let client = pool
            .get()
            .await
            .map_err(|error| translate_probe_failure(classify_pool_error(&error)))?;
        // One round trip. The settings are local to the transaction: they end
        // with it, so the next borrower of the session starts with none. The
        // two values are identifiers this process formats, never free text.
        // A lock waited for longer than the pool waits for a connection gives
        // the connection back rather than holding it.
        let opening = format!(
            "BEGIN; SELECT set_config('lock_timeout', '5s', true), \
             set_config('saffui.tenant', '{}', true), set_config('saffui.realm', '{}', true)",
            scope.tenant().as_uuid(),
            scope.realm().as_uuid()
        );
        client.batch_execute(&opening).await.map_err(|error| {
            tracing::error!(%error, "a unit of work cannot be opened");
            StorageError::Unavailable(StorageUnavailable::Unreachable)
        })?;
        Ok(Self {
            client: Some(client),
            scope,
            failed: false,
        })
    }

    fn scope_keys(&self) -> (Uuid, Uuid) {
        (self.scope.tenant().as_uuid(), self.scope.realm().as_uuid())
    }

    /// Runs a statement of the builder and returns how many rows it changed.
    pub(crate) async fn execute(&mut self, built: &Built<'_>) -> Result<u64, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let values = built.bind(&tenant, &realm);
        self.execute_raw(&built.sql, &values).await
    }

    /// Reads at most one row with a statement of the builder.
    pub(crate) async fn read_one(
        &mut self,
        built: &Built<'_>,
    ) -> Result<Option<Row>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let values = built.bind(&tenant, &realm);
        let read = async {
            let client = self.client.as_ref().ok_or(None)?;
            let statement = client.prepare_cached(&built.sql).await.map_err(Some)?;
            client.query_opt(&statement, &values).await.map_err(Some)
        }
        .await;
        read.map_err(|error| self.translate(error))
    }

    /// Runs constant SQL written by hand: an atomic operation the builder does
    /// not express. The statement names its scope keys itself.
    pub(crate) async fn execute_raw(
        &mut self,
        sql: &str,
        values: &[Value<'_>],
    ) -> Result<u64, StorageError> {
        let ran = async {
            let client = self.client.as_ref().ok_or(None)?;
            let statement = client.prepare_cached(sql).await.map_err(Some)?;
            client.execute(&statement, values).await.map_err(Some)
        }
        .await;
        ran.map_err(|error| self.translate(error))
    }

    /// The text of the database goes to the journal and stops there.
    fn translate(&mut self, error: Option<tokio_postgres::Error>) -> StorageError {
        self.failed = true;
        let Some(error) = error else {
            return StorageError::Failed;
        };
        let Some(refusal) = error.as_db_error() else {
            tracing::error!(%error, "the link to the database failed inside a unit of work");
            return StorageError::Unavailable(StorageUnavailable::Unreachable);
        };
        if *refusal.code() == SqlState::UNIQUE_VIOLATION
            && let Some(taken) = refusal.constraint().and_then(name_what_is_taken)
        {
            return StorageError::Taken(taken);
        }
        // Waited too long, or for a lock the other waits on: busy, not broken.
        if [
            SqlState::LOCK_NOT_AVAILABLE,
            SqlState::T_R_DEADLOCK_DETECTED,
        ]
        .contains(refusal.code())
        {
            tracing::warn!(code = refusal.code().code(), "a statement gave up a lock");
            return StorageError::Unavailable(StorageUnavailable::TimedOut);
        }
        // Not the detail: it quotes the values of the row.
        tracing::error!(
            code = refusal.code().code(),
            message = refusal.message(),
            constraint = refusal.constraint(),
            "a statement failed"
        );
        StorageError::Failed
    }
}

/// What a uniqueness constraint protects, in the words the core matches on.
fn name_what_is_taken(constraint: &str) -> Option<&'static str> {
    match constraint {
        "realms_name_taken" => Some("realm name"),
        _ => None,
    }
}

#[async_trait]
impl UnitOfWork for PgUnitOfWork {
    fn scope(&self) -> RealmScope {
        self.scope
    }

    async fn commit(mut self: Box<Self>) -> Result<(), StorageError> {
        let client = self.client.take().ok_or(StorageError::Failed)?;
        if self.failed {
            let _ = client.batch_execute("ROLLBACK").await;
            return Err(StorageError::Failed);
        }
        client.batch_execute("COMMIT").await.map_err(|error| {
            tracing::error!(%error, "a commit failed");
            StorageError::Failed
        })
    }
}

impl Drop for PgUnitOfWork {
    fn drop(&mut self) {
        let Some(client) = self.client.take() else {
            return;
        };
        // Rolled back now, not at the next borrow: an open transaction keeps
        // its locks for as long as the session waits in the pool.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = client.batch_execute("ROLLBACK").await;
            });
        } else {
            // No runtime to roll back on: closing the session does it.
            drop(Object::take(client));
        }
    }
}
