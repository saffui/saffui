use async_trait::async_trait;

use crate::tenancy::store::RealmStore;
use crate::tenancy::{RealmId, RealmName, RealmScope, TenantId};

#[async_trait]
pub trait Storage: Send + Sync {
    /// Checks that the database can serve a request right now.
    async fn probe(&self) -> Result<(), StorageUnavailable>;

    /// Reads which realm a name designates. The one read made before any
    /// scope exists: it tells where a realm is, and nothing about it.
    async fn locate_realm(&self, name: &RealmName) -> Result<Option<RealmLocation>, StorageError>;

    /// Opens a unit of work bound to one tenant and one realm.
    async fn begin(&self, scope: RealmScope) -> Result<Box<dyn UnitOfWork>, StorageError>;
}

/// Where a realm is, as the directory of realm names tells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealmLocation {
    pub tenant: TenantId,
    pub realm: RealmId,
    pub enabled: bool,
}

/// One transaction, bound to its scope, that reaches nothing outside it.
/// Abandoned, it leaves nothing: only `commit` keeps what was written.
#[async_trait]
pub trait UnitOfWork: RealmStore + Send {
    fn scope(&self) -> RealmScope;

    /// Keeps everything written since the unit of work was opened.
    async fn commit(self: Box<Self>) -> Result<(), StorageError>;
}

/// Why the database cannot serve a request right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StorageUnavailable {
    #[error("every database connection is in use")]
    PoolExhausted,
    #[error("the database did not answer in time")]
    TimedOut,
    #[error("the TLS handshake with the database failed")]
    TlsFailed,
    #[error("the database refused the connection")]
    Refused,
    #[error("the database schema is behind this binary: migrations are pending")]
    SchemaBehind,
    #[error("the database schema is ahead of this binary")]
    SchemaAhead,
    #[error("nothing answers at the database address")]
    Unreachable,
}

/// Why a read or a write did not happen. It never carries the text of the
/// database: the adapter writes that to the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("the storage cannot serve: {0}")]
    Unavailable(#[from] StorageUnavailable),
    /// A rule of uniqueness refused the write. The text names what is taken.
    #[error("already taken: {0}")]
    Taken(&'static str),
    #[error("the storage failed")]
    Failed,
}
