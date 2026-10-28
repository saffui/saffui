use async_trait::async_trait;

#[async_trait]
pub trait Storage: Send + Sync {
    /// Checks that the database can serve a request right now.
    async fn probe(&self) -> Result<(), StorageUnavailable>;
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
