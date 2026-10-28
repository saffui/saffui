//! The storage port of the core, on Postgres. This crate executes: it
//! decides nothing and never commits on its own.

use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::Pool;
use pgcore::migrate::window::SchemaWindow;
use pgcore::probe::{ProbeFailure, probe_database};
use saffui_core::ports::storage::{Storage, StorageUnavailable};

/// How long a probe waits for a connection and for its answer. Short: a
/// probe that hangs tells the orchestrator nothing.
const PROBE_PATIENCE: Duration = Duration::from_secs(2);

pub struct PgStorage {
    pool: Pool,
    window: SchemaWindow,
}

impl PgStorage {
    #[must_use]
    pub fn new(pool: Pool, window: SchemaWindow) -> Self {
        Self { pool, window }
    }
}

#[async_trait]
impl Storage for PgStorage {
    async fn probe(&self) -> Result<(), StorageUnavailable> {
        probe_database(&self.pool, self.window, PROBE_PATIENCE)
            .await
            .map_err(|failure| match failure {
                ProbeFailure::PoolExhausted => StorageUnavailable::PoolExhausted,
                ProbeFailure::TimedOut => StorageUnavailable::TimedOut,
                ProbeFailure::TlsFailed => StorageUnavailable::TlsFailed,
                ProbeFailure::Refused => StorageUnavailable::Refused,
                ProbeFailure::Unreachable => StorageUnavailable::Unreachable,
                ProbeFailure::SchemaBehind { .. } => StorageUnavailable::SchemaBehind,
                ProbeFailure::SchemaAhead { .. } => StorageUnavailable::SchemaAhead,
            })
    }
}
