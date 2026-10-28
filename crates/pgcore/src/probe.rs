//! The readiness probe: one connection under a short patience, and the schema
//! version read against the window of the binary.

use std::error::Error;
use std::io;
use std::time::Duration;

use deadpool_postgres::{Pool, PoolError, TimeoutType, Timeouts};

use crate::migrate::history::read_schema_version;
use crate::migrate::window::{SchemaStanding, SchemaWindow};

/// Why this node cannot serve from its database right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProbeFailure {
    #[error("every database connection is in use")]
    PoolExhausted,
    #[error("the database did not answer in time")]
    TimedOut,
    #[error("the TLS handshake with the database failed")]
    TlsFailed,
    #[error("the database refused the connection")]
    Refused,
    #[error("nothing answers at the database address")]
    Unreachable,
    #[error("the schema is at version {found}: this binary needs at least {oldest}")]
    SchemaBehind { found: i32, oldest: i32 },
    #[error("the schema is at version {found}: this binary knows nothing past {newest}")]
    SchemaAhead { found: i32, newest: i32 },
}

/// Probes the database once.
///
/// # Errors
///
/// Returns the first reason this node cannot serve.
pub async fn probe_database(
    pool: &Pool,
    window: SchemaWindow,
    patience: Duration,
) -> Result<(), ProbeFailure> {
    let within_patience = Timeouts {
        wait: Some(patience),
        create: Some(patience),
        recycle: Some(patience),
    };
    let client = pool
        .timeout_get(&within_patience)
        .await
        .map_err(|error| classify_pool_error(&error))?;
    let version = tokio::time::timeout(patience, read_schema_version(&**client))
        .await
        .map_err(|_| ProbeFailure::TimedOut)?
        .map_err(|error| classify_driver_error(&error))?;
    match window.judge(version) {
        SchemaStanding::Within => Ok(()),
        SchemaStanding::Behind => Err(ProbeFailure::SchemaBehind {
            found: version,
            oldest: window.oldest,
        }),
        SchemaStanding::Ahead => Err(ProbeFailure::SchemaAhead {
            found: version,
            newest: window.newest,
        }),
    }
}

fn classify_pool_error(error: &PoolError) -> ProbeFailure {
    match error {
        PoolError::Timeout(TimeoutType::Wait) => ProbeFailure::PoolExhausted,
        PoolError::Timeout(_) => ProbeFailure::TimedOut,
        PoolError::Backend(error) => classify_driver_error(error),
        _ => ProbeFailure::Unreachable,
    }
}

fn classify_driver_error(error: &tokio_postgres::Error) -> ProbeFailure {
    if error.as_db_error().is_some() {
        return ProbeFailure::Refused;
    }
    let mut source = error.source();
    while let Some(cause) = source {
        if cause.is::<io::Error>() {
            return ProbeFailure::Unreachable;
        }
        source = cause.source();
    }
    // The driver keeps its error kinds private: its handshake error is told
    // apart by its text, pinned with the version of the driver.
    if error.to_string().contains("TLS") {
        ProbeFailure::TlsFailed
    } else {
        ProbeFailure::Unreachable
    }
}
