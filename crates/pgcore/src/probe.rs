//! The readiness probe: one connection under a short patience, and the schema
//! version read against the window of the binary.

use std::error::Error;
use std::io;
use std::time::Duration;

use deadpool_postgres::{Object, Pool, PoolError, TimeoutType, Timeouts};
use tokio_postgres::error::SqlState;

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
    // The server gives up first, so that the statement ends there and the
    // connection comes back clean. The recycling of the pool resets the bound.
    let server_bound = patience.saturating_sub(patience / 4);
    let read = tokio::time::timeout(patience, async {
        client
            .batch_execute(&format!(
                "SET statement_timeout = {}",
                server_bound.as_millis()
            ))
            .await?;
        read_schema_version(&**client).await
    })
    .await;
    let Ok(read) = read else {
        // A link that stopped answering: given back, the connection would make
        // the next borrower wait behind it.
        drop(Object::take(client));
        return Err(ProbeFailure::TimedOut);
    };
    let version = read.map_err(|error| classify_driver_error(&error))?;
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

/// Tells why the pool gave no connection.
#[must_use]
pub fn classify_pool_error(error: &PoolError) -> ProbeFailure {
    match error {
        PoolError::Timeout(TimeoutType::Wait) => ProbeFailure::PoolExhausted,
        PoolError::Timeout(_) => ProbeFailure::TimedOut,
        PoolError::Backend(error) => classify_driver_error(error),
        _ => ProbeFailure::Unreachable,
    }
}

/// Says what a journal needs of an error of the driver, which shows a refusal
/// of the server as "db error" alone and never shows a cause. Not the detail
/// of a refusal: it quotes the values of the row. The message may still quote
/// a value of the statement: keep it for statements that bind no secret.
#[must_use]
pub fn describe_driver_error(error: &tokio_postgres::Error) -> String {
    if let Some(refusal) = error.as_db_error() {
        return format!("{} {}", refusal.code().code(), refusal.message());
    }
    let mut description = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        description.push_str(": ");
        description.push_str(&cause.to_string());
        source = cause.source();
    }
    description
}

/// Tells why the driver could not reach or use the server.
#[must_use]
pub fn classify_driver_error(error: &tokio_postgres::Error) -> ProbeFailure {
    if let Some(refusal) = error.as_db_error() {
        // A lock or a statement waited for past its bound is a busy server,
        // not a refusal.
        if [SqlState::LOCK_NOT_AVAILABLE, SqlState::QUERY_CANCELED].contains(refusal.code()) {
            return ProbeFailure::TimedOut;
        }
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
