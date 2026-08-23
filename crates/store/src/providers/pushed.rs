//! Authorization requests a client pushed before sending the browser.

use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use serde_json::Value;

use crate::error::{StoreError, StoreResult};

/// What presenting a reference found.
#[derive(Debug)]
pub enum Pushed {
    /// Unspent until now. Spent by this call.
    Fresh {
        client_id: String,
        parameters: Value,
    },
    /// Spent before, or never pushed at all.
    Unusable,
}

pub async fn keep(
    transaction: &Transaction<'_>,
    handle_hash: &str,
    client_id: &str,
    parameters: &Value,
    expires_at: DateTime<Utc>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO pushed_requests \
                 (tenant, realm_id, handle_hash, client_id, parameters, expires_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4",
            &[&handle_hash, &client_id, parameters, &expires_at],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Spend a reference. One statement, so two browsers arriving together cannot
/// both be served.
pub async fn spend(transaction: &Transaction<'_>, handle_hash: &str) -> StoreResult<Pushed> {
    Ok(transaction
        .query_opt(
            "UPDATE pushed_requests SET redeemed_at = now() \
             WHERE handle_hash = $1 AND redeemed_at IS NULL AND expires_at > now() \
             RETURNING client_id, parameters",
            &[&handle_hash],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map_or(Pushed::Unusable, |row| Pushed::Fresh {
            client_id: row.get("client_id"),
            parameters: row.get("parameters"),
        }))
}

pub async fn drop_expired_requests(transaction: &Transaction<'_>) -> StoreResult<u64> {
    transaction
        .execute("DELETE FROM pushed_requests WHERE expires_at <= now()", &[])
        .await
        .map_err(|_| StoreError::Backend)
}
