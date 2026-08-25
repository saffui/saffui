use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use serde_json::Value;

use crate::error::{StoreError, StoreResult};

/// A response waiting for the browser that will post it.
#[derive(Debug, Clone)]
pub struct Waiting {
    pub redirect_uri: String,
    pub parameters: Value,
}

/// Put a response aside for the page that posts it.
pub async fn keep(
    transaction: &Transaction<'_>,
    ticket_hash: &str,
    redirect_uri: &str,
    parameters: &Value,
    expires_at: DateTime<Utc>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO form_post_landings \
                 (tenant, realm_id, ticket_hash, redirect_uri, parameters, expires_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4",
            &[&ticket_hash, &redirect_uri, parameters, &expires_at],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Take the response this ticket stands for, and leave nothing behind.
///
/// One statement, so a ticket presented twice is answered once: the second
/// caller deletes no row and is told nothing.
pub async fn take(
    transaction: &Transaction<'_>,
    ticket_hash: &str,
) -> StoreResult<Option<Waiting>> {
    Ok(transaction
        .query_opt(
            "DELETE FROM form_post_landings \
             WHERE ticket_hash = $1 AND expires_at > now() \
             RETURNING redirect_uri, parameters",
            &[&ticket_hash],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| Waiting {
            redirect_uri: row.get("redirect_uri"),
            parameters: row.get("parameters"),
        }))
}

/// Drop what no browser came back for.
pub async fn drop_expired_landings(transaction: &Transaction<'_>) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM form_post_landings WHERE expires_at <= now()",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)
}
