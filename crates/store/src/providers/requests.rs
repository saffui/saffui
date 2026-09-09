use deadpool_postgres::Transaction;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

pub const PENDING: &str = "pending";
pub const GRANTED: &str = "granted";
pub const DENIED: &str = "denied";
pub const WITHDRAWN: &str = "withdrawn";

#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub request_id: String,
    pub user_id: String,
    pub role_id: String,
    pub reason: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub state: String,
    pub asked_by: String,
    pub decided_by: Option<String>,
    pub decided_at: Option<chrono::DateTime<chrono::Utc>>,
    pub decided_reason: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

const COLUMNS: &str = "request_id, user_id, role_id, reason, expires_at, state, \
                       asked_by, decided_by, decided_at, decided_reason, created_at";

pub async fn lodge(transaction: &Transaction<'_>, asked: &AccessRequest) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO access_requests \
                 (tenant, realm_id, request_id, user_id, role_id, reason, expires_at, asked_by) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5, $6",
            &[
                &asked.request_id,
                &asked.user_id,
                &asked.role_id,
                &asked.reason,
                &asked.expires_at,
                &asked.asked_by,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn list(transaction: &Transaction<'_>) -> StoreResult<Vec<AccessRequest>> {
    let statement =
        format!("SELECT {COLUMNS} FROM access_requests ORDER BY created_at DESC, request_id ASC");
    Ok(transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read)
        .collect())
}

pub async fn load(
    transaction: &Transaction<'_>,
    request_id: &str,
) -> StoreResult<Option<AccessRequest>> {
    let statement = format!("SELECT {COLUMNS} FROM access_requests WHERE request_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&request_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// Move one still-pending request to its decided state. Answers whether a
/// row moved: none did means someone decided first, and the caller stops
/// rather than deciding twice.
pub async fn decide(
    transaction: &Transaction<'_>,
    request_id: &str,
    to_state: &str,
    by: &str,
    reason: Option<&str>,
) -> StoreResult<bool> {
    let moved = transaction
        .execute(
            "UPDATE access_requests \
                 SET state = $2, decided_by = $3, decided_at = now(), decided_reason = $4, \
                     version = version + 1 \
             WHERE request_id = $1 AND state = 'pending'",
            &[&request_id, &to_state, &by, &reason],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(moved > 0)
}

fn read(row: Row) -> AccessRequest {
    AccessRequest {
        request_id: row.get("request_id"),
        user_id: row.get("user_id"),
        role_id: row.get("role_id"),
        reason: row.get("reason"),
        expires_at: row.get("expires_at"),
        state: row.get("state"),
        asked_by: row.get("asked_by"),
        decided_by: row.get("decided_by"),
        decided_at: row.get("decided_at"),
        decided_reason: row.get("decided_reason"),
        created_at: row.get("created_at"),
    }
}

/// How many access requests are waiting on somebody.
pub async fn count_pending(transaction: &Transaction<'_>) -> StoreResult<i64> {
    Ok(transaction
        .query_one(
            "SELECT count(*) FROM access_requests WHERE state = $1",
            &[&PENDING],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0))
}
