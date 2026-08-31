use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use serde_json::Value;

use crate::error::{StoreError, StoreResult};

pub const USER_CREATED: &str = "user.created";
pub const USER_UPDATED: &str = "user.updated";
pub const USER_DELETED: &str = "user.deleted";

#[derive(Debug, Clone)]
pub struct OutboxEvent {
    pub event_id: i64,
    pub realm_id: String,
    pub kind: String,
    pub user_id: String,
    pub payload: Value,
    pub attempts: i32,
}

/// Record one happening, inside the transaction that made it happen.
pub async fn emit(
    transaction: &Transaction<'_>,
    kind: &str,
    user_id: &str,
    payload: &Value,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO event_outbox (tenant, realm_id, kind, user_id, payload) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3",
            &[&kind, &user_id, &payload],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The tellings that are due, oldest first, claimed for this pass: the next
/// attempt moves out before the work starts, so a crashed worker costs a
/// delay and never a double-claim inside the window.
pub async fn due(
    transaction: &Transaction<'_>,
    ceiling: i64,
    backoff_seconds: i64,
    now: DateTime<Utc>,
) -> StoreResult<Vec<OutboxEvent>> {
    Ok(transaction
        .query(
            "UPDATE event_outbox SET attempts = attempts + 1, \
                    next_attempt_at = $3 + make_interval(secs => $2::float8 * (attempts + 1)) \
             WHERE (tenant, realm_id, event_id) IN ( \
                 SELECT tenant, realm_id, event_id FROM event_outbox \
                 WHERE state = 'pending' AND next_attempt_at <= $3 \
                 ORDER BY event_id ASC LIMIT $1 FOR UPDATE SKIP LOCKED) \
             RETURNING realm_id, event_id, kind, user_id, payload, attempts",
            &[&ceiling, &(backoff_seconds as f64), &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| OutboxEvent {
            event_id: row.get("event_id"),
            realm_id: row.get("realm_id"),
            kind: row.get("kind"),
            user_id: row.get("user_id"),
            payload: row.get("payload"),
            attempts: row.get("attempts"),
        })
        .collect())
}

pub async fn delivered(transaction: &Transaction<'_>, event_id: i64) -> StoreResult<()> {
    transaction
        .execute(
            "UPDATE event_outbox SET state = 'delivered' WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Give up on one telling, out loud: dead is a state an operator can see,
/// not a silent drop.
pub async fn dead(transaction: &Transaction<'_>, event_id: i64) -> StoreResult<()> {
    transaction
        .execute(
            "UPDATE event_outbox SET state = 'dead' WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn drop_delivered(
    transaction: &Transaction<'_>,
    before: DateTime<Utc>,
) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM event_outbox WHERE state = 'delivered' AND occurred_at <= $1",
            &[&before],
        )
        .await
        .map_err(|_| StoreError::Backend)
}
