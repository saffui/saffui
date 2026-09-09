use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use serde_json::Value;

use crate::error::{StoreError, StoreResult};

pub const USER_CREATED: &str = "user.created";
pub const USER_UPDATED: &str = "user.updated";
pub const USER_DELETED: &str = "user.deleted";
pub const SESSION_REVOKED: &str = "session.revoked";
pub const CREDENTIAL_CHANGED: &str = "credential.changed";
pub const AGENT_REGISTERED: &str = "agent.registered";
pub const AGENT_RESHAPED: &str = "agent.reshaped";
pub const AGENT_REVOKED: &str = "agent.revoked";
pub const AGENT_LIFTED: &str = "agent.lifted";

#[derive(Debug, Clone)]
pub struct OutboxEvent {
    pub event_id: i64,
    pub realm_id: String,
    pub kind: String,
    pub user_id: String,
    pub payload: Value,
    pub attempts: i32,
    /// When the happening happened, which under retries is not when any
    /// telling of it goes out.
    pub occurred_at: DateTime<Utc>,
}

/// The channel a committed emission is spoken on, for whoever listens.
pub const CHANNEL: &str = "saffui_events";

/// Record one happening, inside the transaction that made it happen. The
/// notify rides the same transaction, and Postgres only speaks it at
/// commit: nothing is announced that did not happen.
pub async fn emit(
    transaction: &Transaction<'_>,
    kind: &str,
    user_id: &str,
    payload: &Value,
) -> StoreResult<()> {
    transaction
        .execute(
            "WITH told AS ( \
                 INSERT INTO event_outbox (tenant, realm_id, kind, user_id, payload) \
                 SELECT current_setting('saffui.current_tenant', true), \
                        current_setting('saffui.current_realm', true), $1, $2, $3 \
                 RETURNING tenant, realm_id, event_id, kind, user_id, occurred_at) \
             SELECT pg_notify($4, json_build_object( \
                        'tenant', tenant, 'realm', realm_id, 'event_id', event_id, \
                        'kind', kind, 'user_id', user_id, \
                        'occurred_at', to_char(occurred_at at time zone 'UTC', \
                                               'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'))::text) \
             FROM told",
            &[&kind, &user_id, &payload, &CHANNEL],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The tellings given up on, newest first: the dead-letter queue, as rows
/// an operator can see and requeue instead of a state only a SELECT knows.
pub async fn dead_list(transaction: &Transaction<'_>, limit: i64) -> StoreResult<Vec<OutboxEvent>> {
    Ok(transaction
        .query(
            "SELECT realm_id, event_id, kind, user_id, payload, attempts, occurred_at \
             FROM event_outbox WHERE state = 'dead' \
             ORDER BY event_id DESC LIMIT $1",
            &[&limit],
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
            occurred_at: row.get("occurred_at"),
        })
        .collect())
}

/// Put one dead telling back in the queue, due at once. The attempts stay
/// counted: a requeue is another chance, not a clean record.
pub async fn requeue(transaction: &Transaction<'_>, event_id: i64) -> StoreResult<bool> {
    let changed = transaction
        .execute(
            "UPDATE event_outbox SET state = 'pending', next_attempt_at = now() \
             WHERE event_id = $1 AND state = 'dead'",
            &[&event_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
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
            // The pick is materialised so it runs exactly once: an IN-subquery
            // with SKIP LOCKED may be re-evaluated per candidate row, and each
            // evaluation skips what the last one locked, which quietly hands
            // out more rows than the ceiling names.
            "WITH picked AS MATERIALIZED ( \
                 SELECT tenant, realm_id, event_id FROM event_outbox \
                 WHERE state = 'pending' AND next_attempt_at <= $3 \
                 ORDER BY event_id ASC LIMIT $1 FOR UPDATE SKIP LOCKED) \
             UPDATE event_outbox held SET attempts = held.attempts + 1, \
                    next_attempt_at = $3 + make_interval(secs => $2::float8 * (held.attempts + 1)) \
             FROM picked \
             WHERE held.tenant = picked.tenant AND held.realm_id = picked.realm_id \
               AND held.event_id = picked.event_id \
             RETURNING held.realm_id, held.event_id, held.kind, held.user_id, \
                       held.payload, held.attempts, held.occurred_at",
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
            occurred_at: row.get("occurred_at"),
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

/// The retained tellings of a range, oldest first: what a replay may still
/// reach. Delivered and dead alike are replayable; pending ones are not
/// offered, because the delivery pass owns them.
pub async fn retained(
    transaction: &Transaction<'_>,
    from: i64,
    to: Option<i64>,
    limit: i64,
) -> StoreResult<Vec<OutboxEvent>> {
    Ok(transaction
        .query(
            "SELECT realm_id, event_id, kind, user_id, payload, attempts, occurred_at \
             FROM event_outbox \
             WHERE state <> 'pending' AND event_id >= $1 AND event_id <= COALESCE($2, event_id) \
             ORDER BY event_id ASC LIMIT $3",
            &[&from, &to, &limit],
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
            occurred_at: row.get("occurred_at"),
        })
        .collect())
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

/// Fell this person's queued events, before the one that says the account
/// is gone is emitted: telling the world about somebody being erased must
/// not first deliver their profile.
pub async fn erase_pending_for_user(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<u64> {
    transaction
        .execute("DELETE FROM event_outbox WHERE user_id = $1", &[&user_id])
        .await
        .map_err(|_| StoreError::Backend)
}

/// How many tellings are still waiting to go out of this realm.
///
/// The state is indexed and the rows are the realm's, so this is a reading an
/// operator can take often without paying for it.
pub async fn count_waiting(transaction: &Transaction<'_>) -> StoreResult<i64> {
    Ok(transaction
        .query_one(
            "SELECT count(*) FROM event_outbox WHERE state = 'pending'",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0))
}
