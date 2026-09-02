//! The sign-in log, when the realm switched it on.
//!
//! Best-effort by contract: every writer treats a refusal here as a warning,
//! because a login must never fail on account of its own record.

use deadpool_postgres::Transaction;

use crate::error::{StoreError, StoreResult};

/// One recorded moment of a sign-in's life.
#[derive(Debug, Clone)]
pub struct LoginEvent {
    pub id: i64,
    pub recorded_at: i64,
    pub kind: String,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub session_id: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub detail: Option<serde_json::Value>,
}

/// What a writer states; the row's identity and instant are the store's.
#[derive(Debug, Clone, Default)]
pub struct LoginEventWrite<'a> {
    pub kind: &'a str,
    pub user_id: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub detail: Option<serde_json::Value>,
}

pub async fn record(
    transaction: &Transaction<'_>,
    at: i64,
    event: &LoginEventWrite<'_>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO login_events \
             (tenant, realm_id, recorded_at, kind, user_id, client_id, session_id, \
              ip, user_agent, detail) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8",
            &[
                &at,
                &event.kind,
                &event.user_id,
                &event.client_id,
                &event.session_id,
                &event.ip,
                &event.user_agent,
                &event.detail,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Newest first, one page, with the total when it was paid for.
pub async fn list(
    transaction: &Transaction<'_>,
    first: i64,
    max: i64,
    count: bool,
) -> StoreResult<(Vec<LoginEvent>, Option<i64>)> {
    let rows = transaction
        .query(
            "SELECT id, recorded_at, kind, user_id, client_id, session_id, \
                    ip, user_agent, detail \
             FROM login_events ORDER BY recorded_at DESC, id DESC \
             OFFSET $1 LIMIT $2",
            &[&first, &max],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let events = rows
        .into_iter()
        .map(|row| LoginEvent {
            id: row.get("id"),
            recorded_at: row.get("recorded_at"),
            kind: row.get("kind"),
            user_id: row.get("user_id"),
            client_id: row.get("client_id"),
            session_id: row.get("session_id"),
            ip: row.get("ip"),
            user_agent: row.get("user_agent"),
            detail: row.get("detail"),
        })
        .collect();
    let total = if count {
        Some(
            transaction
                .query_one("SELECT count(*) FROM login_events", &[])
                .await
                .map_err(|_| StoreError::Backend)?
                .get(0),
        )
    } else {
        None
    };
    Ok((events, total))
}

/// Age the window: everything older than the cutoff goes.
pub async fn drop_older_than(transaction: &Transaction<'_>, cutoff: i64) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM login_events WHERE recorded_at < $1",
            &[&cutoff],
        )
        .await
        .map_err(|_| StoreError::Backend)
}
