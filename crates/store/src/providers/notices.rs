use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;

use crate::error::{StoreError, StoreResult};

/// A notice owed to a person, as a pass claims it.
#[derive(Debug, Clone)]
pub struct HeldNotice {
    pub event_id: i64,
    pub user_id: String,
    pub kind: String,
    pub occurred_at: DateTime<Utc>,
    /// Counting the attempt this claim makes.
    pub attempts: i32,
}

/// How a notice left the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    Sent,
    /// Nothing will ever carry it.
    Skipped,
    /// Every attempt to carry it failed.
    Dead,
}

impl Settled {
    fn as_str(self) -> &'static str {
        match self {
            Settled::Sent => "sent",
            Settled::Skipped => "skipped",
            Settled::Dead => "dead",
        }
    }
}

/// Owe a person a notice about one happening, once.
///
/// The same happening told again adds nothing, nor does another happening the
/// same change wrote, nor one about a person no longer held.
pub async fn note(
    transaction: &Transaction<'_>,
    event_id: i64,
    user_id: &str,
    kind: &str,
    occurred_at: DateTime<Utc>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO security_notices (tenant, realm_id, event_id, user_id, kind, occurred_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1::bigint, $2::text, $3::text, $4::timestamptz \
             WHERE EXISTS (SELECT 1 FROM users WHERE user_id = $2::text) \
             ON CONFLICT DO NOTHING",
            &[&event_id, &user_id, &kind, &occurred_at],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The notices due, oldest first, claimed for this pass the way the outbox claims
/// its tellings: the next attempt moves out before anything is sent.
pub async fn claim_due(
    transaction: &Transaction<'_>,
    ceiling: i64,
    backoff_seconds: i64,
) -> StoreResult<Vec<HeldNotice>> {
    Ok(transaction
        .query(
            "WITH picked AS MATERIALIZED ( \
                 SELECT tenant, realm_id, event_id FROM security_notices \
                 WHERE state = 'pending' AND next_attempt_at <= now() \
                 ORDER BY event_id ASC LIMIT $1 FOR UPDATE SKIP LOCKED) \
             UPDATE security_notices held SET attempts = held.attempts + 1, \
                    next_attempt_at = now() + make_interval(secs => $2::float8 * (held.attempts + 1)) \
             FROM picked \
             WHERE held.tenant = picked.tenant AND held.realm_id = picked.realm_id \
               AND held.event_id = picked.event_id \
             RETURNING held.event_id, held.user_id, held.kind, held.occurred_at, held.attempts",
            &[&ceiling, &(backoff_seconds as f64)],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| HeldNotice {
            event_id: row.get("event_id"),
            user_id: row.get("user_id"),
            kind: row.get("kind"),
            occurred_at: row.get("occurred_at"),
            attempts: row.get("attempts"),
        })
        .collect())
}

/// Settle a notice for good.
pub async fn settle(
    transaction: &Transaction<'_>,
    event_id: i64,
    settled: Settled,
) -> StoreResult<()> {
    transaction
        .execute(
            "UPDATE security_notices SET state = $2 WHERE event_id = $1",
            &[&event_id, &settled.as_str()],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Take away the notices settled about happenings before `cutoff`, and say how
/// many went. A notice still pending is still owed.
pub async fn drop_settled_before(
    transaction: &Transaction<'_>,
    cutoff: DateTime<Utc>,
) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM security_notices WHERE state <> 'pending' AND occurred_at < $1",
            &[&cutoff],
        )
        .await
        .map_err(|_| StoreError::Backend)
}
