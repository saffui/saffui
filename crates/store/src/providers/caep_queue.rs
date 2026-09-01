use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;

use crate::error::{StoreError, StoreResult};

/// Hold one Security Event Token for one collecting receiver.
pub async fn queue(
    transaction: &Transaction<'_>,
    receiver_id: &str,
    jti: &str,
    set_body: &str,
    expires_at: DateTime<Utc>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO security_event_queue \
                 (tenant, realm_id, receiver_id, jti, set_body, expires_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4 \
             ON CONFLICT DO NOTHING",
            &[&receiver_id, &jti, &set_body, &expires_at],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// What one receiver has waiting, oldest first, and whether there is more.
pub async fn pending(
    transaction: &Transaction<'_>,
    receiver_id: &str,
    ceiling: i64,
) -> StoreResult<(Vec<(String, String)>, bool)> {
    let rows = transaction
        .query(
            "SELECT jti, set_body FROM security_event_queue \
             WHERE receiver_id = $1 ORDER BY queued_at ASC LIMIT $2",
            &[&receiver_id, &(ceiling + 1)],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let more = rows.len() as i64 > ceiling;
    Ok((
        rows.into_iter()
            .take(ceiling as usize)
            .map(|row| (row.get("jti"), row.get("set_body")))
            .collect(),
        more,
    ))
}

/// Let go of what the receiver said it has, and say how many went.
pub async fn ack(
    transaction: &Transaction<'_>,
    receiver_id: &str,
    jtis: &[String],
) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM security_event_queue \
             WHERE receiver_id = $1 AND jti = ANY($2)",
            &[&receiver_id, &jtis],
        )
        .await
        .map_err(|_| StoreError::Backend)
}

/// Take away what nobody collected before it ran out.
pub async fn drop_expired(transaction: &Transaction<'_>, now: DateTime<Utc>) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM security_event_queue WHERE expires_at <= $1",
            &[&now],
        )
        .await
        .map_err(|_| StoreError::Backend)
}
