use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::messaging::Delivery;

use crate::error::{StoreError, StoreResult};

/// What a `detail` column will hold. Longer is cut, because an SMTP server
/// that answers with a page of text should not decide the size of a row.
const DETAIL: usize = 500;

pub async fn record(transaction: &Transaction<'_>, delivery: &Delivery) -> StoreResult<()> {
    let detail = delivery.detail.as_deref().map(|held| {
        let end = held
            .char_indices()
            .nth(DETAIL)
            .map_or(held.len(), |(at, _)| at);
        &held[..end]
    });
    transaction
        .execute(
            "INSERT INTO message_deliveries \
                 (tenant, realm_id, delivery_id, user_id, purpose, recipient, \
                  attempted_at, delivered, detail) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7",
            &[
                &delivery.delivery_id,
                &delivery.user_id,
                &delivery.purpose,
                &delivery.recipient,
                &delivery.attempted_at,
                &delivery.delivered,
                &detail,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// What was attempted for this person, most recent first.
pub async fn of_user(
    transaction: &Transaction<'_>,
    user_id: &str,
    limit: i64,
) -> StoreResult<Vec<Delivery>> {
    Ok(transaction
        .query(
            "SELECT delivery_id, user_id, purpose, recipient, attempted_at, delivered, detail \
             FROM message_deliveries WHERE user_id = $1 \
             ORDER BY attempted_at DESC LIMIT $2",
            &[&user_id, &limit],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| Delivery {
            delivery_id: row.get("delivery_id"),
            user_id: row.get("user_id"),
            purpose: row.get("purpose"),
            recipient: row.get("recipient"),
            attempted_at: row.get("attempted_at"),
            delivered: row.get("delivered"),
            detail: row.get("detail"),
        })
        .collect())
}

/// Forget what is older than this, which the sweep does.
pub async fn drop_older_than(
    transaction: &Transaction<'_>,
    cut: DateTime<Utc>,
) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM message_deliveries WHERE attempted_at <= $1",
            &[&cut],
        )
        .await
        .map_err(|_| StoreError::Backend)
}

/// What this realm tried to send and could not, most recent first.
///
/// The console shows these where mail is configured, because a relay that
/// answers a probe and still refuses real mail is the case an operator cannot
/// otherwise see: the settings are right and the messages are not arriving.
pub async fn read_refusals_since(
    transaction: &Transaction<'_>,
    since: DateTime<Utc>,
    max: i64,
) -> StoreResult<Vec<Delivery>> {
    Ok(transaction
        .query(
            "SELECT delivery_id, user_id, purpose, recipient, attempted_at, delivered, detail \
             FROM message_deliveries \
             WHERE delivered = false AND attempted_at >= $1 \
             ORDER BY attempted_at DESC \
             LIMIT $2",
            &[&since, &max],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| Delivery {
            delivery_id: row.get(0),
            user_id: row.get(1),
            purpose: row.get(2),
            recipient: row.get(3),
            attempted_at: row.get(4),
            delivered: row.get(5),
            detail: row.get(6),
        })
        .collect())
}
