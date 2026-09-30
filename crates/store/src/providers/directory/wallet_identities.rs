use chrono::{DateTime, Utc};

use crate::error::{StoreError, StoreResult, refuse_broken_rule};
use crate::tenancy::UnitOfWork;

/// An identity an account linked, named by its issuer. The digest stays in the
/// store: it answers whether a presentation matches, and is shown to nobody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linked {
    pub issuer: String,
    pub linked_at: DateTime<Utc>,
}

/// Link an identity to an account, and tell whoever listens: the person hears
/// of it, whoever linked it. The schema refuses an identity another account
/// holds, and a second identity from the same issuer.
pub async fn link(
    transaction: &UnitOfWork,
    user_id: &str,
    issuer: &str,
    digest: &str,
    at: &DateTime<Utc>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO wallet_identities (tenant, realm_id, user_id, issuer, digest, linked_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4",
            &[&user_id, &issuer, &digest, at],
        )
        .await
        .map_err(refuse_broken_rule)?;
    crate::providers::events::outbox::emit(
        transaction,
        crate::providers::events::outbox::IDENTITY_LINKED,
        user_id,
        &serde_json::json!({ "provider": issuer, "account_created": false }),
    )
    .await
}

/// The account this identity answers for, if any.
pub async fn holder(
    transaction: &UnitOfWork,
    issuer: &str,
    digest: &str,
) -> StoreResult<Option<String>> {
    Ok(transaction
        .query_opt(
            "SELECT user_id FROM wallet_identities WHERE issuer = $1 AND digest = $2",
            &[&issuer, &digest],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| row.get(0)))
}

/// Whether this account holds this identity.
pub async fn holds(
    transaction: &UnitOfWork,
    user_id: &str,
    issuer: &str,
    digest: &str,
) -> StoreResult<bool> {
    Ok(transaction
        .query_opt(
            "SELECT 1 FROM wallet_identities \
             WHERE user_id = $1 AND issuer = $2 AND digest = $3",
            &[&user_id, &issuer, &digest],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .is_some())
}

/// The identities an account linked, oldest first.
pub async fn of_user(transaction: &UnitOfWork, user_id: &str) -> StoreResult<Vec<Linked>> {
    let rows = transaction
        .query(
            "SELECT issuer, linked_at FROM wallet_identities \
             WHERE user_id = $1 ORDER BY linked_at, issuer",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(rows
        .into_iter()
        .map(|row| Linked {
            issuer: row.get("issuer"),
            linked_at: row.get("linked_at"),
        })
        .collect())
}

/// Unlink the identity an account holds from this issuer, and say whether it
/// held one.
pub async fn unlink(transaction: &UnitOfWork, user_id: &str, issuer: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM wallet_identities WHERE user_id = $1 AND issuer = $2",
            &[&user_id, &issuer],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}
