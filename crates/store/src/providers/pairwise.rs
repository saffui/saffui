//! The identifier one account wears in front of one sector, OIDC Core §8.

use deadpool_postgres::Transaction;

use crate::error::{StoreError, StoreResult};

/// The identifier this account already wears here, or nothing.
pub async fn subject_of(
    transaction: &Transaction<'_>,
    sector: &str,
    user_id: &str,
) -> StoreResult<Option<String>> {
    Ok(transaction
        .query_opt(
            "SELECT sub FROM pairwise_subjects WHERE sector = $1 AND user_id = $2",
            &[&sector, &user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| row.get("sub")))
}

/// Keep this identifier for this account here, or hand back the one already
/// kept: two requests racing the first login both draw one and one of them
/// loses, and the loser must read rather than fail.
pub async fn keep_subject(
    transaction: &Transaction<'_>,
    sector: &str,
    user_id: &str,
    drawn: &str,
) -> StoreResult<String> {
    transaction
        .execute(
            "INSERT INTO pairwise_subjects (tenant, realm_id, sector, user_id, sub) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3 \
             ON CONFLICT DO NOTHING",
            &[&sector, &user_id, &drawn],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    subject_of(transaction, sector, user_id)
        .await?
        .ok_or(StoreError::Backend)
}

/// The account behind an identifier, or nothing when none wears it.
pub async fn account_of(transaction: &Transaction<'_>, sub: &str) -> StoreResult<Option<String>> {
    Ok(transaction
        .query_opt(
            "SELECT user_id FROM pairwise_subjects WHERE sub = $1",
            &[&sub],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| row.get("user_id")))
}
