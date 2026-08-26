use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;

use crate::error::{StoreError, StoreResult};

/// Whether this proof had already been spent.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Spent {
    /// First time seen, and now recorded.
    No,
    /// Seen before, within the window it is still judged in.
    Already,
}

/// Record a proof, and say whether it was already there.
///
/// One statement, so two requests arriving together cannot both be told they
/// were first: the insert either takes the row or finds it taken.
pub async fn spend(
    transaction: &Transaction<'_>,
    proof_hash: &str,
    expires_at: DateTime<Utc>,
) -> StoreResult<Spent> {
    let written = transaction
        .execute(
            "INSERT INTO dpop_proofs (tenant, realm_id, proof_hash, expires_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2 \
             ON CONFLICT (tenant, realm_id, proof_hash) DO NOTHING",
            &[&proof_hash, &expires_at],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    Ok(if written == 1 {
        Spent::No
    } else {
        Spent::Already
    })
}

/// Drop the proofs that can no longer be presented.
pub async fn drop_expired_proofs(transaction: &Transaction<'_>) -> StoreResult<u64> {
    transaction
        .execute("DELETE FROM dpop_proofs WHERE expires_at <= now()", &[])
        .await
        .map_err(|_| StoreError::Backend)
}
