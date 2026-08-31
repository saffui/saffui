use crypto::provider::{DigestProvider, HashAlg};
use deadpool_postgres::Transaction;

use crate::error::{StoreError, StoreResult};

/// Remember a value once, and say whether it was new. The row lives until
/// `expires_at`, which the caller takes from the value's own window, and
/// the sweep ages it out.
pub async fn remember_once(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    purpose: &str,
    value: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> StoreResult<bool> {
    let hash = digest
        .hash(HashAlg::Sha256, value.as_bytes())
        .map_err(|_| StoreError::Backend)?;
    let fresh = transaction
        .execute(
            "INSERT INTO replay_guard (tenant, realm_id, purpose, value_hash, expires_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3 \
             ON CONFLICT (tenant, realm_id, purpose, value_hash) DO NOTHING",
            &[&purpose, &hash, &expires_at],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(fresh > 0)
}

pub async fn drop_expired(
    transaction: &Transaction<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> StoreResult<u64> {
    transaction
        .execute("DELETE FROM replay_guard WHERE expires_at <= $1", &[&now])
        .await
        .map_err(|_| StoreError::Backend)
}
