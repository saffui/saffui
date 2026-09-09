use deadpool_postgres::Transaction;

use crate::error::{StoreError, StoreResult};

/// One capability a realm has spoken about, and who spoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureWish {
    pub slug: String,
    pub enabled: bool,
    pub changed_by: String,
    pub changed_at: chrono::DateTime<chrono::Utc>,
}

/// Everything this realm has asked for, in slug order.
pub async fn read_wishes(transaction: &Transaction<'_>) -> StoreResult<Vec<FeatureWish>> {
    Ok(transaction
        .query(
            "SELECT slug, enabled, changed_by, changed_at FROM realm_features \
             ORDER BY slug ASC",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| FeatureWish {
            slug: row.get(0),
            enabled: row.get(1),
            changed_by: row.get(2),
            changed_at: row.get(3),
        })
        .collect())
}

/// Say what this realm wants of one capability.
pub async fn keep_wish(
    transaction: &Transaction<'_>,
    slug: &str,
    enabled: bool,
    by: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO realm_features (tenant, realm_id, slug, enabled, changed_by) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3 \
             ON CONFLICT (tenant, realm_id, slug) DO UPDATE \
                 SET enabled = EXCLUDED.enabled, \
                     changed_by = EXCLUDED.changed_by, \
                     changed_at = now()",
            &[&slug, &enabled, &by],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Stop saying anything about one capability, which returns the realm to
/// whatever the process runs. Not the same as asking for it to be off.
pub async fn forget_wish(transaction: &Transaction<'_>, slug: &str) -> StoreResult<bool> {
    Ok(transaction
        .execute("DELETE FROM realm_features WHERE slug = $1", &[&slug])
        .await
        .map_err(|_| StoreError::Backend)?
        > 0)
}
