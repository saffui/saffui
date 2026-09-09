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

/// Whether one capability is running for the realm this transaction is scoped
/// to.
///
/// The process is the ceiling, so a realm that has asked for nothing gets the
/// process's answer and none can reach above it. A read that fails answers
/// with the process's own state rather than refusing: a capability must not
/// switch itself off because a table was briefly unreadable.
///
/// It lives here, at the bottom, because a capability is refused where it is
/// used and the places it is used run from the login engine to the admin
/// doors. Every layer above can ask without being handed the answer.
pub async fn runs_for_realm(
    transaction: &Transaction<'_>,
    feature: commons::feature::Feature,
) -> bool {
    let process = commons::feature::installed();
    if !process.is_enabled(feature) {
        return false;
    }

    let Ok(held) = read_wishes(transaction).await else {
        return true;
    };
    let mut wishes = commons::feature::RealmWishes::none();
    for wish in &held {
        wishes = wishes
            .clone()
            .with_wish(&wish.slug, wish.enabled)
            .unwrap_or(wishes);
    }
    process.within_realm(&wishes).is_enabled(feature)
}
