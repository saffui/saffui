use crate::tenancy::UnitOfWork;
use chrono::{DateTime, Utc};

use crate::error::{StoreError, StoreResult};

/// Keep a draft of this realm's page wording under a drawn identifier.
///
/// Insert only, so the table needs no update privilege at all: the identifier
/// is drawn from sixteen random bytes, and a clause handling a collision that
/// cannot happen would have bought nothing and cost a grant.
pub async fn keep(
    transaction: &UnitOfWork,
    preview_id: &str,
    overrides: &serde_json::Value,
    expires_at: DateTime<Utc>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO page_previews (tenant, realm_id, preview_id, overrides, expires_at) \
             VALUES (current_setting('saffui.current_tenant', true), \
                     current_setting('saffui.current_realm', true), $1, $2, $3)",
            &[&preview_id, overrides, &expires_at],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// What that identifier holds, where it still holds anything.
///
/// The expiry is weighed in the query and on the database's own clock, so a
/// draft does not outlive its minute because a pod's clock drifted.
pub async fn read(
    transaction: &UnitOfWork,
    preview_id: &str,
) -> StoreResult<Option<serde_json::Value>> {
    let found = transaction
        .query_opt(
            "SELECT overrides FROM page_previews \
             WHERE preview_id = $1 AND expires_at > now()",
            &[&preview_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(found.map(|row| row.get::<_, serde_json::Value>(0)))
}

/// Drop what nobody can read any more. Called by the sweeper, since a draft
/// nobody came back to look at would otherwise sit there for good.
pub async fn sweep(transaction: &UnitOfWork) -> StoreResult<u64> {
    let gone = transaction
        .execute("DELETE FROM page_previews WHERE expires_at <= now()", &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(gone)
}
