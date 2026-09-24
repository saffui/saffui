pub use store::providers::realms::realm_features::runs_for_realm;

use store::providers::realms::realm_features::{self, FeatureWish};
use store::tenancy::UnitOfWork;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the realm's capability wishes could not be read or written")]
pub struct Unwished;

/// What this realm asked for, capability by capability.
pub async fn read_wishes(transaction: &UnitOfWork) -> Result<Vec<FeatureWish>, Unwished> {
    realm_features::read_wishes(transaction)
        .await
        .map_err(|_| Unwished)
}

/// Keep this realm's wish for one capability, or forget it so the process
/// decides alone.
pub async fn write_wish(
    transaction: &UnitOfWork,
    slug: &str,
    enabled: Option<bool>,
    by: &str,
) -> Result<(), Unwished> {
    match enabled {
        Some(enabled) => realm_features::keep_wish(transaction, slug, enabled, by)
            .await
            .map_err(|_| Unwished),
        None => realm_features::forget_wish(transaction, slug)
            .await
            .map(|_| ())
            .map_err(|_| Unwished),
    }
}
