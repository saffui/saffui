use commons::feature::{Feature, RealmWishes};
use deadpool_postgres::Transaction;

/// Whether one capability is running for the realm this transaction is scoped
/// to.
///
/// The process is the ceiling, so a realm that has asked for nothing gets the
/// process's answer and no realm can reach above it. A read that fails answers
/// with the process's own state rather than refusing: a capability must not
/// switch itself off because a table was briefly unreadable.
pub async fn runs_for_realm(transaction: &Transaction<'_>, feature: Feature) -> bool {
    let process = crate::api::config::features();
    if !process.is_enabled(feature) {
        return false;
    }

    let Ok(held) = store::providers::realm_features::read_wishes(transaction).await else {
        return true;
    };
    let mut wishes = RealmWishes::none();
    for wish in &held {
        wishes = wishes
            .clone()
            .with_wish(&wish.slug, wish.enabled)
            .unwrap_or(wishes);
    }
    process.within_realm(&wishes).is_enabled(feature)
}
