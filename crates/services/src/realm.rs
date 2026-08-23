//! Reading a realm and what it publishes.

use deadpool_postgres::Transaction;
use models::entities::keys::{KeyUse, RealmSigningKeyView};
use models::entities::realm::RealmModel;
use models::paging::Page;
use store::providers::{realm_keys, realms};
use store::query::list_query::ListQuery;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the realm could not be read")]
pub struct Unreadable;

/// The keys a caller may verify against, in the order the realm would rather
/// they were tried. Signing keys: nothing verifies a token against a key the
/// realm publishes to be encrypted to.
pub async fn published_keys(
    transaction: &Transaction<'_>,
) -> Result<Vec<RealmSigningKeyView>, Unreadable> {
    realm_keys::published(transaction, KeyUse::Sig)
        .await
        .map_err(|_| Unreadable)
}

/// One realm of this tenant, by identifier.
pub async fn named(
    transaction: &Transaction<'_>,
    realm_id: &str,
) -> Result<Option<RealmModel>, Unreadable> {
    realms::load(transaction, realm_id)
        .await
        .map_err(|_| Unreadable)
}

/// One page of this tenant's realms.
pub async fn listed(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> Result<Page<RealmModel>, Unreadable> {
    realms::list(transaction, query, with_total)
        .await
        .map_err(|_| Unreadable)
}
