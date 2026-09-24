//! A realm's configuration and upkeep: its keys, provisioning, theme,
//! features and sweeping.

pub mod feature;
pub mod housekeeping;
pub mod page_previews;
pub mod provisioning;
pub mod theme;

use crypto::provider::SignAlg;
use models::entities::keys::{KeyStatus, KeyUse, RealmSigningKeyView};
use models::entities::realm::RealmModel;
use models::paging::Page;
use store::providers::realms;
use store::providers::realms::realm_keys;
use store::query::list_query::ListQuery;
use store::tenancy::UnitOfWork;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the realm could not be read")]
pub struct Unreadable;

/// The keys a caller may verify against, in the order the realm would rather
/// they were tried. Signing keys: nothing verifies a token against a key the
/// realm publishes to be encrypted to.
pub async fn published_keys(
    transaction: &UnitOfWork,
) -> Result<Vec<RealmSigningKeyView>, Unreadable> {
    realm_keys::published(transaction, KeyUse::Sig)
        .await
        .map_err(|_| Unreadable)
}

/// The algorithms this realm signs responses with: those of its active signing
/// keys. A key in retreat still verifies what it signed and signs nothing new,
/// so a response asked for in its algorithm alone could never be sent.
pub async fn active_signing_algorithms(
    transaction: &UnitOfWork,
) -> Result<Vec<SignAlg>, Unreadable> {
    let mut held: Vec<SignAlg> = realm_keys::published(transaction, KeyUse::Sig)
        .await
        .map_err(|_| Unreadable)?
        .into_iter()
        .filter(|key| key.status == KeyStatus::Active)
        .map(|key| key.algorithm)
        .collect();
    held.sort_unstable_by_key(|algorithm| algorithm.name());
    held.dedup();
    Ok(held)
}

/// The keys a caller may encrypt to, in the order the realm would rather they
/// were used.
pub async fn published_encryption_keys(
    transaction: &UnitOfWork,
) -> Result<Vec<models::entities::keys::RealmEncryptionKeyView>, Unreadable> {
    realm_keys::published_encryption(transaction)
        .await
        .map_err(|_| Unreadable)
}

/// One realm of this tenant, by identifier.
pub async fn named(
    transaction: &UnitOfWork,
    realm_id: &str,
) -> Result<Option<RealmModel>, Unreadable> {
    realms::load(transaction, realm_id)
        .await
        .map_err(|_| Unreadable)
}

/// One page of this tenant's realms.
pub async fn listed(
    transaction: &UnitOfWork,
    query: &ListQuery<'_>,
    with_total: bool,
) -> Result<Page<RealmModel>, Unreadable> {
    realms::list(transaction, query, with_total)
        .await
        .map_err(|_| Unreadable)
}

/// Write the realm's switches back.
///
/// False when no realm by that identity holds a row to write, which the
/// caller reads as not found rather than as a fresh realm: reshaping is not
/// creating.
pub async fn reshape(transaction: &UnitOfWork, realm: &RealmModel) -> Result<bool, Unreadable> {
    realms::update(transaction, realm)
        .await
        .map_err(|_| Unreadable)
}
