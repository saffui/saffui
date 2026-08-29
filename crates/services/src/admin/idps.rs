use crypto::envelope::Envelope;
use crypto::provider::CryptoProvider;
use data_encoding::{BASE64, BASE64URL_NOPAD};
use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::attributes::AttributeValue;
use models::entities::authz::{IdentityProviderModel, IdentityProviderMutationModel};
use store::keyring::RealmKeyring;
use store::providers::brokering;

use crate::brokering::Upstream;

/// What the sealed upstream secret is scoped to.
const PURPOSE: &str = "identity-provider-secret";
/// Where the sealed half lives in the bag; the clear key never lands.
pub const SEALED_SECRET: &str = "client_secret_sealed";
const CLEAR_SECRET: &str = "client_secret";

#[derive(Debug, thiserror::Error)]
pub enum Unwritable {
    #[error("one with this alias already exists")]
    AlreadyExists,
    #[error("no such provider")]
    NotFound,
    /// Deletion refused while local accounts are linked through the alias:
    /// the links carry no key to the provider row, so deleting it would
    /// leave them naming a door that no longer exists.
    #[error("accounts are still linked through this provider")]
    StillLinked,
    #[error("{0}")]
    Invalid(String),
    #[error("the store could not be written")]
    Backend,
}

pub async fn providers(
    transaction: &Transaction<'_>,
) -> Result<Vec<IdentityProviderModel>, Unwritable> {
    let mut listed = brokering::list_providers(transaction)
        .await
        .map_err(|_| Unwritable::Backend)?;
    for provider in &mut listed {
        conceal(provider);
    }
    Ok(listed)
}

pub async fn get_provider(
    transaction: &Transaction<'_>,
    alias: &str,
) -> Result<IdentityProviderModel, Unwritable> {
    let mut found = brokering::provider_by_alias(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)?;
    conceal(&mut found);
    Ok(found)
}

/// What an answer never carries: the sealed bytes are the deployment's, and
/// even sealed they are nobody's to read back over the plane.
fn conceal(provider: &mut IdentityProviderModel) {
    if let Some(bag) = provider.configs.as_mut() {
        bag.remove(CLEAR_SECRET);
        if bag.remove(SEALED_SECRET).is_some() {
            bag.insert(
                CLEAR_SECRET.to_owned(),
                AttributeValue::Str("**********".to_owned()),
            );
        }
    }
}

/// Seal the upstream secret into the bag, so the clear value never lands.
async fn seal_secret(
    ring: &RealmKeyring,
    envelope: &Envelope,
    provider: &mut IdentityProviderModel,
) -> Result<(), Unwritable> {
    let Some(bag) = provider.configs.as_mut() else {
        return Ok(());
    };
    let Some(taken) = bag.remove(CLEAR_SECRET) else {
        return Ok(());
    };
    let Some(clear) = taken.as_str() else {
        return Err(Unwritable::Invalid(
            "the upstream secret is a string".to_owned(),
        ));
    };
    let sealed = ring
        .seal(envelope, PURPOSE, &provider.internal_id, clear.as_bytes())
        .await
        .map_err(|_| Unwritable::Backend)?;
    bag.insert(
        SEALED_SECRET.to_owned(),
        AttributeValue::Str(BASE64.encode(&sealed)),
    );
    Ok(())
}

/// Register an upstream. The configuration is read the way a login will
/// read it, here at the door: a bag accepted unread defers every failure
/// to somebody's sign-in.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one registration"
)]
pub async fn create_provider(
    transaction: &Transaction<'_>,
    crypto: &dyn CryptoProvider,
    ring: &RealmKeyring,
    envelope: &Envelope,
    tenant: &str,
    realm_id: &str,
    by: &str,
    asked: IdentityProviderMutationModel,
) -> Result<IdentityProviderModel, Unwritable> {
    if asked.provider_id.trim().is_empty()
        || asked.provider_id.contains('/')
        || asked.provider_id.contains(char::is_whitespace)
    {
        return Err(Unwritable::Invalid(
            "an alias rides a path segment: no spaces, no slashes".to_owned(),
        ));
    }
    if brokering::provider_by_alias(transaction, &asked.provider_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .is_some()
    {
        return Err(Unwritable::AlreadyExists);
    }

    let mut provider = asked.into_model(
        drawn(crypto)?,
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    Upstream::parse(&provider).map_err(|why| Unwritable::Invalid(why.to_string()))?;
    seal_secret(ring, envelope, &mut provider).await?;
    brokering::create_provider(transaction, &provider)
        .await
        .map_err(|_| Unwritable::Backend)?;
    conceal(&mut provider);
    Ok(provider)
}

pub async fn update_provider(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    alias: &str,
    by: &str,
    asked: IdentityProviderMutationModel,
) -> Result<IdentityProviderModel, Unwritable> {
    let standing = brokering::provider_by_alias(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)?;
    if asked.provider_id != standing.provider_id {
        return Err(Unwritable::Invalid(
            "a provider answers to one alias and does not change it".to_owned(),
        ));
    }

    let mut rewritten = asked.into_model(
        standing.internal_id.clone(),
        standing.realm_id.clone(),
        standing.metadata.clone(),
    );
    rewritten.metadata.updated_by = Some(by.to_owned());
    // A rewrite that says nothing about the secret keeps the sealed one.
    let says_secret = rewritten
        .configs
        .as_ref()
        .is_some_and(|bag| bag.contains_key(CLEAR_SECRET));
    if !says_secret
        && let Some(kept) = standing
            .configs
            .as_ref()
            .and_then(|bag| bag.get(SEALED_SECRET))
    {
        rewritten
            .configs
            .get_or_insert_with(Default::default)
            .insert(SEALED_SECRET.to_owned(), kept.clone());
    }
    Upstream::parse(&rewritten).map_err(|why| Unwritable::Invalid(why.to_string()))?;
    seal_secret(ring, envelope, &mut rewritten).await?;
    if !brokering::update_provider(transaction, &rewritten)
        .await
        .map_err(|_| Unwritable::Backend)?
    {
        return Err(Unwritable::NotFound);
    }
    get_provider(transaction, alias).await
}

pub async fn delete_provider(transaction: &Transaction<'_>, alias: &str) -> Result<(), Unwritable> {
    let standing = brokering::provider_by_alias(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)?;
    if brokering::alias_still_linked(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)?
    {
        return Err(Unwritable::StillLinked);
    }
    brokering::delete_provider(transaction, &standing.internal_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

fn drawn(crypto: &dyn CryptoProvider) -> Result<String, Unwritable> {
    let mut bytes = [0_u8; 16];
    crypto
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Unwritable::Backend)?;
    Ok(format!("idp-{}", BASE64URL_NOPAD.encode(&bytes)))
}
