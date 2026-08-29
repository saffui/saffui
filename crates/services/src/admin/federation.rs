use crypto::envelope::Envelope;
use data_encoding::BASE64;
use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::attributes::AttributeValue;
use models::entities::brokering::{UserFederationModel, UserFederationMutationModel};
use store::keyring::RealmKeyring;
use store::providers::brokering;

use crate::federation::{
    CLEAR_BIND, LdapSettings, PURPOSE, SEALED_BIND, SINGLETON, check_bag, presentable,
};

/// Why the directory could not be written.
#[derive(Debug, thiserror::Error)]
pub enum Unwritable {
    #[error("the realm federates no directory")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
    #[error("the store could not be written")]
    Backend,
}

/// The realm's directory as an answer may carry it: secrets stripped.
pub async fn get(transaction: &Transaction<'_>) -> Result<UserFederationModel, Unwritable> {
    brokering::federation(transaction)
        .await
        .map_err(|_| Unwritable::Backend)?
        .map(presentable)
        .ok_or(Unwritable::NotFound)
}

/// Write the realm's directory, whole. The bag is read here the way a login
/// will read it, and the bind secret is sealed on the way in: a bag accepted
/// unread defers every failure to somebody's sign-in.
pub async fn put(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    tenant: &str,
    realm_id: &str,
    by: &str,
    asked: UserFederationMutationModel,
) -> Result<UserFederationModel, Unwritable> {
    let mut federation = UserFederationModel {
        realm_id: realm_id.to_owned(),
        enabled: asked.enabled,
        configs: asked.configs,
        metadata: AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    };
    if let Some(bag) = federation.configs.as_ref() {
        check_bag(bag).map_err(|why| Unwritable::Invalid(why.to_string()))?;
    }
    LdapSettings::parse(&federation).map_err(|why| Unwritable::Invalid(why.to_string()))?;
    seal_bind(ring, envelope, &mut federation).await?;
    brokering::keep_federation(transaction, &federation)
        .await
        .map_err(|_| Unwritable::Backend)?;
    get(transaction).await
}

pub async fn delete(transaction: &Transaction<'_>) -> Result<(), Unwritable> {
    brokering::drop_federation(transaction)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

async fn seal_bind(
    ring: &RealmKeyring,
    envelope: &Envelope,
    federation: &mut UserFederationModel,
) -> Result<(), Unwritable> {
    let Some(bag) = federation.configs.as_mut() else {
        return Ok(());
    };
    let Some(taken) = bag.remove(CLEAR_BIND) else {
        return Ok(());
    };
    let Some(clear) = taken.as_str() else {
        return Err(Unwritable::Invalid(
            "the bind secret is a string".to_owned(),
        ));
    };
    let sealed = ring
        .seal(envelope, PURPOSE, SINGLETON, clear.as_bytes())
        .await
        .map_err(|_| Unwritable::Backend)?;
    bag.insert(
        SEALED_BIND.to_owned(),
        AttributeValue::Str(BASE64.encode(&sealed)),
    );
    Ok(())
}
