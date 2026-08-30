//! The plane's hands on the one ticket door a realm holds.

use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::brokering::{RealmSpnegoModel, RealmSpnegoMutationModel};
use store::providers::brokering;

use crate::negotiation::{SpnegoSettings, check_bag};

/// Why the door could not be written.
#[derive(Debug, thiserror::Error)]
pub enum Unwritable {
    #[error("the realm answers no ticket door")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
    #[error("the store could not be written")]
    Backend,
}

pub async fn get(transaction: &Transaction<'_>) -> Result<RealmSpnegoModel, Unwritable> {
    brokering::spnego(transaction)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)
}

/// Write the door, whole. The bag is read here the way a login will read it:
/// a bag accepted unread defers every failure to somebody's sign-in.
pub async fn put(
    transaction: &Transaction<'_>,
    tenant: &str,
    realm_id: &str,
    by: &str,
    asked: RealmSpnegoMutationModel,
) -> Result<RealmSpnegoModel, Unwritable> {
    let spnego = RealmSpnegoModel {
        realm_id: realm_id.to_owned(),
        enabled: asked.enabled,
        configs: asked.configs,
        metadata: AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    };
    if let Some(bag) = spnego.configs.as_ref() {
        check_bag(bag).map_err(|why| Unwritable::Invalid(why.to_string()))?;
    }
    SpnegoSettings::parse(&spnego).map_err(|why| Unwritable::Invalid(why.to_string()))?;
    brokering::keep_spnego(transaction, &spnego)
        .await
        .map_err(|_| Unwritable::Backend)?;
    get(transaction).await
}

pub async fn delete(transaction: &Transaction<'_>) -> Result<(), Unwritable> {
    brokering::drop_spnego(transaction)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}
