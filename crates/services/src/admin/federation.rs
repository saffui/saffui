use crypto::envelope::Envelope;
use data_encoding::BASE64;
use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::attributes::AttributeValue;
use models::entities::brokering::{UserFederationModel, UserFederationMutationModel};
use store::keyring::RealmKeyring;
use store::providers::brokering;

use crate::federation::{CLEAR_BIND, LdapSettings, PURPOSE, SEALED_BIND, check_bag, presentable};

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

/// The realm's directories as an answer may carry them: secrets stripped.
pub async fn list(transaction: &Transaction<'_>) -> Result<Vec<UserFederationModel>, Unwritable> {
    Ok(brokering::federations(transaction)
        .await
        .map_err(|_| Unwritable::Backend)?
        .into_iter()
        .map(presentable)
        .collect())
}

pub async fn get(
    transaction: &Transaction<'_>,
    alias: &str,
) -> Result<UserFederationModel, Unwritable> {
    brokering::federation(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)?
        .map(presentable)
        .ok_or(Unwritable::NotFound)
}

/// Write the realm's directory, whole. The bag is read here the way a login
/// will read it, and the bind secret is sealed on the way in: a bag accepted
/// unread defers every failure to somebody's sign-in.
#[allow(clippy::too_many_arguments, reason = "each is a distinct fact")]
pub async fn put(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    tenant: &str,
    realm_id: &str,
    alias: &str,
    by: &str,
    asked: UserFederationMutationModel,
) -> Result<UserFederationModel, Unwritable> {
    let standing = brokering::federation(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)?;
    let mut federation = UserFederationModel {
        realm_id: realm_id.to_owned(),
        alias: alias.to_owned(),
        enabled: asked.enabled,
        priority: asked.priority.unwrap_or(0),
        configs: asked.configs,
        metadata: AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    };
    keep_bind_secret(standing.as_ref(), &mut federation);
    if let Some(bag) = federation.configs.as_ref() {
        check_bag(bag).map_err(|why| Unwritable::Invalid(why.to_string()))?;
    }
    LdapSettings::parse(&federation).map_err(|why| Unwritable::Invalid(why.to_string()))?;
    seal_bind(ring, envelope, alias, &mut federation).await?;
    brokering::keep_federation(transaction, &federation)
        .await
        .map_err(|_| Unwritable::Backend)?;
    get(transaction, alias).await
}

fn keep_bind_secret(standing: Option<&UserFederationModel>, rewritten: &mut UserFederationModel) {
    let says_new = rewritten
        .configs
        .as_ref()
        .is_some_and(|bag| bag.contains_key(CLEAR_BIND));
    if says_new {
        return;
    }
    let same_binding = ["url", "bind_dn"].into_iter().all(|key| {
        standing
            .and_then(|held| held.configs.as_ref())
            .and_then(|bag| bag.get(key))
            == rewritten.configs.as_ref().and_then(|bag| bag.get(key))
    });
    if !same_binding {
        return;
    }
    let Some(sealed) = standing
        .and_then(|held| held.configs.as_ref())
        .and_then(|bag| bag.get(SEALED_BIND))
    else {
        return;
    };
    rewritten
        .configs
        .get_or_insert_with(Default::default)
        .insert(SEALED_BIND.to_owned(), sealed.clone());
}

pub async fn delete(transaction: &Transaction<'_>, alias: &str) -> Result<(), Unwritable> {
    brokering::drop_federation(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

async fn seal_bind(
    ring: &RealmKeyring,
    envelope: &Envelope,
    alias: &str,
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
        .seal(envelope, PURPOSE, alias, clear.as_bytes())
        .await
        .map_err(|_| Unwritable::Backend)?;
    bag.insert(
        SEALED_BIND.to_owned(),
        AttributeValue::Str(BASE64.encode(&sealed)),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::entities::attributes::AttributesMap;

    fn row(configs: AttributesMap) -> UserFederationModel {
        UserFederationModel {
            realm_id: "main".into(),
            alias: "directory".into(),
            enabled: Some(true),
            priority: 0,
            configs: Some(configs),
            metadata: AuditableModel::unassigned(),
        }
    }

    #[test]
    fn a_silent_rewrite_keeps_the_sealed_bind_secret() {
        let sealed = AttributeValue::Str("sealed".into());
        let connection = [
            (
                "url".into(),
                AttributeValue::Str("ldaps://directory".into()),
            ),
            ("bind_dn".into(), AttributeValue::Str("cn=reader".into())),
        ];
        let mut held = AttributesMap::from(connection.clone());
        held.insert(SEALED_BIND.into(), sealed.clone());
        let standing = row(held);
        let mut quiet = row(AttributesMap::from(connection));
        keep_bind_secret(Some(&standing), &mut quiet);
        assert_eq!(quiet.configs.unwrap().get(SEALED_BIND), Some(&sealed));

        let clear = AttributeValue::Str("replacement".into());
        let mut replacing = row(AttributesMap::from([(CLEAR_BIND.into(), clear.clone())]));
        keep_bind_secret(Some(&standing), &mut replacing);
        let bag = replacing.configs.unwrap();
        assert_eq!(bag.get(CLEAR_BIND), Some(&clear));
        assert!(!bag.contains_key(SEALED_BIND));

        let mut moved = row(AttributesMap::from([
            (
                "url".into(),
                AttributeValue::Str("ldaps://elsewhere".into()),
            ),
            ("bind_dn".into(), AttributeValue::Str("cn=reader".into())),
        ]));
        keep_bind_secret(Some(&standing), &mut moved);
        assert!(!moved.configs.unwrap().contains_key(SEALED_BIND));
    }
}
