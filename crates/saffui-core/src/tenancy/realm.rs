//! Creating a tenant with its first realm, and the first client of that
//! realm: what an operator does once per customer, before anyone can sign in
//! anywhere.

use serde_json::json;

use super::{Realm, RealmId, RealmName, RealmScope, Tenant, TenantId};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::clients::register::{NewServiceClient, register_service_client};
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::keys::generate::create_first_keys;
use crate::ports::storage::StorageError;
use crate::secret::Secret;

pub struct NewRealm<'a> {
    pub tenant_name: &'a str,
    pub realm_name: &'a str,
}

/// A service client created with the realm, for the operator to start from.
pub struct FirstClient<'a> {
    pub client_id: &'a str,
    pub scopes: &'a [String],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provisioned {
    pub tenant: Tenant,
    pub realm: Realm,
}

/// Creates a tenant and its first realm, both or neither. The creation is
/// the first event of the chain of the realm, and the realm is born with its
/// keys, all written by the same unit of work: a realm never exists without
/// them.
///
/// # Errors
///
/// Returns the code of the name that is refused, [`ErrorCode::RealmNameTaken`]
/// when the realm name designates a realm already,
/// [`ErrorCode::CryptoUnavailable`] when its keys cannot be made, or the
/// storage failure.
pub async fn provision_first_realm(
    app: &App,
    wanted: NewRealm<'_>,
) -> Result<Provisioned, Failure> {
    provision_realm_with_client(app, wanted, None)
        .await
        .map(|(provisioned, _secret)| provisioned)
}

/// As [`provision_first_realm`], with a first client of the realm written by
/// the same unit of work, and its secret, returned here and never again.
///
/// # Errors
///
/// As [`provision_first_realm`], and the code of what is refused in the client.
pub async fn provision_realm_with_client(
    app: &App,
    wanted: NewRealm<'_>,
    first_client: Option<FirstClient<'_>>,
) -> Result<(Provisioned, Option<Secret>), Failure> {
    let realm_name = RealmName::parse(wanted.realm_name)?;
    let tenant_name = wanted.tenant_name.trim();
    if !(1..=120).contains(&tenant_name.chars().count())
        || tenant_name.chars().any(char::is_control)
    {
        return Err(Failure::new(ErrorCode::TenantNameInvalid));
    }

    let created_at = app.now();
    let tenant = Tenant {
        id: TenantId::from_uuid(mint_id(app)?),
        name: tenant_name.to_owned(),
        created_at,
    };
    let realm = Realm {
        id: RealmId::from_uuid(mint_id(app)?),
        tenant: tenant.id,
        name: realm_name,
        enabled: true,
        created_at,
    };

    let mut work = app
        .storage
        .begin(RealmScope::bind(tenant.id, realm.id))
        .await?;
    work.insert_tenant(&tenant).await?;
    work.insert_realm(&realm)
        .await
        .map_err(|error| match error {
            StorageError::Taken("realm name") => Failure::new(ErrorCode::RealmNameTaken),
            other => other.into(),
        })?;
    let created = json!({ "name": realm.name.as_str(), "tenant_name": tenant.name });
    record_event(app, work.as_mut(), EventKind::RealmCreated, created).await?;
    create_first_keys(app, work.as_mut()).await?;
    let secret = match first_client {
        Some(client) => {
            let service = NewServiceClient {
                client_id: client.client_id,
                name: client.client_id,
                scopes: client.scopes,
            };
            Some(
                register_service_client(app, work.as_mut(), service)
                    .await?
                    .1,
            )
        }
        None => None,
    };
    work.commit().await?;
    Ok((Provisioned { tenant, realm }, secret))
}

#[cfg(test)]
mod tests {
    use super::{FirstClient, NewRealm, provision_first_realm, provision_realm_with_client};
    use crate::error::ErrorCode;
    use crate::testkit::drive::complete;
    use crate::testkit::memory::MemoryStorage;

    fn acme() -> NewRealm<'static> {
        NewRealm {
            tenant_name: "Acme",
            realm_name: "acme",
        }
    }

    #[test]
    fn a_tenant_and_its_first_realm_are_created_together() {
        let (app, storage) = MemoryStorage::wire();

        let provisioned = complete(provision_first_realm(&app, acme())).expect("a first realm");

        assert_eq!(provisioned.realm.tenant, provisioned.tenant.id);
        assert!(provisioned.realm.enabled);
        assert_eq!(storage.count_tenants(), 1);
        assert_eq!(storage.count_realms(), 1);
    }

    #[test]
    fn creating_a_realm_and_its_keys_is_recorded_in_its_chain_by_the_same_unit_of_work() {
        let (app, storage) = MemoryStorage::wire();

        let provisioned = complete(provision_first_realm(&app, acme())).expect("a first realm");

        let recorded = storage.read_audit_envelopes(provisioned.realm.id);
        let kinds: Vec<&str> = recorded
            .iter()
            .filter_map(|event| event["kind"].as_str())
            .collect();
        assert_eq!(kinds, ["realm.created", "key.created"]);
        assert_eq!(recorded[0]["payload"]["name"], "acme");
        assert_eq!(recorded[0]["payload"]["tenant_name"], "Acme");
        assert_eq!(
            storage.count_units_of_work(),
            1,
            "the events were written by the unit of work that created the realm"
        );
        assert_eq!(
            recorded[1]["payload"]["alg"], "ES256",
            "the first key signs in ES256"
        );
    }

    #[test]
    fn a_realm_name_already_taken_is_refused_and_leaves_no_tenant_behind() {
        let (app, storage) = MemoryStorage::wire();
        complete(provision_first_realm(&app, acme())).expect("a first realm");

        let refused = complete(provision_first_realm(
            &app,
            NewRealm {
                tenant_name: "Another customer",
                realm_name: "acme",
            },
        ))
        .map_err(|failure| failure.code);

        assert_eq!(refused, Err(ErrorCode::RealmNameTaken));
        assert_eq!(storage.count_tenants(), 1, "the second tenant was not kept");
    }

    #[test]
    fn a_name_that_cannot_be_used_is_refused_before_anything_is_written() {
        let (app, storage) = MemoryStorage::wire();

        let bad_realm = complete(provision_first_realm(
            &app,
            NewRealm {
                tenant_name: "Acme",
                realm_name: "Acme Prod",
            },
        ))
        .map_err(|failure| failure.code);
        let bad_tenant = complete(provision_first_realm(
            &app,
            NewRealm {
                tenant_name: "  ",
                realm_name: "acme",
            },
        ))
        .map_err(|failure| failure.code);

        assert_eq!(bad_realm, Err(ErrorCode::RealmNameInvalid));
        assert_eq!(bad_tenant, Err(ErrorCode::TenantNameInvalid));
        assert_eq!(storage.count_units_of_work(), 0);
    }

    #[test]
    fn a_first_client_is_created_with_the_realm_and_its_secret_is_given_once() {
        let (app, storage) = MemoryStorage::wire();
        let scopes = ["invoices:read".to_owned()];

        let (provisioned, secret) = complete(provision_realm_with_client(
            &app,
            acme(),
            Some(FirstClient {
                client_id: "billing",
                scopes: &scopes,
            }),
        ))
        .expect("a realm and its client");

        assert!(secret.is_some(), "the secret is given to the operator");
        let kinds: Vec<String> = storage
            .read_audit_envelopes(provisioned.realm.id)
            .iter()
            .filter_map(|event| event["kind"].as_str().map(str::to_owned))
            .collect();
        assert_eq!(kinds, ["realm.created", "key.created", "client.created"]);
        assert_eq!(storage.count_units_of_work(), 1, "one unit of work for all");
    }

    #[test]
    fn a_first_client_that_cannot_be_registered_leaves_no_realm_behind() {
        let (app, storage) = MemoryStorage::wire();

        let refused = complete(provision_realm_with_client(
            &app,
            acme(),
            Some(FirstClient {
                client_id: "bill ing",
                scopes: &[],
            }),
        ))
        .map(|_| ())
        .map_err(|failure| failure.code);

        assert_eq!(refused, Err(ErrorCode::ClientIdentifierInvalid));
        assert_eq!(storage.count_realms(), 0);
        assert_eq!(storage.count_tenants(), 0);
    }
}
