//! Creating a tenant with its first realm: what an operator does once per
//! customer, before anyone can sign in anywhere.

use super::{Realm, RealmId, RealmName, RealmScope, Tenant, TenantId};
use crate::app::App;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::ports::storage::StorageError;

pub struct NewRealm<'a> {
    pub tenant_name: &'a str,
    pub realm_name: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provisioned {
    pub tenant: Tenant,
    pub realm: Realm,
}

/// Creates a tenant and its first realm, both or neither.
///
/// # Errors
///
/// Returns the code of the name that is refused, [`ErrorCode::RealmNameTaken`]
/// when the realm name designates a realm already, or the storage failure.
pub async fn provision_first_realm(
    app: &App,
    wanted: NewRealm<'_>,
) -> Result<Provisioned, Failure> {
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
    work.commit().await?;
    Ok(Provisioned { tenant, realm })
}

#[cfg(test)]
mod tests {
    use super::{NewRealm, provision_first_realm};
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
}
