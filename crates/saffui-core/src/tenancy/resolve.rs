//! From a realm name to a scope. Realm first: the tenant is read from where
//! the realm is, on the server, and never from anything the caller sent.

use super::{RealmName, RealmScope};
use crate::app::App;
use crate::error::{ErrorCode, Failure};

/// Resolves the scope a realm name designates.
///
/// # Errors
///
/// Returns [`ErrorCode::RealmNotFound`] for a name that is not well formed,
/// that designates nothing, or that designates a disabled realm: the three
/// answer alike. Returns the storage failure when the directory cannot be read.
pub async fn resolve_realm(app: &App, name: &str) -> Result<(RealmName, RealmScope), Failure> {
    let name = RealmName::parse(name).map_err(|_| Failure::new(ErrorCode::RealmNotFound))?;
    match app.storage.locate_realm(&name).await? {
        Some(location) if location.enabled => {
            Ok((name, RealmScope::bind(location.tenant, location.realm)))
        }
        _ => Err(Failure::new(ErrorCode::RealmNotFound)),
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_realm;
    use crate::error::ErrorCode;
    use crate::tenancy::realm::{NewRealm, provision_first_realm};
    use crate::testkit::drive::complete;
    use crate::testkit::memory::MemoryStorage;

    #[test]
    fn a_provisioned_realm_resolves_to_its_own_scope() {
        let (app, _storage) = MemoryStorage::wire();
        let provisioned = complete(provision_first_realm(
            &app,
            NewRealm {
                tenant_name: "Acme",
                realm_name: "acme",
            },
        ))
        .expect("a first realm");

        let (name, scope) = complete(resolve_realm(&app, "acme")).expect("the realm resolves");

        assert_eq!(name.as_str(), "acme");
        assert_eq!(scope.tenant(), provisioned.tenant.id);
        assert_eq!(scope.realm(), provisioned.realm.id);
    }

    #[test]
    fn an_unknown_name_and_a_malformed_name_answer_alike() {
        let (app, _storage) = MemoryStorage::wire();

        for name in ["nobody", "Not A Name", ""] {
            let refused = complete(resolve_realm(&app, name)).map_err(|failure| failure.code);
            assert_eq!(refused, Err(ErrorCode::RealmNotFound), "{name:?}");
        }
    }

    #[test]
    fn a_disabled_realm_answers_as_if_it_did_not_exist() {
        let (app, storage) = MemoryStorage::wire();
        complete(provision_first_realm(
            &app,
            NewRealm {
                tenant_name: "Acme",
                realm_name: "acme",
            },
        ))
        .expect("a first realm");
        storage.disable_realm("acme");

        let refused = complete(resolve_realm(&app, "acme")).map_err(|failure| failure.code);

        assert_eq!(refused, Err(ErrorCode::RealmNotFound));
    }
}
