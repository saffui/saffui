//! What most tests start from: a realm, and a client in it.

use crate::app::App;
use crate::clients::register::{NewServiceClient, register_service_client};
use crate::secret::Secret;
use crate::tenancy::RealmScope;
use crate::tenancy::realm::{NewRealm, provision_first_realm};
use crate::tenancy::resolve::resolve_realm;

/// Creates a realm of that name and returns its scope.
///
/// # Panics
///
/// Panics when the realm cannot be created.
pub async fn create_realm(app: &App, name: &str) -> RealmScope {
    provision_first_realm(
        app,
        NewRealm {
            tenant_name: "Tenant under test",
            realm_name: name,
        },
    )
    .await
    .expect("a realm");
    resolve_realm(app, name)
        .await
        .expect("the realm resolves")
        .1
}

/// Registers a service client in the realm and returns its secret.
///
/// # Panics
///
/// Panics when the client cannot be registered.
pub async fn create_service_client(
    app: &App,
    scope: RealmScope,
    client_id: &str,
    scopes: &[&str],
) -> Secret {
    let scopes: Vec<String> = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let (_client, secret) = register_service_client(
        app,
        work.as_mut(),
        NewServiceClient {
            client_id,
            name: "A service under test",
            scopes: &scopes,
        },
    )
    .await
    .expect("a client");
    work.commit().await.expect("a commit");
    secret
}
