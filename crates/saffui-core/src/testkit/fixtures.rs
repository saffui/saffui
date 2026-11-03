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
            capabilities: &[],
        },
    )
    .await
    .expect("a client");
    work.commit().await.expect("a commit");
    secret
}

/// Registers a client that may call the administration plane with these
/// capabilities, and returns a token it was just given.
///
/// # Panics
///
/// Panics when the client cannot be registered or the token granted.
pub async fn create_administrator(
    app: &App,
    realm: &str,
    scope: RealmScope,
    client_id: &str,
    capabilities: &[crate::authz::capability::Capability],
) -> String {
    use crate::oidc::token::{TokenRequest, grant_token};

    let scopes = [crate::authz::admin::ADMIN_SCOPE.to_owned()];
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let wanted = NewServiceClient {
        client_id,
        name: "An administrator under test",
        scopes: &scopes,
        capabilities,
    };
    let (_client, secret) = register_service_client(app, work.as_mut(), wanted)
        .await
        .expect("a client");
    work.commit().await.expect("a commit");
    let request = TokenRequest {
        grant_type: Some("client_credentials"),
        scope: None,
        client_id: Some(client_id),
        client_secret: Some(secret),
    };
    grant_token(app, realm, request)
        .await
        .expect("a token")
        .access_token
}

/// Creates a person with a password, and an address made from the name.
///
/// # Panics
///
/// Panics when the person cannot be created.
pub async fn create_person(
    app: &App,
    scope: RealmScope,
    username: &str,
    password: &str,
) -> crate::directory::Person {
    use crate::directory::create::{NewPerson, create_person as create};

    let wanted = NewPerson {
        username,
        email: Some(&format!("{username}@example.org")),
        display_name: Some("A person under test"),
        password: Some(Secret::new(password.as_bytes().to_vec())),
        created_by: None,
    };
    create(app, scope, wanted).await.expect("a person")
}
