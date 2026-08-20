//! What a realm has to be given before it can be administered.
//!
//! The admin plane requires a scope on the token, and `/authorize` grants no
//! scope nothing attached the client to. Between the two, the plane was
//! reachable only by a token nobody could obtain through the protocol, which is
//! what this closes and what these hold shut.

mod support;

use models::auditable::AuditableModel;
use models::entities::client::{ClientScopeModel, Protocol};
use services::authorize::granted_scope;
use services::provisioning::{ADMIN_SCOPE, AdminConsole, provision_admin_console};
use store::providers::client_scopes;
use store::tenancy::TenantContext;
use support::Fixture;

const CONSOLE: &str = "saffui-console";
const REDIRECT: &str = "https://console.test/callback";

fn console() -> AdminConsole<'static> {
    AdminConsole {
        client_id: CONSOLE,
        scope: ADMIN_SCOPE,
        redirect_uris: vec![REDIRECT.to_owned()],
    }
}

fn scope(name: &str, realm_default: bool) -> ClientScopeModel {
    ClientScopeModel {
        client_scope_id: name.to_owned(),
        realm_id: "main".to_owned(),
        name: name.to_owned(),
        description: String::new(),
        protocol: Protocol::OpenId,
        default_scope: Some(realm_default),
        configs: None,
        metadata: AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    }
}

/// The console carries the scope without naming it, which is what lets the plane
/// require it of every admin UI rather than of the ones that remembered to ask.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_console_carries_the_admin_scope_without_asking_for_it() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    provision_admin_console(&transaction, "acme", "main", &console())
        .await
        .unwrap();

    assert_eq!(
        granted_scope(&transaction, CONSOLE, "openid")
            .await
            .unwrap(),
        format!("openid {ADMIN_SCOPE}"),
        "the console had to ask for the scope its own plane requires"
    );

    // And the client the realm was planted with is not the console, so naming
    // the scope is not holding it.
    assert_eq!(
        granted_scope(&transaction, "app", &format!("openid {ADMIN_SCOPE}"))
            .await
            .unwrap(),
        "openid",
        "a client nothing attached to the admin scope was granted it"
    );
}

/// How a client holds a scope is a property of the attachment. An optional one
/// is granted only when the request names it; anything else is granted whether
/// it was named or not.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_optional_scope_is_granted_only_when_it_is_asked_for() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    // Both marked as realm defaults, which is the flag that says what a new
    // client is offered and not what an attached one holds. Reading that one
    // here would grant the optional scope too.
    for named in ["profile", "phone"] {
        client_scopes::create_scope(&transaction, &scope(named, true))
            .await
            .unwrap();
    }
    client_scopes::attach_scope(&transaction, "app", "profile", false)
        .await
        .unwrap();
    client_scopes::attach_scope(&transaction, "app", "phone", true)
        .await
        .unwrap();

    assert_eq!(
        granted_scope(&transaction, "app", "openid").await.unwrap(),
        "openid profile",
        "an optional scope was granted to a request that did not name it"
    );
    assert_eq!(
        granted_scope(&transaction, "app", "openid phone")
            .await
            .unwrap(),
        "openid phone profile"
    );
}

/// Provisioning a realm that already has a console leaves what an operator did
/// to it, and re-asserts the one thing it is here to guarantee.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn provisioning_twice_keeps_what_the_operator_changed() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    provision_admin_console(&transaction, "acme", "main", &console())
        .await
        .unwrap();

    // The console moved, and the attachment was taken away.
    let mut moved = store::providers::clients::load(&transaction, CONSOLE)
        .await
        .unwrap()
        .expect("the console");
    moved.redirect_uris = Some(vec!["https://elsewhere.test/callback".to_owned()]);
    store::providers::clients::update(&transaction, &moved)
        .await
        .unwrap();
    assert!(
        client_scopes::detach_scope(&transaction, CONSOLE, ADMIN_SCOPE)
            .await
            .unwrap()
    );

    provision_admin_console(&transaction, "acme", "main", &console())
        .await
        .unwrap();

    assert_eq!(
        store::providers::clients::load(&transaction, CONSOLE)
            .await
            .unwrap()
            .expect("the console")
            .redirect_uris,
        Some(vec!["https://elsewhere.test/callback".to_owned()]),
        "provisioning again sent the console back to an address nobody serves"
    );
    assert_eq!(
        granted_scope(&transaction, CONSOLE, "openid")
            .await
            .unwrap(),
        format!("openid {ADMIN_SCOPE}"),
        "the attachment was not put back"
    );
}

/// Creating a realm and giving it what it cannot work without are one act. A
/// realm whose scopes failed to seed is not half provisioned: it is one whose
/// clients are entitled to nothing and whose tokens carry a subject and no
/// claims, and nothing about it says so.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn provisioning_a_realm_gives_it_the_scopes_it_cannot_work_without() {
    let fixture = Fixture::empty().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::tenant_wide("acme"))
        .await;
    store::providers::tenants::create(&transaction, &tenant())
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    services::provisioning::provision_realm(&transaction, &realm(), &console())
        .await
        .unwrap();

    for (name, default) in [("profile", true), ("email", true), ("phone", false)] {
        let held = client_scopes::load_scope(&transaction, name)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{name} was not provisioned"));
        assert_eq!(
            held.default_scope,
            Some(default),
            "{name}: §5.4 gates a number behind a scope a client has to name, \
             and a default hands it to every registration"
        );
    }

    // And the console, so the plane the realm is administered from is reachable
    // by a token its own protocol can mint.
    assert!(
        client_scopes::load_scope(&transaction, ADMIN_SCOPE)
            .await
            .unwrap()
            .is_some()
    );

    // Run again. An operator who added a redirect or renamed a console must be
    // able to, and what already exists is left as it stands.
    services::provisioning::provision_realm(&transaction, &realm(), &console())
        .await
        .expect("provisioning is idempotent");
    transaction.commit().await.unwrap();
}

fn tenant() -> models::entities::tenant::TenantModel {
    models::entities::tenant::TenantCreateModel {
        tenant_id: "acme".into(),
        display_name: "Acme".into(),
        region: None,
        limits: None,
        created_by: Some("root".into()),
    }
    .into()
}

fn realm() -> models::entities::realm::RealmModel {
    models::entities::realm::RealmCreateModel {
        name: "main".into(),
        display_name: "Main".into(),
        enabled: true,
    }
    .into_model(
        "main".into(),
        AuditableModel::from_creator("acme".into(), "root".into()),
    )
}
