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

/// A deployment stands up from nothing, and standing it up again changes
/// nothing: every piece says whether it was created, and the second pass says
/// no everywhere. What was created is usable, not merely present: the key is
/// published, the flow is the one `/authorize` looks up, the password verifies.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_deployment_is_provisioned_once_and_left_alone_after() {
    use crypto::envelope::Envelope;
    use crypto::password::migration::verify_and_plan;
    use crypto::password::storage::StoredPassword;
    use crypto::provider::SignAlg;
    use models::entities::credentials::CredentialType;
    use models::entities::keys::KeyUse;
    use secrecy::SecretBox;
    use services::provisioning::{
        Person, Registration, provision_browser_flow, provision_client, provision_signing_key,
        provision_tenant, provision_user,
    };
    use std::sync::Arc;
    use store::providers::{auth_flows, clients, credentials, realm_keys, users};

    let fixture = Fixture::empty().await;
    let provider = support::provider();
    let envelope = Envelope::new(
        Arc::new(support::provider()),
        "a-wrapping-key-of-decent-length",
    )
    .expect("an envelope");
    let secret = SecretBox::new(Box::new("a-client-secret".to_owned()));
    let password = SecretBox::new(Box::new("a-password-of-decent-length".to_owned()));

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::tenant_wide("local"))
        .await;
    assert!(
        provision_tenant(&transaction, "local", "Local")
            .await
            .unwrap()
    );
    assert!(
        !provision_tenant(&transaction, "local", "Local")
            .await
            .unwrap()
    );
    let realm = models::entities::realm::RealmCreateModel {
        name: "main".into(),
        display_name: "Main".into(),
        enabled: true,
    }
    .into_model(
        "main".into(),
        AuditableModel::from_creator("local".into(), "provisioner".into()),
    );
    store::providers::realms::create(&transaction, &realm)
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("local", "main"))
        .await;
    let registration = Registration {
        client_id: "app",
        secret: Some(&secret),
        redirect_uris: vec!["https://app.example/callback".into()],
        post_logout_redirect_uris: vec!["https://app.example/bye".into()],
        backchannel_logout_uri: Some("https://app.example/logout-token".into()),
        frontchannel_logout_uri: Some("https://app.example/logout-frame".into()),
        implicit: false,
    };
    let person = Person {
        user_name: "ada",
        email: "ada@example.test",
        password: &password,
        given_name: Some("Ada"),
        family_name: Some("Lovelace"),
        phone: Some("+33123456789"),
        attributes: vec![("user.profile.locale", "en-GB")],
    };
    for (pass, expected) in [("first", true), ("second", false)] {
        assert_eq!(
            provision_signing_key(
                &transaction,
                &provider,
                &envelope,
                "local",
                "main",
                1_700_000_000
            )
            .await
            .unwrap(),
            expected,
            "{pass} pass, signing key"
        );
        assert_eq!(
            provision_browser_flow(&transaction, "local", "main")
                .await
                .unwrap(),
            expected,
            "{pass} pass, browser flow"
        );
        assert_eq!(
            provision_client(&transaction, &provider, "local", "main", &registration)
                .await
                .unwrap(),
            expected,
            "{pass} pass, client"
        );
        assert_eq!(
            provision_user(&transaction, &provider, "local", "main", &person)
                .await
                .unwrap(),
            expected,
            "{pass} pass, user"
        );
    }

    let published = realm_keys::published(&transaction, KeyUse::Sig)
        .await
        .unwrap();
    let mut algorithms: Vec<_> = published.iter().map(|key| key.algorithm).collect();
    algorithms.sort_by_key(|algorithm| algorithm.name());
    assert_eq!(
        algorithms,
        vec![SignAlg::Es256, SignAlg::Rs256],
        "one key per algorithm a fresh realm signs with, published once"
    );
    for key in &published {
        assert_eq!(
            key.kid,
            crypto::thumbprint::jwk_sha256_thumbprint(
                &provider,
                &crypto::jose::jwk::Jwk::from_map(
                    key.public_jwk.as_object().expect("a jwk").clone()
                )
                .expect("the published key")
            )
            .expect("its thumbprint"),
            "the key is not named by its thumbprint"
        );
    }

    let flow = auth_flows::flow_by_alias(&transaction, "browser")
        .await
        .unwrap()
        .expect("the flow /authorize looks up");
    assert_eq!(
        auth_flows::executions_of(&transaction, &flow.flow_id)
            .await
            .unwrap()
            .len(),
        1,
        "one password step"
    );

    let client = clients::load(&transaction, "app")
        .await
        .unwrap()
        .expect("the client");
    assert_eq!(
        client.public_client,
        Some(false),
        "a client with a secret is confidential"
    );
    assert_eq!(client.standard_flow_enabled, Some(true));
    assert_eq!(
        client.post_logout_redirect_uris.as_deref(),
        Some(&["https://app.example/bye".to_owned()][..]),
        "where a logout may land was not registered"
    );
    assert_eq!(
        services::authorize::granted_scope(&transaction, "app", "openid profile email phone")
            .await
            .unwrap(),
        "openid profile email phone",
        "a standard scope asked for was not granted"
    );
    assert_eq!(
        services::authorize::granted_scope(&transaction, "app", "openid email")
            .await
            .unwrap(),
        "openid email",
        "a scope nobody asked for was granted anyway"
    );

    let user = users::load_by_name(&transaction, "ada")
        .await
        .unwrap()
        .expect("the user");
    assert_eq!(user.phone_number.as_deref(), Some("+33123456789"));
    assert_eq!(user.phone_number_verified, Some(true));
    assert_eq!(
        user.attributes
            .as_ref()
            .and_then(|held| models::entities::attributes::string_at(
                held,
                models::entities::user::profile::FIRST_NAME
            )),
        Some("Ada"),
        "the given name was not kept where the profile scope reads it"
    );
    let held =
        credentials::load_for_user_of_type(&transaction, &user.user_id, CredentialType::Password)
            .await
            .unwrap();
    let stored = StoredPassword::Argon2id {
        encoded: held[0].secret.expose().to_owned(),
    }
    .to_legacy_hash()
    .expect("a password in the shape the login reads");
    assert!(
        verify_and_plan(&provider, &password, &stored)
            .expect("a verification")
            .valid,
        "the provisioned password does not verify"
    );
    transaction.commit().await.unwrap();
}
