mod support;

use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use data_encoding::BASE64;
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;
use support::Plane;

const REALM: &str = support::REALM;
const CERT_HEADER: &str = "x-ssl-client-cert";

fn mounted(plane: &Plane) -> server::api::config::Plane {
    server::api::config::Plane {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Anywhere,
        sealing: support::sealing(),
    }
}

fn behind_proxy(plane: &Plane) -> server::api::config::Plane {
    server::api::config::Plane {
        hops: config::proxying::Proxying::behind_terminating_peers(
            config::proxying::ProxyHeader::XForwardedFor,
            CERT_HEADER,
            vec![config::proxying::Peer::parse("10.0.0.0/8").expect("a peer")],
        ),
        ..mounted(plane)
    }
}

async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asking = test::TestRequest::default()
        .method(method)
        .uri(path)
        .insert_header(("authorization", format!("Bearer {bearer}")));
    if let Some(body) = body {
        asking = asking.set_json(body);
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn opted_with_policy(plane: &Plane, server_id: &str) {
    use models::entities::attributes::AttributeValue;
    use store::tenancy::TenantContext;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
        .await
        .unwrap()
        .expect("the client");
    let bag = client.configs.get_or_insert_with(Default::default);
    for (key, value) in [
        ("token.exchange.enabled", "true"),
        ("token.exchange.policy_server", server_id),
        ("token.exchange.policy_resource", "exchange"),
        ("token.exchange.policy_scope", "delegate"),
    ] {
        bag.insert(key.to_owned(), AttributeValue::Str(value.to_owned()));
    }
    assert!(
        store::providers::clients::update(&transaction, &client)
            .await
            .unwrap()
    );
    transaction.commit().await.unwrap();
}

/// The engine's surface, planted the way the engine reads it: the client as a
/// resource server, the exchange as a protected resource with one scope, and
/// one permission conditioned on a role.
async fn protected_by_managers(plane: &Plane) {
    use models::auditable::AuditableModel;
    use models::entities::authz::{DecisionLogic, DecisionStrategy, PolicyRule, PolicyTerms};
    use store::tenancy::TenantContext;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    for statement in [
        "INSERT INTO resource_servers (tenant, realm_id, server_id) \
         VALUES ('acme', 'main', 'app')",
        "INSERT INTO resources \
             (tenant, realm_id, resource_id, server_id, name, resource_type, resource_owner) \
         VALUES ('acme', 'main', 'exchange', 'app', 'token-exchange', 'urn:exchange', 'app')",
        "INSERT INTO scopes (tenant, realm_id, scope_id, server_id, name) \
         VALUES ('acme', 'main', 'delegate', 'app', 'delegate')",
        "INSERT INTO resource_scopes (tenant, realm_id, server_id, resource_id, scope_id) \
         VALUES ('acme', 'main', 'app', 'exchange', 'delegate')",
        "INSERT INTO roles (tenant, realm_id, role_id, name, display_name) \
         VALUES ('acme', 'main', 'managers', 'managers', 'Managers')",
    ] {
        transaction.execute(statement, &[]).await.unwrap();
    }
    let managers = PolicyTerms {
        name: "managers".into(),
        description: String::new(),
        decision: DecisionStrategy::Unanimous,
        logic: DecisionLogic::Positive,
        policy_owner: "app".into(),
        policies: Vec::new(),
        resources: Vec::new(),
        scopes: Vec::new(),
        rule: PolicyRule::Role {
            roles: vec!["managers".into()],
        },
    }
    .into_model(
        "managers-only".into(),
        "app".into(),
        REALM.into(),
        None,
        AuditableModel::from_creator(support::TENANT.into(), "root".into()),
    );
    store::providers::authz_policies::create(&transaction, &managers)
        .await
        .unwrap();
    let may_delegate = PolicyTerms {
        name: "may-delegate".into(),
        description: String::new(),
        decision: DecisionStrategy::Unanimous,
        logic: DecisionLogic::Positive,
        policy_owner: "app".into(),
        policies: vec!["managers-only".into()],
        resources: vec!["exchange".into()],
        scopes: vec!["delegate".into()],
        rule: PolicyRule::ScopePermission {
            resource_type: String::new(),
        },
    }
    .into_model(
        "may-delegate".into(),
        "app".into(),
        REALM.into(),
        None,
        AuditableModel::from_creator(support::TENANT.into(), "root".into()),
    );
    store::providers::authz_policies::create(&transaction, &may_delegate)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

async fn granted_role(plane: &Plane, user_id: &str, role_id: &str) {
    use store::tenancy::TenantContext;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    store::providers::roles::grant_to_user(&transaction, user_id, role_id)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

async fn tokens_of_ada(plane: &Plane) -> String {
    let code = plane
        .mint_code(support::CONFIDENTIAL, support::REDIRECT, "openid", None)
        .await;
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
            .insert_header(("authorization", format!("Basic {encoded}")))
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", support::REDIRECT),
            ])
            .to_request(),
    )
    .await;
    let body: Value = test::read_body_json(response).await;
    body["access_token"].as_str().expect("a token").to_owned()
}

async fn exchange(plane: &Plane, subject_token: &str) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
            .insert_header(("authorization", format!("Basic {encoded}")))
            .set_form([
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token", subject_token),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
            ])
            .to_request(),
    )
    .await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// The policy engine gates the exchange when the client asks it to: the same
/// subject is refused without the role and admitted with it, and both
/// decisions land in the journal.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_policy_engine_gates_the_exchange() {
    let plane = Plane::with_actions(&[AdminAction::AuthzDecisionRead]).await;
    let bearer = plane.token(&support::claims());

    protected_by_managers(&plane).await;
    opted_with_policy(&plane, "app").await;
    let subject_token = tokens_of_ada(&plane).await;

    // Ada is no manager: the engine says no, the exchange says no.
    let (status, told) = exchange(&plane, &subject_token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "unauthorized_client", "{told}");

    // Made a manager, the same exchange passes.
    granted_role(&plane, support::SUBJECT, "managers").await;
    let (status, told) = exchange(&plane, &subject_token).await;
    assert_eq!(status, StatusCode::OK, "{told}");

    // Both decisions were journalled, against the exchange's own action.
    let (status, decisions) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/authz/decisions"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{decisions}");
    let ours: Vec<&Value> = decisions
        .as_array()
        .into_iter()
        .flatten()
        .filter(|held| held["action"] == "token-exchange")
        .collect();
    assert_eq!(ours.len(), 2, "{decisions}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_mesh_certificate_is_an_identity_too() {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::x509::{X509Builder, X509NameBuilder};

    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());

    // The trusted mesh: same provider row as the token side, spiffe patterns.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        Some(json!({
            "provider_id": "the-mesh",
            "name": "the-mesh",
            "display_name": "", "description": "", "trust_email": false,
            "configs": {
                "kind": { "Str": "workload" },
                "issuer": { "Str": "spiffe://mesh" },
                "jwks_uri": { "Str": "https://unused.example/jwks" },
                "audience": { "Str": "unused" },
                "subject_patterns": { "Str": "spiffe://mesh/payments spiffe://mesh/billing-*" },
                "client_id": { "Str": support::CONFIDENTIAL },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");

    let minted = |uri: &str| {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "workload").unwrap();
        let name = name.build();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        let san = SubjectAlternativeName::new()
            .uri(uri)
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(san).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        BASE64.encode(&builder.build().to_der().unwrap())
    };

    let app = test::init_service(App::new().configure(register(&behind_proxy(&plane)))).await;
    let called = |certificate: Option<String>| {
        let mut asking = test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
            .peer_addr("10.1.2.3:5000".parse().unwrap())
            .set_form([("grant_type", "client_credentials")]);
        if let Some(certificate) = certificate {
            asking = asking.insert_header((CERT_HEADER, certificate));
        }
        asking.to_request()
    };

    // The admitted identity signs in; act names its URI.
    let response = test::call_service(&app, called(Some(minted("spiffe://mesh/payments")))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let minted_tokens: Value = test::read_body_json(response).await;
    let claims = plane
        .claims_of(minted_tokens["access_token"].as_str().expect("a token"))
        .await;
    assert_eq!(claims["sub"], "service-account-app", "{claims}");
    assert_eq!(claims["act"]["sub"], "spiffe://mesh/payments", "{claims}");
    assert_eq!(claims["act"]["iss"], "x509", "{claims}");

    // The prefix admits billing-eu; a stranger and a bare call are refused
    // with one face.
    let response = test::call_service(&app, called(Some(minted("spiffe://mesh/billing-eu")))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = test::call_service(&app, called(Some(minted("spiffe://intruder/app")))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Carrying no certificate at all is not this door's failure: the caller
    // simply never said who it was, and is refused as such.
    let response = test::call_service(&app, called(None)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let refused: Value = test::read_body_json(response).await;
    assert_eq!(refused["error"], "invalid_client", "{refused}");
}
