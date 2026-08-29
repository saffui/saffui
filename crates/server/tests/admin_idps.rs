mod support;

use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use support::Plane;

const REALM: &str = support::REALM;

/// Ask the plane, with a body or without one.
async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    use actix_web::{App, test};
    use server::api::config::register;
    use server::middleware::admin_policy::AdminPolicy;
    let app = test::init_service(App::new().configure(register(&server::api::config::Plane {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    })))
    .await;
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
    let told = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, told)
}

fn upstream(alias: &str) -> Value {
    json!({
        "provider_id": alias,
        "name": alias,
        "display_name": "An upstream",
        "description": "",
        "trust_email": false,
        "configs": {
            "issuer": { "Str": "https://op.example/realms/main" },
            "authorization_endpoint": { "Str": "https://op.example/auth" },
            "token_endpoint": { "Str": "https://op.example/token" },
            "jwks_uri": { "Str": "https://op.example/certs" },
            "client_id": { "Str": "saffui-at-op" },
            "client_secret": { "Str": "a-shared-secret" },
        },
    })
}

/// A provider is registered with its configuration read at the door, its
/// secret sealed on the way in and never read back, and refused deletion
/// while accounts are linked through it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_provider_is_kept_whole_and_its_secret_is_kept_dark() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/identity-providers");

    // The configuration is read the way a login will read it: a bag missing
    // what decides trust is refused here, naming the field.
    let mut lacking = upstream("half");
    lacking["configs"]
        .as_object_mut()
        .unwrap()
        .remove("token_endpoint");
    let (status, told) = asked(&plane, Method::POST, &base, &bearer, Some(lacking)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|held| held.contains("token_endpoint")),
        "the missing field is not named: {told}"
    );

    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(
            json!({ "provider_id": "two words", "name": "x", "display_name": "x",
                     "description": "", "configs": {} }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, born) = asked(&plane, Method::POST, &base, &bearer, Some(upstream("acme"))).await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let bag = born["configs"].as_object().expect("a bag");
    assert!(
        !bag.contains_key("client_secret_sealed"),
        "the sealed bytes rode out over the plane: {born}"
    );
    assert_eq!(born["configs"]["client_secret"]["Str"], "**********");

    let (status, told) = asked(&plane, Method::POST, &base, &bearer, Some(upstream("acme"))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "identity_provider.already_exists");

    // A rewrite that says nothing about the secret keeps the sealed one;
    // and a provider answers to one alias.
    let mut renamed = upstream("acme");
    renamed["provider_id"] = json!("elsewhere");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/acme"),
        &bearer,
        Some(renamed),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let mut quiet = upstream("acme");
    quiet["configs"]
        .as_object_mut()
        .unwrap()
        .remove("client_secret");
    quiet["description"] = json!("rewritten");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/acme"),
        &bearer,
        Some(quiet),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["description"], "rewritten");
    assert_eq!(
        told["configs"]["client_secret"]["Str"], "**********",
        "the kept secret is no longer there: {told}"
    );

    // Linked through, the provider stays; released, it goes.
    {
        use models::entities::brokering::FederatedIdentityModel;
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::brokering::link(
            &transaction,
            &FederatedIdentityModel {
                realm_id: REALM.into(),
                user_id: support::SUBJECT.into(),
                provider_alias: "acme".into(),
                external_user_id: "upstream-ada".into(),
                external_username: "ada@upstream".into(),
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/acme"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    let (status, held) = asked(
        &plane,
        Method::GET,
        &format!(
            "/admin/realms/{REALM}/users/{}/federated-identities",
            support::SUBJECT
        ),
        &bearer,
        None,
    )
    .await;
    // The route costs user:read, which this plane does not hold.
    assert_eq!(status, StatusCode::FORBIDDEN, "{held}");
}

/// Reading the providers does not grant writing them, and the user's own
/// links read under the user capability.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_idp_capabilities_split_where_they_should() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::UserRead]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/identity-providers");

    let (status, told) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, _) = asked(&plane, Method::POST, &base, &bearer, Some(upstream("x"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, held) = asked(
        &plane,
        Method::GET,
        &format!(
            "/admin/realms/{REALM}/users/{}/federated-identities",
            support::SUBJECT
        ),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert_eq!(held.as_array().expect("links").len(), 0);
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/users/nobody/federated-identities"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
