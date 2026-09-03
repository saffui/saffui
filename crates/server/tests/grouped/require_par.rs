
#[allow(unused_imports)]
use super::support;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;
use super::support::{Plane, urlencode};

const REDIRECT: &str = "https://app.example/callback";

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
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
        sealing: support::sealing(),
        egress: config::serving::Egress::Outward,
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, support::REALM)
}

async fn realm_requires(plane: &Plane, required: bool) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let mut realm = store::providers::realms::load(&transaction, support::REALM)
        .await
        .expect("the realms table")
        .expect("a planted realm");
    realm.require_pushed_authorization_requests = required;
    store::providers::realms::update(&transaction, &realm)
        .await
        .expect("the realms table");
    transaction.commit().await.expect("the setting kept");
}

async fn client_says(plane: &Plane, says: Option<bool>) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
        .await
        .expect("the clients table")
        .expect("a planted client");
    client.require_pushed_authorization_requests = says;
    store::providers::clients::update(&transaction, &client)
        .await
        .expect("the clients table");
    transaction.commit().await.expect("the setting kept");
}

/// Where the browser was sent, straight to the authorization endpoint.
async fn direct(plane: &Plane) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope=openid&state=s",
                support::REALM,
                support::CONFIDENTIAL,
                urlencode(REDIRECT),
            ))
            .to_request(),
    )
    .await;
    response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

async fn pushed_then_sent(plane: &Plane) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded = data_encoding::BASE64
        .encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/par",
                support::REALM
            ))
            .insert_header(("authorization", format!("Basic {encoded}")))
            .set_form([
                ("client_id", support::CONFIDENTIAL),
                ("redirect_uri", REDIRECT),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "s"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let pushed: Value = test::read_body_json(response).await;
    let reference = pushed["request_uri"].as_str().expect("a reference");

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?client_id={}&request_uri={}",
                support::REALM,
                support::CONFIDENTIAL,
                urlencode(reference),
            ))
            .to_request(),
    )
    .await;
    response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_that_asks_for_it_refuses_a_request_that_did_not_push() {
    let plane = Plane::with_actions(&[]).await;
    assert!(
        !direct(&plane).await.contains("error="),
        "a realm that asks for nothing refused a direct request"
    );

    realm_requires(&plane, true).await;
    let landing = direct(&plane).await;
    assert!(
        landing.contains("error=invalid_request"),
        "a direct request was honoured where pushing is required: {landing}"
    );
    assert!(landing.contains("state=s"), "{landing}");

    assert!(
        !pushed_then_sent(&plane).await.contains("error="),
        "a pushed request was refused where pushing is required"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_the_client_says_wins_over_the_realm() {
    let plane = Plane::with_actions(&[]).await;

    // The realm asks for nothing and this client asks for itself.
    client_says(&plane, Some(true)).await;
    assert!(
        direct(&plane).await.contains("error=invalid_request"),
        "a client that requires pushing was let through directly"
    );

    // The realm asks and this client is excused.
    realm_requires(&plane, true).await;
    client_says(&plane, Some(false)).await;
    assert!(
        !direct(&plane).await.contains("error="),
        "a client excused from pushing was refused anyway"
    );

    // Saying nothing follows the realm.
    client_says(&plane, None).await;
    assert!(
        direct(&plane).await.contains("error=invalid_request"),
        "a client that says nothing did not follow its realm"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn discovery_states_what_the_realm_asks_for() {
    let plane = Plane::with_actions(&[]).await;
    for required in [false, true] {
        realm_requires(&plane, required).await;
        let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!(
                    "/realms/{}/.well-known/openid-configuration",
                    support::REALM
                ))
                .to_request(),
        )
        .await;
        let published: Value = test::read_body_json(response).await;
        assert_eq!(
            published["require_pushed_authorization_requests"].as_bool(),
            Some(required),
            "discovery said something else"
        );
    }
}
