
#[allow(unused_imports)]
use super::support;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;
use super::support::{Plane, cookie_value, urlencode};

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

async fn demand_consent(plane: &Plane, demanded: bool) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
        .await
        .expect("the clients table")
        .expect("a planted client");
    client.consent_required = Some(demanded);
    store::providers::clients::update(&transaction, &client)
        .await
        .expect("the clients table");
    transaction.commit().await.expect("the setting kept");
}

async fn opened(plane: &Plane, scope: &str) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope={}&state=s",
                support::REALM,
                support::CONFIDENTIAL,
                urlencode(REDIRECT),
                urlencode(scope),
            ))
            .to_request(),
    )
    .await;
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login")
}

async fn answered(plane: &Plane, binding: &str, body: Value) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/login",
                support::REALM
            ))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .set_json(body)
            .to_request(),
    )
    .await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

fn credentials() -> Value {
    serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD })
}

fn with_consent(answer: &str) -> Value {
    let mut body = credentials();
    body["consent"] = Value::String(answer.to_owned());
    body
}

async fn agreed_scopes(plane: &Plane) -> Option<Vec<String>> {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    store::providers::consents::held(&transaction, support::SUBJECT, support::CONFIDENTIAL)
        .await
        .expect("the consents table")
        .map(|held| held.scopes)
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_that_asks_for_consent_gets_a_screen_and_then_an_answer() {
    let plane = Plane::with_actions(&[]).await;
    demand_consent(&plane, true).await;

    let binding = opened(&plane, "openid profile").await;
    let (status, shown) = answered(&plane, &binding, credentials()).await;
    assert_eq!(status, StatusCode::OK, "{shown}");
    assert_eq!(shown["status"].as_str(), Some("consent"), "{shown}");
    assert_eq!(shown["client_id"].as_str(), Some(support::CONFIDENTIAL));
    let scopes: Vec<String> = serde_json::from_value(shown["scopes"].clone()).expect("scopes");
    assert!(scopes.contains(&"openid".to_owned()), "{scopes:?}");
    assert!(scopes.contains(&"profile".to_owned()), "{scopes:?}");
    assert_eq!(agreed_scopes(&plane).await, None, "agreed too early");

    let (status, admitted) = answered(&plane, &binding, with_consent("granted")).await;
    assert_eq!(status, StatusCode::OK, "{admitted}");
    assert_eq!(admitted["status"].as_str(), Some("admitted"), "{admitted}");
    let agreed = agreed_scopes(&plane).await.expect("a consent");
    assert!(agreed.contains(&"profile".to_owned()), "{agreed:?}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn saying_no_is_the_client_s_answer_and_not_a_refused_login() {
    let plane = Plane::with_actions(&[]).await;
    demand_consent(&plane, true).await;

    let binding = opened(&plane, "openid profile").await;
    answered(&plane, &binding, credentials()).await;
    let (status, told) = answered(&plane, &binding, with_consent("refused")).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"].as_str(), Some("sent_back"), "{told}");
    let landing = told["redirect_to"].as_str().expect("a landing");
    assert!(
        landing.contains("error=access_denied"),
        "the client was told something else: {landing}"
    );
    assert!(landing.contains("state=s"), "{landing}");
    assert_eq!(agreed_scopes(&plane).await, None, "a refusal was recorded");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_was_agreed_to_is_not_asked_again() {
    let plane = Plane::with_actions(&[]).await;
    demand_consent(&plane, true).await;

    let binding = opened(&plane, "openid profile").await;
    answered(&plane, &binding, credentials()).await;
    answered(&plane, &binding, with_consent("granted")).await;

    // A second login, same scopes: nothing to ask.
    let again = opened(&plane, "openid profile").await;
    let (status, admitted) = answered(&plane, &again, credentials()).await;
    assert_eq!(status, StatusCode::OK, "{admitted}");
    assert_eq!(
        admitted["status"].as_str(),
        Some("admitted"),
        "a person was asked again for what they had already agreed to: {admitted}"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn asking_for_more_is_asked_again_and_asking_for_less_is_not() {
    let plane = Plane::with_actions(&[]).await;
    demand_consent(&plane, true).await;
    let binding = opened(&plane, "openid profile").await;
    answered(&plane, &binding, credentials()).await;
    answered(&plane, &binding, with_consent("granted")).await;

    // Narrower: nothing new was asked for.
    let narrower = opened(&plane, "openid").await;
    let (_, admitted) = answered(&plane, &narrower, credentials()).await;
    assert_eq!(
        admitted["status"].as_str(),
        Some("admitted"),
        "asking for less was treated as asking for something new: {admitted}"
    );

    // Wider: something new.
    let wider = opened(&plane, "openid profile address").await;
    let (_, shown) = answered(&plane, &wider, credentials()).await;
    assert_eq!(
        shown["status"].as_str(),
        Some("consent"),
        "a wider request was served without asking: {shown}"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_that_asks_for_nothing_is_never_asked_about() {
    let plane = Plane::with_actions(&[]).await;
    let binding = opened(&plane, "openid profile").await;
    let (status, admitted) = answered(&plane, &binding, credentials()).await;
    assert_eq!(status, StatusCode::OK, "{admitted}");
    assert_eq!(admitted["status"].as_str(), Some("admitted"), "{admitted}");
    assert_eq!(agreed_scopes(&plane).await, None);
}
