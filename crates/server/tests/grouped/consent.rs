#[allow(unused_imports)]
use super::support;
use super::support::{Plane, cookie_value, urlencode};
use actix_web::http::StatusCode;
use actix_web::{App, test};
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;

const REDIRECT: &str = "https://app.example/callback";

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
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
        ceiling: support::ceiling(),
        egress: config::serving::Egress::Outward,
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, support::REALM)
}

async fn demand_consent(plane: &Plane, demanded: bool) {
    let transaction = plane.scoped(&within()).await;
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
    let transaction = plane.scoped(&within()).await;
    store::providers::directory::consents::held(
        &transaction,
        support::SUBJECT,
        support::CONFIDENTIAL,
    )
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

/// The consent screen names the client's registered policy and terms pages,
/// and only over https: a plain-http link on a consent screen is an
/// invitation this server does not extend, so it is kept quiet rather than
/// shown.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_screen_offers_the_registered_pages_and_only_over_https() {
    let plane = Plane::with_actions(&[]).await;
    {
        let transaction = plane.scoped(&within()).await;
        let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
            .await
            .expect("the clients table")
            .expect("a planted client");
        client.consent_required = Some(true);
        client.policy_uri = Some("https://app.example/privacy".into());
        client.tos_uri = Some("http://app.example/terms".into());
        store::providers::clients::update(&transaction, &client)
            .await
            .expect("the clients table");
        transaction.commit().await.expect("the setting kept");
    }

    let binding = opened(&plane, "openid profile").await;
    let (status, shown) = answered(&plane, &binding, credentials()).await;
    assert_eq!(status, StatusCode::OK, "{shown}");
    assert_eq!(shown["status"].as_str(), Some("consent"), "{shown}");
    assert_eq!(
        shown["policy_uri"].as_str(),
        Some("https://app.example/privacy"),
        "{shown}"
    );
    assert!(
        shown["tos_uri"].is_null(),
        "a plain-http page rode onto the consent screen: {shown}"
    );
}

/// Ask for a code, the browser holding the planted login or nothing, and read back
/// the status, where the browser is sent, and the login opened instead, if any.
async fn authorized(
    plane: &Plane,
    scope: &str,
    prompt: Option<&str>,
    holding: bool,
) -> (StatusCode, String, Option<String>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let prompted = prompt
        .map(|asked| format!("&prompt={asked}"))
        .unwrap_or_default();
    let mut asking = test::TestRequest::get().uri(&format!(
        "/realms/{}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
         &response_type=code&scope={}&state=s{prompted}",
        support::REALM,
        support::CONFIDENTIAL,
        urlencode(REDIRECT),
        urlencode(scope),
    ));
    if holding {
        asking = asking.insert_header((
            "cookie",
            format!("{}={}", support::SSO_COOKIE, support::SESSION),
        ));
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    (
        status,
        location,
        cookie_value(&cookies, support::AUTH_SESSION_COOKIE),
    )
}

/// A browser holding a login gets no code for a client whose consent it never had:
/// the person signs in again and is shown the screen, and once they agreed, the
/// held login is served without one.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_held_login_owing_consent_goes_through_the_login_before_any_code() {
    let plane = Plane::with_actions(&[]).await;
    demand_consent(&plane, true).await;

    let (status, location, binding) = authorized(&plane, "openid profile", None, true).await;
    assert!(
        !location.contains("code="),
        "a code was minted without consent: {location}"
    );
    let binding = binding.unwrap_or_else(|| panic!("no login was opened: {status} {location}"));
    let (_, shown) = answered(&plane, &binding, credentials()).await;
    assert_eq!(shown["status"].as_str(), Some("consent"), "{shown}");
    let (_, admitted) = answered(&plane, &binding, with_consent("granted")).await;
    assert_eq!(admitted["status"].as_str(), Some("admitted"), "{admitted}");

    let (_, location, binding) = authorized(&plane, "openid profile", None, true).await;
    assert!(
        location.contains("code="),
        "a client agreed to was not served by the held login: {location}"
    );
    assert!(
        binding.is_none(),
        "a login was opened for what was already agreed to"
    );
}

/// A consent withdrawn is asked for again, even while the browser holds a login.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_withdrawn_consent_is_asked_again_even_with_a_held_login() {
    let plane = Plane::with_actions(&[]).await;
    demand_consent(&plane, true).await;
    {
        let transaction = plane.scoped(&within()).await;
        auth::consent::keep(
            &transaction,
            support::SUBJECT,
            support::CONFIDENTIAL,
            "openid profile",
            chrono::Utc::now(),
        )
        .await
        .unwrap_or_else(|_| panic!("the consent was not kept"));
        transaction.commit().await.expect("the consent kept");
    }
    let (_, location, _) = authorized(&plane, "openid profile", None, true).await;
    assert!(location.contains("code="), "{location}");

    {
        let transaction = plane.scoped(&within()).await;
        store::providers::directory::consents::withdraw(
            &transaction,
            support::SUBJECT,
            support::CONFIDENTIAL,
        )
        .await
        .expect("the consents table");
        transaction.commit().await.expect("the withdrawal kept");
    }
    let (status, location, binding) = authorized(&plane, "openid profile", None, true).await;
    assert!(
        !location.contains("code="),
        "a withdrawn consent was served by the held login: {location}"
    );
    assert!(
        binding.is_some(),
        "no login was opened: {status} {location}"
    );
}

/// A client that asked for no interaction is told the consent it lacks rather than
/// shown a screen, and gets no code.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_held_login_asked_not_to_interact_is_told_consent_is_required() {
    let plane = Plane::with_actions(&[]).await;
    demand_consent(&plane, true).await;

    let (_, location, binding) = authorized(&plane, "openid profile", Some("none"), true).await;
    assert!(location.contains("error=consent_required"), "{location}");
    assert!(!location.contains("code="), "{location}");
    assert!(
        binding.is_none(),
        "a login was opened for a client that asked for none"
    );
}

/// `prompt=consent` shows the screen even for a client that does not ask for
/// consent, whether the browser holds a login or not.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_prompt_for_consent_is_honoured_with_or_without_a_held_login() {
    let plane = Plane::with_actions(&[]).await;

    for holding in [true, false] {
        let (status, location, binding) =
            authorized(&plane, "openid", Some("consent"), holding).await;
        assert!(
            !location.contains("code="),
            "holding {holding}: a code was minted without asking: {location}"
        );
        let binding =
            binding.unwrap_or_else(|| panic!("holding {holding}: no login: {status} {location}"));
        let (_, shown) = answered(&plane, &binding, credentials()).await;
        assert_eq!(
            shown["status"].as_str(),
            Some("consent"),
            "holding {holding}: {shown}"
        );
    }
}
