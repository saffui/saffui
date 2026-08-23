//! Answering an authorization request as a form the browser sends on.

mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use server::api::config::{Plane as Mounted, register};
use support::{Plane, cookie_value, urlencode};

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
    }
}

/// Open a login, and hand back the cookie and what the response was.
async fn opened(plane: &Plane, mode: Option<&str>) -> (StatusCode, String, Vec<String>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut query = format!(
        "client_id={}&response_type=code&redirect_uri={}&scope=openid&state=a+b",
        support::CONFIDENTIAL,
        urlencode(REDIRECT),
    );
    if let Some(mode) = mode {
        query.push_str(&format!("&response_mode={}", urlencode(mode)));
    }
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?{query}",
                support::REALM
            ))
            .to_request(),
    )
    .await;
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let cookies = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    (status, location, cookies)
}

/// Answer the login as a browser posting the form does, and hand back the whole
/// response.
async fn answered(plane: &Plane, binding: &str) -> (StatusCode, String, String) {
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
            .set_form([
                ("username", support::SUBJECT),
                ("password", support::PASSWORD),
            ])
            .to_request(),
    )
    .await;
    let status = response.status();
    let policy = response
        .headers()
        .get("content-security-policy")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = String::from_utf8(test::read_body(response).await.to_vec()).expect("a body");
    (status, policy, body)
}

/// The whole way through: nothing of the answer is ever in a URL.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_form_post_answer_never_touches_a_url() {
    let plane = Plane::with_actions(&[]).await;
    let (status, _, cookies) = opened(&plane, Some("form_post")).await;
    assert_eq!(status, StatusCode::FOUND, "a login did not open");
    let binding = cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login");

    let (status, policy, body) = answered(&plane, &binding).await;
    assert_eq!(status, StatusCode::OK, "an answer redirected: {body}");
    assert!(
        body.contains(&format!(r#"<form method="post" action="{REDIRECT}""#)),
        "{body}"
    );
    assert!(
        body.contains(r#"name="code""#) && body.contains(r#"name="state" value="a b""#),
        "the answer did not carry what the client asked for: {body}"
    );
    assert!(
        policy.contains(&format!("form-action {REDIRECT}")),
        "the page could post somewhere else: {policy}"
    );
    assert!(
        policy.contains("script-src 'self'"),
        "the page allowed a script from anywhere: {policy}"
    );
}

/// The same request without the mode is answered where it always was.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_request_naming_no_mode_is_answered_at_the_redirect() {
    let plane = Plane::with_actions(&[]).await;
    let (_, _, cookies) = opened(&plane, None).await;
    let binding = cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login");

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
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
            .set_form([
                ("username", support::SUBJECT),
                ("password", support::PASSWORD),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        location.starts_with(REDIRECT) && location.contains("code="),
        "{location}"
    );
}

/// A mode this build cannot answer in is refused rather than answered as a
/// query: a response put where the client is not reading is one it never sees.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_mode_this_build_does_not_know_is_refused() {
    let plane = Plane::with_actions(&[]).await;
    let (status, location, _) = opened(&plane, Some("fragment")).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location.contains("error=unsupported_response_mode"),
        "{location}"
    );
}

/// A refusal travels the way the request asked, or a client that only reads
/// posts never learns it was refused.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_refusal_travels_the_way_the_request_asked() {
    let plane = Plane::with_actions(&[]).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth\
                 ?client_id={}&response_type=token&redirect_uri={}&scope=openid\
                 &state=s&response_mode=form_post",
                support::REALM,
                support::CONFIDENTIAL,
                urlencode(REDIRECT),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "a refusal redirected");
    let body = String::from_utf8(test::read_body(response).await.to_vec()).expect("a body");
    assert!(
        body.contains(r#"name="error" value="unsupported_response_type""#),
        "{body}"
    );
    assert!(body.contains(r#"name="state" value="s""#), "{body}");
}

/// The script the page runs is served by this server, so the page never needs
/// to allow an inline one.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_page_runs_a_script_this_server_serves() {
    let plane = Plane::with_actions(&[]).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/form-post.js",
                support::REALM
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(test::read_body(response).await.to_vec()).expect("a body");
    assert!(body.contains("submit()"), "{body}");
}
