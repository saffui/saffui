//! OpenID Connect Session Management 1.0: what a relying party is told about
//! the login it just joined, and what it reads to see whether it still holds.

mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use serde_json::Value;
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
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    }
}

/// What came back after the `?`, by name.
fn in_query<'a>(landing: &'a str, named: &str) -> Option<&'a str> {
    landing
        .split_once('?')?
        .1
        .split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{named}=")))
}

/// Sign in and hand back the landing plus the cookies the answer set.
async fn signed_in(plane: &Plane) -> (String, Vec<String>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?client_id={}\
                 &redirect_uri={}&scope=openid&state=s&response_type=code",
                support::REALM,
                support::CONFIDENTIAL,
                urlencode(REDIRECT),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let opened: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let binding = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a login");

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
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let landing = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    (landing, cookies)
}

/// §2: the client is told the state of the session it joined, and §4.2 says
/// what that value is made of, so the same four things reproduce it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_is_told_the_state_of_the_session_it_joined() {
    let plane = Plane::with_actions(&[]).await;
    let (landing, cookies) = signed_in(&plane).await;

    let told = in_query(&landing, "session_state").expect("a session state");
    let (digest, salt) = told.rsplit_once('.').expect("a digest and its salt");
    assert_eq!(digest.len(), 64, "{told}");
    assert!(!salt.is_empty());

    // The cookie the frame reads, on the terms it has to be readable on.
    let held = cookies
        .iter()
        .find(|cookie| cookie.starts_with("saffui_op_state="))
        .expect("the state the browser holds");
    assert!(held.contains("SameSite=None"), "{held}");
    assert!(held.contains("Secure"), "{held}");
    assert!(
        !held.to_ascii_lowercase().contains("httponly"),
        "a cookie script must read was withheld from it: {held}"
    );
    let browser_state = cookie_value(&cookies, "saffui_op_state").expect("a value");

    // §4.2's own computation, from the four things it names.
    let expected = services::session_state::computed(
        &support::provider(),
        support::CONFIDENTIAL,
        "https://app.example",
        &browser_state,
        salt,
    )
    .expect("a state");
    assert_eq!(expected, told, "the state is not what §4.2 computes");

    // Never the session identifier: the value reaches script.
    assert_ne!(
        browser_state,
        cookie_value(&cookies, support::SSO_COOKIE).unwrap_or_default()
    );
}

/// §4.1: the frame a relying party loads is the one page here that may be
/// loaded by somebody else, and discovery says where it is.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_frame_may_be_loaded_and_is_advertised() {
    let plane = Plane::with_actions(&[]).await;
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
    let named = published["check_session_iframe"]
        .as_str()
        .expect("the frame");
    assert_eq!(
        named,
        format!(
            "{}/protocol/openid-connect/check-session",
            support::origin().issuer(support::REALM)
        )
    );
    assert!(published["end_session_endpoint"].is_string(), "{published}");

    for path in ["check-session", "check-session.js"] {
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!(
                    "/realms/{}/protocol/openid-connect/{path}",
                    support::REALM
                ))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let headers = response.headers();
        assert!(
            headers.get("x-frame-options").is_none(),
            "{path} refused the framing that is its whole purpose"
        );
        let policy = headers
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(!policy.contains("frame-ancestors"), "{path}: {policy}");
        // Nothing inline, and no origin but this one.
        assert!(policy.contains("script-src 'self'"), "{path}: {policy}");
    }

    // Every other page still refuses to be framed.
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/login",
                support::REALM
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        response
            .headers()
            .get("x-frame-options")
            .and_then(|value| value.to_str().ok()),
        Some("DENY")
    );
}

/// Logging out takes the value away, which is how the frame learns the login
/// ended without asking anybody.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn logging_out_takes_the_state_away() {
    let plane = Plane::with_actions(&[]).await;
    let (_, cookies) = signed_in(&plane).await;
    let session = cookie_value(&cookies, support::SSO_COOKIE).expect("a session");

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    // Asked first, then told: the confirmation is what ends it.
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/logout",
                support::REALM
            ))
            .insert_header(("cookie", format!("{}={session}", support::SSO_COOKIE)))
            .set_form([("confirmed", "yes")])
            .to_request(),
    )
    .await;
    let cleared: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    assert!(
        cleared
            .iter()
            .any(|cookie| cookie.starts_with("saffui_op_state=;")
                || cookie.starts_with("saffui_op_state=\"\";")),
        "the state the frame reads outlived the login: {cleared:?}"
    );
}

/// RFC 9207: every answer from the authorization endpoint names the server
/// that gave it, so a client talking to two providers cannot be made to take
/// one's answer for the other's.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn every_answer_names_the_server_that_gave_it() {
    let plane = Plane::with_actions(&[]).await;
    let issuer = support::origin().issuer(support::REALM);
    let (landing, _) = signed_in(&plane).await;
    assert_eq!(in_query(&landing, "iss"), Some(urlencode(&issuer).as_str()));

    // A refusal is an answer too.
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?client_id={}\
                 &redirect_uri={}&scope=openid&state=s&response_type=code&prompt=none",
                support::REALM,
                support::CONFIDENTIAL,
                urlencode(REDIRECT),
            ))
            .to_request(),
    )
    .await;
    let refused = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(refused.contains("error=login_required"), "{refused}");
    assert_eq!(in_query(refused, "iss"), Some(urlencode(&issuer).as_str()));

    // And discovery says so, since a client only looks for it when told to.
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
        published["authorization_response_iss_parameter_supported"].as_bool(),
        Some(true),
        "{published}"
    );
}

/// RFC 8414 §3.1: the same metadata under the name an OAuth client builds.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_metadata_answers_to_both_of_its_names() {
    let plane = Plane::with_actions(&[]).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let mut answered = Vec::new();
    for path in [
        format!(
            "/realms/{}/.well-known/openid-configuration",
            support::REALM
        ),
        format!(
            "/.well-known/oauth-authorization-server/realms/{}",
            support::REALM
        ),
    ] {
        let response =
            test::call_service(&app, test::TestRequest::get().uri(&path).to_request()).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        answered.push(test::read_body_json::<Value, _>(response).await);
    }
    assert_eq!(answered[0], answered[1], "two names, two documents");
    assert_eq!(
        answered[0]["issuer"].as_str(),
        Some(support::origin().issuer(support::REALM).as_str())
    );
}
