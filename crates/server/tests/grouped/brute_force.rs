
#[allow(unused_imports)]
use super::support;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;
use super::support::Plane;

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

/// Start a login and hand back the cookie that names it.
async fn opened(plane: &Plane) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope=openid&state=s",
                support::REALM,
                support::CONFIDENTIAL,
                support::urlencode("https://app.example/callback"),
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
    support::cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login")
}

/// Answer with this password, and hand back the status and body.
async fn answered(plane: &Plane, password: &str) -> (StatusCode, Value) {
    let binding = opened(plane).await;
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
            // Answered as json, because that is how the outcome comes back as
            // something to assert on rather than as a place to go.
            .set_json(serde_json::json!({
                "username": support::SUBJECT,
                "password": password,
            }))
            .to_request(),
    )
    .await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

/// A realm that counts nothing lets a wrong password be wrong forever, which
/// is what every realm did before this.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_that_does_not_count_never_locks() {
    let plane = Plane::with_actions(&[]).await;
    for _ in 0..6 {
        let (status, body) = answered(&plane, "not-the-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["status"].as_str(), Some("refused"), "{body}");
    }
    // And the right password still works, because nothing stands in the way.
    let (status, body) = answered(&plane, support::PASSWORD).await;
    assert_ne!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
}

/// Past the threshold the answer is no longer looked at, and the page says so
/// rather than saying the password is wrong.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn too_many_failures_stop_the_answer_being_read() {
    let plane = Plane::with_actions(&[]).await;
    plane.count_logins(3).await;

    for attempt in 1..=2 {
        let (status, body) = answered(&plane, "not-the-password").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt}: {body}"
        );
    }
    // The third reaches the threshold, so it is the last one refused.
    let (status, _) = answered(&plane, "not-the-password").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = answered(&plane, "not-the-password").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["status"].as_str(), Some("locked-out"), "{body}");
    assert!(
        body["until"].as_i64().is_some_and(|until| until > 0),
        "{body}"
    );

    // And the right password is refused too: what is locked is the account,
    // not the wrong answer.
    let (status, body) = answered(&plane, support::PASSWORD).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
}

/// A login that succeeds says the person is the person, so what was counted
/// against them was noise.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn getting_in_forgets_what_was_counted() {
    let plane = Plane::with_actions(&[]).await;
    plane.count_logins(5).await;

    for _ in 0..3 {
        answered(&plane, "not-the-password").await;
    }
    assert_eq!(counted(&plane).await, 3);

    let (status, body) = answered(&plane, support::PASSWORD).await;
    assert_ne!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(
        counted(&plane).await,
        0,
        "a successful login kept the count"
    );
}

/// An administrator is the way out of a lock somebody else can cause.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_administrator_lifts_the_lock() {
    let plane = Plane::with_actions(&[
        models::entities::authz::AdminAction::UserRead,
        models::entities::authz::AdminAction::UserWrite,
    ])
    .await;
    plane.count_logins(2).await;
    for _ in 0..3 {
        answered(&plane, "not-the-password").await;
    }
    let (status, _) = answered(&plane, "not-the-password").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let at = format!(
        "/admin/realms/{}/users/{}/lockout",
        support::REALM,
        support::SUBJECT
    );
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&at)
            .insert_header((
                "authorization",
                format!("Bearer {}", plane.token(&support::claims())),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let held: Value = test::read_body_json(response).await;
    assert_eq!(held["locked"].as_bool(), Some(true), "{held}");

    let response = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri(&at)
            .insert_header((
                "authorization",
                format!("Bearer {}", plane.token(&support::claims())),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let (status, body) = answered(&plane, support::PASSWORD).await;
    assert_ne!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
}

/// What the row holds against this person right now.
async fn counted(plane: &Plane) -> i64 {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    store::providers::login::failures(&transaction, support::SUBJECT)
        .await
        .expect("the failures table")
        .map_or(0, |record| record.num_failures)
}
