//! A grant that outlives the login it came from, OIDC Core §11.

mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use data_encoding::BASE64;
use models::sessions::records::UserSessionState;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;
use support::Plane;

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

async fn at_token(plane: &Plane, form: &[(&str, &str)]) -> (StatusCode, serde_json::Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let request = test::TestRequest::post()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/token",
            support::REALM
        ))
        .insert_header(("authorization", format!("Basic {encoded}")))
        .set_form(form)
        .to_request();
    let response = test::call_service(&app, request).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

/// Spend a code minted for `scope`, and hand back what came out.
async fn granted(plane: &Plane, scope: &str) -> serde_json::Value {
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, scope, None)
        .await;
    let (status, granted) = at_token(
        plane,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("client_id", support::CONFIDENTIAL),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{granted}");
    granted
}

/// End the login the fixture's codes are minted against.
async fn log_out(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    let ended = store::providers::sessions::set_state(
        &transaction,
        support::SESSION,
        UserSessionState::LoggedOut,
    )
    .await
    .expect("the login ended");
    assert!(ended);
    transaction.commit().await.expect("the logout kept");
}

async fn renews(plane: &Plane, refresh_token: &str) -> StatusCode {
    at_token(
        plane,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", support::CONFIDENTIAL),
        ],
    )
    .await
    .0
}

/// A logout ends an ordinary grant. Without this a logout is one in name: the
/// refresh token outlives the session it was minted from and keeps renewing.
///
/// Its own test rather than a leg of the next, because one login holds one
/// grant per client: a second exchange for the same client replaces the first.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_logout_ends_an_ordinary_grant() {
    let plane = Plane::with_actions(&[]).await;
    let ordinary = granted(&plane, "openid profile").await;
    let ordinary = ordinary["refresh_token"].as_str().expect("a refresh token");

    log_out(&plane).await;

    assert_eq!(renews(&plane, ordinary).await, StatusCode::BAD_REQUEST);
}

/// And does not end an offline one, which is the whole point of §11.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_logout_does_not_end_an_offline_grant() {
    let plane = Plane::with_actions(&[]).await;
    let offline = granted(&plane, "openid offline_access").await;
    let refresh = offline["refresh_token"].as_str().expect("a refresh token");

    log_out(&plane).await;

    let (status, renewed) = at_token(
        &plane,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", support::CONFIDENTIAL),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{renewed}");
    assert!(
        renewed["access_token"].is_string() && renewed["refresh_token"].is_string(),
        "a renewal handed back no successor: {renewed}"
    );
}

/// An offline grant ends at its own expiry, since there is no login left whose
/// end could bound it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_offline_grant_ends_at_its_own_expiry() {
    let plane = Plane::with_actions(&[]).await;
    let offline = granted(&plane, "openid offline_access").await;
    let refresh = offline["refresh_token"].as_str().expect("a refresh token");

    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(
                &mut connection,
                &TenantContext::new(support::TENANT, support::REALM),
            )
            .await;
        transaction
            .execute(
                "UPDATE client_sessions SET expiration = $1 WHERE offline",
                &[&(chrono::Utc::now().timestamp() - 1)],
            )
            .await
            .expect("an ageing");
        transaction.commit().await.expect("the ageing kept");
    }

    assert_eq!(renews(&plane, refresh).await, StatusCode::BAD_REQUEST);
}

/// §11: without `prompt=consent` the request for offline access is ignored, and
/// the rest of the request is served. The code carries what was granted, so what
/// the token response names is what the browser was allowed.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn offline_access_is_ignored_without_consent() {
    let plane = Plane::with_actions(&[]).await;

    for (prompt, expected) in [
        (None, false),
        (Some("login"), false),
        (Some("consent"), true),
        (Some("login consent"), true),
    ] {
        let mut asked = vec![
            ("client_id", support::CONFIDENTIAL),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT),
            ("scope", "openid offline_access"),
            ("state", "s"),
        ];
        if let Some(prompt) = prompt {
            asked.push(("prompt", prompt));
        }
        let scope = support::granted_scope_of(&plane, &asked).await;
        assert_eq!(
            scope
                .split_whitespace()
                .any(|held| held == "offline_access"),
            expected,
            "prompt={prompt:?} granted {scope:?}"
        );
    }
}

/// A grant nothing attached to the client is not one a prompt can conjure.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_not_attached_to_the_scope_never_holds_it() {
    let plane = Plane::with_actions(&[]).await;
    let scope = support::granted_scope_of(
        &plane,
        &[
            ("client_id", support::OTHER),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT),
            ("scope", "openid offline_access"),
            ("prompt", "consent"),
            ("state", "s"),
        ],
    )
    .await;
    assert!(
        !scope
            .split_whitespace()
            .any(|held| held == "offline_access"),
        "{scope:?}"
    );
}

/// The sweep takes an expired login. It must not take one an offline grant
/// hangs off: the client sessions cascade from it, so the login row going takes
/// the grant with it and a device that was away for a month comes back to
/// nothing.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_sweep_leaves_a_login_an_offline_grant_still_needs() {
    let plane = Plane::with_actions(&[]).await;
    let offline = granted(&plane, "openid offline_access").await;
    let refresh = offline["refresh_token"].as_str().expect("a refresh token");

    // The login ran out a month ago and nothing renewed it, which is what a
    // login does while the device that holds the grant is away.
    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(
                &mut connection,
                &TenantContext::new(support::TENANT, support::REALM),
            )
            .await;
        transaction
            .execute(
                "UPDATE user_sessions SET expiration = $1, state = 'logged-out'",
                &[&(chrono::Utc::now().timestamp() - 60)],
            )
            .await
            .expect("an ageing");
        transaction.commit().await.expect("the ageing kept");
    }

    let swept = server::jobs::sweep_every_realm(&plane.pool(), &plane.tenancy())
        .await
        .expect("the realms were listed");
    assert_eq!(
        swept.sessions, 0,
        "the sweep took the login an offline grant needs"
    );

    let (status, renewed) = at_token(
        &plane,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", support::CONFIDENTIAL),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{renewed}");
}

/// And takes it once the grant has run out too, so nothing is kept forever.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_sweep_takes_the_login_once_the_offline_grant_is_over() {
    let plane = Plane::with_actions(&[]).await;
    granted(&plane, "openid offline_access").await;

    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(
                &mut connection,
                &TenantContext::new(support::TENANT, support::REALM),
            )
            .await;
        let over = chrono::Utc::now().timestamp() - 60;
        transaction
            .execute(
                "UPDATE user_sessions SET expiration = $1, state = 'logged-out'",
                &[&over],
            )
            .await
            .expect("an ageing");
        transaction
            .execute("UPDATE client_sessions SET expiration = $1", &[&over])
            .await
            .expect("an ageing");
        transaction.commit().await.expect("the ageing kept");
    }

    let swept = server::jobs::sweep_every_realm(&plane.pool(), &plane.tenancy())
        .await
        .expect("the realms were listed");
    assert_eq!(swept.sessions, 1, "an ended grant kept its login alive");
}

/// The bound slides. A device that is away for most of a window and checks in
/// once has a grant that lives, and the same device that never checks in does
/// not: what has to stay inside the window is the gap between two renewals.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn checking_in_moves_an_offline_grant_further_out() {
    let plane = Plane::with_actions(&[]).await;
    let offline = granted(&plane, "openid offline_access").await;
    let refresh = offline["refresh_token"].as_str().expect("a refresh token");

    let before = offline_ends_at(&plane).await;
    // Wound back to a moment before the end, which is a device coming home from
    // a long time away with the window not quite spent.
    set_offline_end(&plane, chrono::Utc::now().timestamp() + 60).await;

    let (status, renewed) = at_token(
        &plane,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", support::CONFIDENTIAL),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{renewed}");

    let after = offline_ends_at(&plane).await;
    assert!(
        after > before - 5,
        "checking in did not move the end out: {before} then {after}"
    );
}

async fn offline_ends_at(plane: &Plane) -> i64 {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    transaction
        .query_one("SELECT expiration FROM client_sessions WHERE offline", &[])
        .await
        .expect("an offline grant")
        .get(0)
}

async fn set_offline_end(plane: &Plane, at: i64) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    transaction
        .execute(
            "UPDATE client_sessions SET expiration = $1 WHERE offline",
            &[&at],
        )
        .await
        .expect("an ageing");
    transaction.commit().await.expect("the ageing kept");
}
