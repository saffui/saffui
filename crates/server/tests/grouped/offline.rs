
#[allow(unused_imports)]
use super::support;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use data_encoding::BASE64;
use models::sessions::records::UserSessionState;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;
use super::support::Plane;

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

/// A grant that ran out does not renew, whatever its login is doing. Reading
/// only the login's end kept renewing one that was over.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_grant_that_ran_out_does_not_renew_under_a_login_that_has_not() {
    let plane = Plane::with_actions(&[]).await;
    let ordinary = granted(&plane, "openid profile").await;
    let refresh = ordinary["refresh_token"].as_str().expect("a refresh token");

    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(
                &mut connection,
                &TenantContext::new(support::TENANT, support::REALM),
            )
            .await;
        // The login is untouched and still open. Only the grant is over.
        transaction
            .execute(
                "UPDATE client_sessions SET expiration = $1",
                &[&(chrono::Utc::now().timestamp() - 1)],
            )
            .await
            .expect("an ageing");
        let open: i64 = transaction
            .query_one(
                "SELECT count(*) FROM user_sessions WHERE state = 'logged-in'",
                &[],
            )
            .await
            .expect("a count")
            .get(0);
        assert_eq!(open, 1, "the login under test was not left open");
        transaction.commit().await.expect("the ageing kept");
    }

    assert_eq!(renews(&plane, refresh).await, StatusCode::BAD_REQUEST);
}

/// And an ordinary grant that keeps renewing keeps its end moving, or checking
/// that end would have ended every one of them at the first window.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn renewing_moves_an_ordinary_grant_further_out() {
    let plane = Plane::with_actions(&[]).await;
    let ordinary = granted(&plane, "openid profile").await;
    let refresh = ordinary["refresh_token"].as_str().expect("a refresh token");

    let before = ends_at(&plane).await;
    set_end(&plane, chrono::Utc::now().timestamp() + 60).await;
    assert_eq!(renews(&plane, refresh).await, StatusCode::OK);

    assert!(
        ends_at(&plane).await > before - 5,
        "renewing did not move the end out"
    );
}

async fn ends_at(plane: &Plane) -> i64 {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    transaction
        .query_one("SELECT expiration FROM client_sessions", &[])
        .await
        .expect("a grant")
        .get(0)
}

async fn set_end(plane: &Plane, at: i64) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    transaction
        .execute("UPDATE client_sessions SET expiration = $1", &[&at])
        .await
        .expect("an ageing");
    transaction.commit().await.expect("the ageing kept");
}

/// The plane can take back an offline grant. It outlives the login, so ending
/// the login is not what ends it, and until something reached the grant itself
/// nothing could.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_plane_revokes_an_offline_grant() {
    let plane = Plane::with_actions(&[
        models::entities::authz::AdminAction::UserRead,
        models::entities::authz::AdminAction::UserWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let offline = granted(&plane, "openid offline_access").await;
    let refresh = offline["refresh_token"].as_str().expect("a refresh token");

    let shown = admin(&plane, &bearer, Method::GET, "sessions").await;
    let held = &shown[0]["grants"][0];
    assert_eq!(held["client_id"], support::CONFIDENTIAL);
    assert_eq!(held["offline"], true, "the listing did not name the grant");

    assert_eq!(renews(&plane, refresh).await, StatusCode::OK);
    let taken = admin_status(
        &plane,
        &bearer,
        Method::DELETE,
        &format!(
            "sessions/{}/grants/{}",
            support::SESSION,
            support::CONFIDENTIAL
        ),
    )
    .await;
    assert_eq!(taken, StatusCode::NO_CONTENT);
    assert_eq!(
        renews(&plane, refresh).await,
        StatusCode::BAD_REQUEST,
        "a revoked grant kept renewing"
    );

    // A second one, and one for a client that holds nothing here, both miss
    // rather than reporting they took something.
    for client in [support::CONFIDENTIAL, support::OTHER] {
        assert_eq!(
            admin_status(
                &plane,
                &bearer,
                Method::DELETE,
                &format!("sessions/{}/grants/{client}", support::SESSION),
            )
            .await,
            StatusCode::NOT_FOUND,
            "{client}"
        );
    }
}

/// And can end a login outright, which takes every grant under it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_plane_ends_a_login() {
    let plane = Plane::with_actions(&[models::entities::authz::AdminAction::UserWrite]).await;
    let bearer = plane.token(&support::claims());
    let ordinary = granted(&plane, "openid profile").await;
    let refresh = ordinary["refresh_token"].as_str().expect("a refresh token");

    // A login nobody opened misses rather than reporting it ended something.
    assert_eq!(
        admin_status(&plane, &bearer, Method::DELETE, "sessions/never-opened").await,
        StatusCode::NOT_FOUND
    );

    // Ended last: the admin's own token names this very login, so what ends it
    // ends the caller's reach as well.
    assert_eq!(
        admin_status(
            &plane,
            &bearer,
            Method::DELETE,
            &format!("sessions/{}", support::SESSION)
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(renews(&plane, refresh).await, StatusCode::BAD_REQUEST);
}

/// A session identifier from somewhere else does not reach this user's.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_session_is_reached_only_through_the_user_it_belongs_to() {
    let plane = Plane::with_actions(&[models::entities::authz::AdminAction::UserWrite]).await;
    let bearer = plane.token(&support::claims());
    granted(&plane, "openid profile").await;

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let request = test::TestRequest::default()
        .method(Method::DELETE)
        .uri(&format!(
            "/admin/realms/{}/users/nobody/sessions/{}",
            support::REALM,
            support::SESSION
        ))
        .insert_header(("authorization", format!("Bearer {bearer}")))
        .to_request();
    assert_eq!(
        test::call_service(&app, request).await.status(),
        StatusCode::NOT_FOUND,
        "a session was ended through a user it does not belong to"
    );
}

async fn admin(plane: &Plane, bearer: &str, method: Method, path: &str) -> serde_json::Value {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let request = test::TestRequest::default()
        .method(method)
        .uri(&format!(
            "/admin/realms/{}/users/{}/{path}",
            support::REALM,
            support::SUBJECT
        ))
        .insert_header(("authorization", format!("Bearer {bearer}")))
        .to_request();
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    test::read_body_json(response).await
}

async fn admin_status(plane: &Plane, bearer: &str, method: Method, path: &str) -> StatusCode {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let request = test::TestRequest::default()
        .method(method)
        .uri(&format!(
            "/admin/realms/{}/users/{}/{path}",
            support::REALM,
            support::SUBJECT
        ))
        .insert_header(("authorization", format!("Bearer {bearer}")))
        .to_request();
    test::call_service(&app, request).await.status()
}

async fn bound_offline(plane: &Plane, max_lifespan: i32, max_grants: i32) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    let mut realm = store::providers::realms::load(&transaction, support::REALM)
        .await
        .expect("the realms table")
        .expect("a planted realm");
    realm.offline_session_max_lifespan = max_lifespan;
    realm.max_offline_grants = max_grants;
    store::providers::realms::update(&transaction, &realm)
        .await
        .expect("the realms table");
    transaction.commit().await.expect("the bounds kept");
}

async fn age_offline_start(plane: &Plane, by: i64) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    transaction
        .execute(
            "UPDATE client_sessions SET started_at = started_at - $1 WHERE offline",
            &[&by],
        )
        .await
        .expect("an ageing");
    transaction.commit().await.expect("the ageing kept");
}

async fn offline_grant_ids(plane: &Plane) -> Vec<String> {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    store::providers::sessions::offline_grants_of(
        &transaction,
        support::SUBJECT,
        chrono::Utc::now().timestamp(),
    )
    .await
    .expect("the client sessions table")
    .into_iter()
    .map(|grant| grant.session_id)
    .collect()
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_ceiling_ends_a_grant_that_keeps_checking_in() {
    let plane = Plane::with_actions(&[]).await;
    bound_offline(&plane, 3_600, 0).await;
    let offline = granted(&plane, "openid offline_access").await;
    let refresh = offline["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned();

    assert_eq!(renews(&plane, &refresh).await, StatusCode::OK);
    let now = chrono::Utc::now().timestamp();
    let ends = offline_ends_at(&plane).await;
    assert!(
        ends <= now + 3_600 + 5,
        "the sliding window outran the ceiling: {ends} against {now}"
    );

    age_offline_start(&plane, 3_601).await;
    assert_eq!(
        renews(&plane, &refresh).await,
        StatusCode::BAD_REQUEST,
        "a grant past its ceiling renewed"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_token_states_the_end_the_ceiling_imposes() {
    let plane = Plane::with_actions(&[]).await;
    bound_offline(&plane, 3_600, 0).await;
    let offline = granted(&plane, "openid offline_access").await;
    let refresh = offline["refresh_token"].as_str().expect("a refresh token");

    age_offline_start(&plane, 3_000).await;
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

    let successor = renewed["refresh_token"].as_str().expect("a successor");
    let stated = plane.claims_of(successor).await["exp"]
        .as_i64()
        .expect("an expiry");
    let ends = offline_ends_at(&plane).await;
    assert_eq!(
        stated, ends,
        "the token stated an end the grant does not have"
    );
    let now = chrono::Utc::now().timestamp();
    assert!(stated <= now + 601, "the ceiling was not applied: {stated}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_cap_ends_the_oldest_grant() {
    let plane = Plane::with_actions(&[]).await;
    bound_offline(&plane, 0, 1).await;
    plant_older_grant(&plane, "an-older-grant", support::OTHER).await;
    assert_eq!(offline_grant_ids(&plane).await.len(), 1);

    granted(&plane, "openid offline_access").await;

    let left = offline_grant_ids(&plane).await;
    assert_eq!(left.len(), 1, "the cap did not hold: {left:?}");
    assert_ne!(
        left[0], "an-older-grant",
        "the cap ended the new grant rather than the old one"
    );
}

async fn plant_older_grant(plane: &Plane, session_id: &str, client_id: &str) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    let now = chrono::Utc::now().timestamp();
    store::providers::sessions::open_client_session(
        &transaction,
        &models::sessions::records::ClientSessionModel {
            tenant: support::TENANT.to_owned(),
            realm_id: support::REALM.to_owned(),
            session_id: session_id.to_owned(),
            user_session_id: support::SESSION.to_owned(),
            user_id: support::SUBJECT.to_owned(),
            client_id: client_id.to_owned(),
            auth_method: Some("authorization_code".to_owned()),
            redirect_uri: None,
            started_at: now - 86_400,
            expiration: Some(now + 86_400),
            notes: None,
            current_refresh_token: None,
            current_refresh_token_use_count: Some(0),
            offline: Some(true),
            requested_claims: None,
        },
    )
    .await
    .expect("a planted grant");
    transaction.commit().await.expect("the grant kept");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_grant_that_is_over_is_not_counted_by_the_cap() {
    let plane = Plane::with_actions(&[]).await;
    granted(&plane, "openid offline_access").await;
    assert_eq!(offline_grant_ids(&plane).await.len(), 1);

    set_offline_end(&plane, chrono::Utc::now().timestamp() - 1).await;
    assert!(
        offline_grant_ids(&plane).await.is_empty(),
        "a grant whose own end has passed was still counted"
    );
}
