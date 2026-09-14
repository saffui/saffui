#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use crypto::jose::jwt::JwtPayload;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};
use services::account_api::{ACCOUNT_CONSOLE, compose_account_console_redirect};
use std::time::SystemTime;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;
const INVALID_TOKEN: &str = r#"Bearer error="invalid_token""#;

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
        ceiling: support::ceiling(),
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, REALM)
}

fn me() -> String {
    format!("/realms/{REALM}/account-api/v1/me")
}

fn recent_sign_in() -> String {
    format!("/realms/{REALM}/account-api/v1/me/recent-sign-in")
}

/// A token the account console obtained for the planted login.
fn account_claims() -> JwtPayload {
    let mut payload = support::claims();
    payload.set_audience(vec![ACCOUNT_CONSOLE]);
    payload
        .set_claim("azp", Some(json!(ACCOUNT_CONSOLE)))
        .expect("an authorized party claim");
    payload
        .set_claim("scope", Some(json!("openid account")))
        .expect("a scope claim");
    payload.set_issued_at(&SystemTime::now());
    payload
}

fn with_claim(mut payload: JwtPayload, name: &str, value: Option<Value>) -> JwtPayload {
    payload.set_claim(name, value).expect("a claim");
    payload
}

/// The realm's account console, provisioned the way a realm's birth provisions it.
async fn provision_account_console(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    services::provisioning::provision_account_console(
        &transaction,
        support::TENANT,
        REALM,
        &services::provisioning::AccountConsole {
            redirect_uris: vec![compose_account_console_redirect(
                &support::origin().issuer(REALM),
            )],
        },
    )
    .await
    .expect("the account console");
    transaction
        .commit()
        .await
        .expect("the account console kept");
}

async fn prove_sign_in_reaching(plane: &Plane, at: i64, level: i32) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    store::providers::sessions::record_authentication(
        &transaction,
        support::SESSION,
        at,
        Some(level),
    )
    .await
    .expect("the sessions table");
    transaction.commit().await.expect("the sign-in kept");
}

/// Ask the account API, and read back the status, the challenge and the body.
async fn asked(plane: &Plane, path: &str, bearer: Option<&str>) -> (StatusCode, String, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asking = test::TestRequest::get().uri(path);
    if let Some(bearer) = bearer {
        asking = asking.insert_header(("authorization", format!("Bearer {bearer}")));
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|held| held.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = test::read_body(response).await;
    (
        status,
        challenge,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}

/// Only a token the account console obtained for an open login reaches the account
/// API. Refused with the bearer challenge: no token, the admin console's, one
/// another client obtained, one minted for another audience, a refresh token, one
/// naming no login, one bound to a key the caller did not prove, and the console's
/// own token presented under another realm's path. The console's token without the
/// account scope is told which scope it lacks.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_a_token_the_account_console_obtained_reaches_the_account_api() {
    let plane = Plane::with_actions(&[]).await;
    let another_audience = {
        let mut payload = account_claims();
        payload.set_audience(vec![support::CONFIDENTIAL]);
        payload
    };
    let refused = [
        None,
        Some(plane.token(&support::claims())),
        Some(plane.token(&with_claim(
            account_claims(),
            "azp",
            Some(json!(support::CONFIDENTIAL)),
        ))),
        Some(plane.token(&another_audience)),
        Some(plane.token(&with_claim(account_claims(), "typ", Some(json!("Refresh"))))),
        Some(plane.token(&with_claim(account_claims(), "sid", None))),
        Some(plane.token(&with_claim(
            account_claims(),
            "cnf",
            Some(json!({ "jkt": "a-key-nobody-proved" })),
        ))),
    ];
    for bearer in &refused {
        let (status, challenge, told) = asked(&plane, &me(), bearer.as_deref()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
        assert_eq!(challenge, INVALID_TOKEN, "{told}");
        assert_eq!(told["error_code"], "unauthorized", "{told}");
    }

    let bearer = plane.token(&account_claims());
    let (status, challenge, told) =
        asked(&plane, "/realms/elsewhere/account-api/v1/me", Some(&bearer)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(challenge, INVALID_TOKEN, "{told}");

    let unscoped = plane.token(&with_claim(
        account_claims(),
        "scope",
        Some(json!("openid")),
    ));
    let (status, challenge, told) = asked(&plane, &me(), Some(&unscoped)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{told}");
    assert_eq!(
        challenge,
        r#"Bearer error="insufficient_scope", scope="account""#
    );
    assert_eq!(told["error_code"], "access_denied", "{told}");

    let (status, _, told) = asked(&plane, &me(), Some(&bearer)).await;
    assert_eq!(status, StatusCode::OK, "{told}");
}

/// A login that ended no longer reaches the account API, even with a token
/// carrying `offline_access`, which elsewhere outlives its login.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_login_that_ended_no_longer_reaches_the_account_api() {
    let plane = Plane::with_actions(&[]).await;
    let bearer = plane.token(&account_claims());
    let offline = plane.token(&with_claim(
        account_claims(),
        "scope",
        Some(json!("openid account offline_access")),
    ));
    for held in [&bearer, &offline] {
        let (status, _, told) = asked(&plane, &me(), Some(held)).await;
        assert_eq!(status, StatusCode::OK, "{told}");
    }

    plane.end_login().await;
    for held in [&bearer, &offline] {
        let (status, challenge, told) = asked(&plane, &me(), Some(held)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
        assert_eq!(challenge, INVALID_TOKEN, "{told}");
    }
}

/// The account API answers for the person the token's login belongs to, never for
/// its subject, which may be pairwise: with what the realm holds of them, uncached,
/// and without the subject.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_account_api_answers_for_the_person_the_login_belongs_to() {
    let plane = Plane::with_actions(&[]).await;
    let mut pairwise = account_claims();
    pairwise.set_subject("f7c3e2a9-pairwise");
    let bearer = plane.token(&pairwise);
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&me())
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|held| held.to_str().ok()),
        Some("no-store")
    );
    let told: Value = test::read_body_json(response).await;
    assert_eq!(
        (
            told["preferred_username"].as_str(),
            told["given_name"].as_str(),
            told["family_name"].as_str(),
        ),
        (
            Some(support::SUBJECT),
            Some(support::GIVEN_NAME),
            Some(support::FAMILY_NAME),
        ),
        "{told}"
    );
    assert!(told.get("sub").is_none(), "{told}");
}

/// A sensitive change waits for a sign-in both recent and as strong as the flow the
/// account console signs in with lets the person reach, and the account API says so
/// in RFC 9470's terms: the level by the realm's name for it, and five minutes of age.
/// No recorded sign-in, a password proven more than five minutes ago, and a recent
/// password once the flow asks for a code the person holds are each asked to step
/// up; a recent password on the plain flow and a recent code on the strong one pass.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_sign_in_too_old_or_too_weak_is_asked_to_step_up() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    let now = chrono::Utc::now().timestamp();
    let step_up = |acr: &str| {
        format!(
            r#"Bearer error="insufficient_user_authentication", error_description="sign in again, recently and as strongly as this account allows", acr_values="{acr}", max_age="300""#
        )
    };

    let (status, challenge, told) = asked(&plane, &recent_sign_in(), Some(&bearer)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(challenge, step_up(support::PASSWORD_ACR));
    assert_eq!(told["error_code"], "account.step_up_required", "{told}");

    prove_sign_in_reaching(&plane, now, 1).await;
    let (status, _, told) = asked(&plane, &recent_sign_in(), Some(&bearer)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    prove_sign_in_reaching(&plane, now - 301, 1).await;
    let (status, challenge, _) = asked(&plane, &recent_sign_in(), Some(&bearer)).await;
    assert_eq!(
        (status, challenge),
        (StatusCode::UNAUTHORIZED, step_up(support::PASSWORD_ACR))
    );

    plane
        .bind_browser_flow(ACCOUNT_CONSOLE, support::STRONG_FLOW)
        .await;
    plane
        .enrol_totp("app-for-the-account", support::TOTP_SECRET)
        .await;
    prove_sign_in_reaching(&plane, now, 1).await;
    let (status, challenge, _) = asked(&plane, &recent_sign_in(), Some(&bearer)).await;
    assert_eq!(
        (status, challenge),
        (StatusCode::UNAUTHORIZED, step_up(support::STRONG_ACR))
    );

    prove_sign_in_reaching(&plane, now, 2).await;
    let (status, _, told) = asked(&plane, &recent_sign_in(), Some(&bearer)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
}
