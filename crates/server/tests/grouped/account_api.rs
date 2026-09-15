#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use crypto::jose::jwt::JwtPayload;
use models::sessions::records::{UserSessionModel, UserSessionState};
use secrecy::SecretBox;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};
use services::account_api::{ACCOUNT_CONSOLE, compose_account_console_redirect};
use std::time::SystemTime;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;
const INVALID_TOKEN: &str = r#"Bearer error="invalid_token""#;
const ELSEWHERE: &str = "session-elsewhere";
const REPLACEMENT: &str = "a-fresh-password-of-decent-length";

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

/// Send the account API a request, and read back the status, the challenge and the
/// body.
async fn sent(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, String, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asking = test::TestRequest::default().method(method).uri(path);
    if let Some(bearer) = bearer {
        asking = asking.insert_header(("authorization", format!("Bearer {bearer}")));
    }
    if let Some(body) = body {
        asking = asking.set_json(body);
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

/// Ask the account API, and read back the status, the challenge and the body.
async fn asked(plane: &Plane, path: &str, bearer: Option<&str>) -> (StatusCode, String, Value) {
    sent(plane, Method::GET, path, bearer, None).await
}

fn own(leaf: &str) -> String {
    format!("/realms/{REALM}/account-api/v1/me/{leaf}")
}

/// A login of the same person on another device.
async fn open_login_elsewhere(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    store::providers::sessions::open(
        &transaction,
        &UserSessionModel {
            browser_state: None,
            tenant: support::TENANT.into(),
            session_id: ELSEWHERE.into(),
            realm_id: support::REALM.into(),
            user_id: support::SUBJECT.into(),
            login_username: support::SUBJECT.into(),
            broker_session_id: None,
            broker_user_id: None,
            auth_method: None,
            ip_address: None,
            user_agent: None,
            started_at: chrono::Utc::now().timestamp(),
            auth_time: None,
            loa: None,
            expiration: None,
            state: UserSessionState::LoggedIn,
            remember_me: None,
            last_session_refresh: None,
            is_offline: None,
            notes: None,
        },
    )
    .await
    .expect("a login elsewhere");
    transaction.commit().await.expect("the login kept");
}

async fn login_stands(plane: &Plane, session_id: &str) -> bool {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    store::providers::sessions::load(&transaction, session_id)
        .await
        .expect("the sessions table")
        .is_some()
}

async fn held_password_is(plane: &Plane, offered: &str) -> bool {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    auth::password::compare_with_held(
        &transaction,
        &support::provider(),
        support::SUBJECT,
        &SecretBox::new(Box::new(offered.to_owned())),
    )
    .await
    .expect("the credentials table")
        == auth::password::Compared::Matches
}

async fn plant_key(plane: &Plane, credential_id: &[u8]) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    store::providers::webauthn::enrol(
        &transaction,
        &store::providers::webauthn::EnrolledCredential {
            credential_id: credential_id.to_vec(),
            user_id: support::SUBJECT.into(),
            label: "laptop".into(),
            passkey: json!({}),
            sign_count: 0,
            attachment: None,
            aaguid: None,
            attestation_format: None,
            enrolled_at: None,
            last_used_at: None,
        },
    )
    .await
    .expect("the keys table");
    transaction.commit().await.expect("the key kept");
}

async fn plant_recovery_codes(plane: &Plane) {
    use crypto::provider::CryptoProvider as _;
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    store::providers::credentials::replace_recovery_codes(
        &transaction,
        support::provider().digest(),
        support::REALM,
        support::SUBJECT,
        &["first-code", "second-code"],
        &["sheet-1", "sheet-2"],
        &models::auditable::AuditableModel::from_creator(
            support::TENANT.to_owned(),
            support::SUBJECT.to_owned(),
        ),
    )
    .await
    .expect("the credentials table");
    transaction.commit().await.expect("the sheet kept");
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

fn changed_to(current: &str, replacement: &str) -> Option<Value> {
    Some(json!({ "current_password": current, "new_password": replacement }))
}

/// A person replaces their own password through the account API only from a login
/// recent and strong enough, and only on proof of the current one. Without a recent
/// sign-in they are asked to step up; an empty field is refused, and a body larger
/// than a password change is not read; a wrong current password changes nothing and
/// ends no login. The right one keeps the new password and ends every other login,
/// leaving the one that made the change.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_password_changes_from_a_recent_strong_sign_in_on_proof_of_the_current_one() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    open_login_elsewhere(&plane).await;

    let (status, challenge, told) = sent(
        &plane,
        Method::PUT,
        &own("password"),
        Some(&bearer),
        changed_to(support::PASSWORD, REPLACEMENT),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(told["error_code"], "account.step_up_required", "{told}");
    assert!(
        challenge.contains(&format!(r#"acr_values="{}""#, support::PASSWORD_ACR)),
        "{challenge}"
    );
    assert!(
        held_password_is(&plane, support::PASSWORD).await,
        "a password changed without a recent sign-in"
    );

    prove_sign_in_reaching(&plane, chrono::Utc::now().timestamp(), 1).await;
    for (current, replacement) in [("", REPLACEMENT), (support::PASSWORD, "")] {
        let (status, _, told) = sent(
            &plane,
            Method::PUT,
            &own("password"),
            Some(&bearer),
            changed_to(current, replacement),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert_eq!(told["error_code"], "validation_error", "{told}");
    }
    let (status, _, told) = sent(
        &plane,
        Method::PUT,
        &own("password"),
        Some(&bearer),
        changed_to(support::PASSWORD, &"long".repeat(2048)),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{told}");

    let (status, _, told) = sent(
        &plane,
        Method::PUT,
        &own("password"),
        Some(&bearer),
        changed_to("not-the-password-at-all", REPLACEMENT),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["error_code"], "user.password.current_mismatch",
        "{told}"
    );
    assert!(
        held_password_is(&plane, support::PASSWORD).await,
        "a wrong current password changed the password"
    );
    assert!(
        login_stands(&plane, ELSEWHERE).await,
        "a refused change ended a login"
    );

    let (status, _, told) = sent(
        &plane,
        Method::PUT,
        &own("password"),
        Some(&bearer),
        changed_to(support::PASSWORD, REPLACEMENT),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["ended_sessions"], 1, "{told}");
    assert!(
        held_password_is(&plane, REPLACEMENT).await,
        "the new password was not kept"
    );
    assert!(
        !login_stands(&plane, ELSEWHERE).await,
        "another login outlived the change"
    );
    assert!(
        login_stands(&plane, support::SESSION).await,
        "the change ended the login that made it"
    );
    let (status, _, told) = asked(&plane, &me(), Some(&bearer)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the login that made the change was turned away: {told}"
    );
}

/// A wrong current password counts against the lock a sign-in counts against, and
/// the count holds although the change was refused: the right password is then
/// locked out as well.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_wrong_current_password_counts_against_the_lock() {
    let plane = Plane::with_actions(&[]).await;
    plane.count_logins(2).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    prove_sign_in_reaching(&plane, chrono::Utc::now().timestamp(), 1).await;

    for attempt in 1..=2 {
        let (status, _, told) = sent(
            &plane,
            Method::PUT,
            &own("password"),
            Some(&bearer),
            changed_to("not-the-password-at-all", REPLACEMENT),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "attempt {attempt}: {told}"
        );
    }
    let (status, _, told) = sent(
        &plane,
        Method::PUT,
        &own("password"),
        Some(&bearer),
        changed_to(support::PASSWORD, REPLACEMENT),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the lock let the right password through: {told}"
    );
    assert_eq!(told["error_code"], "user.locked_out", "{told}");
    assert!(
        held_password_is(&plane, support::PASSWORD).await,
        "a locked account changed its password"
    );
}

/// A person reads what they hold to sign in with through the account API, and
/// removes a factor only from a login recent and strong enough. Without a recent
/// sign-in the removal is asked to step up and nothing goes; a factor the person
/// does not hold is not found; a key spelled in no base64 is a bad request; the last
/// second factor stays; the sheet of recovery codes may always go.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_lists_and_removes_their_factors_from_a_recent_strong_sign_in() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    plant_key(&plane, b"key-one").await;
    plant_recovery_codes(&plane).await;

    let (status, _, held) = asked(&plane, &own("credentials"), Some(&bearer)).await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert_eq!(
        (
            held["password"].as_bool(),
            held["apps"][0]["id"].as_str(),
            held["keys"][0]["label"].as_str(),
            held["recovery_codes"].as_i64(),
        ),
        (Some(true), Some("cred-totp"), Some("laptop"), Some(2)),
        "{held}"
    );
    assert!(held["fresh_until"].is_null(), "{held}");

    let (status, challenge, told) = sent(
        &plane,
        Method::DELETE,
        &own("credentials/cred-totp"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert!(
        challenge.contains(&format!(r#"acr_values="{}""#, support::PASSWORD_ACR)),
        "{challenge}"
    );

    prove_sign_in_reaching(&plane, chrono::Utc::now().timestamp(), 1).await;
    let (status, _, told) = sent(
        &plane,
        Method::DELETE,
        &own("credentials/not-an-app-of-mine"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(
        (status, told["error_code"].as_str()),
        (StatusCode::NOT_FOUND, Some("credential.not_found")),
        "{told}"
    );
    let (status, _, told) = sent(
        &plane,
        Method::DELETE,
        &own("keys/not*base64"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");

    let (status, _, told) = sent(
        &plane,
        Method::DELETE,
        &own("credentials/cred-totp"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let key = data_encoding::BASE64URL_NOPAD.encode(b"key-one");
    let (status, _, told) = sent(
        &plane,
        Method::DELETE,
        &own(&format!("keys/{key}")),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(
        (status, told["error_code"].as_str()),
        (StatusCode::CONFLICT, Some("account.last_factor")),
        "the last second factor was taken: {told}"
    );
    let (status, _, told) = sent(
        &plane,
        Method::DELETE,
        &own("recovery-codes"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    let (_, _, held) = asked(&plane, &own("credentials"), Some(&bearer)).await;
    assert_eq!(
        (
            held["apps"].as_array().map(Vec::len),
            held["keys"].as_array().map(Vec::len),
            held["recovery_codes"].as_i64(),
        ),
        (Some(0), Some(1), Some(0)),
        "{held}"
    );
    assert!(held["fresh_until"].is_i64(), "{held}");
}

/// A factor goes only from a sign-in as strong as the flow the account console signs
/// in with lets the person reach: with a code step behind the password, a recent
/// password alone is asked to step up to `mfa` and removes nothing, and a recent
/// code removes it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_factor_goes_only_from_a_sign_in_as_strong_as_the_console_flow_allows() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    plane
        .bind_browser_flow(ACCOUNT_CONSOLE, support::STRONG_FLOW)
        .await;
    plant_key(&plane, b"key-one").await;

    prove_sign_in_reaching(&plane, chrono::Utc::now().timestamp(), 1).await;
    let (status, challenge, told) = sent(
        &plane,
        Method::DELETE,
        &own("credentials/cred-totp"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert!(
        challenge.contains(&format!(r#"acr_values="{}""#, support::STRONG_ACR)),
        "{challenge}"
    );
    let (_, _, held) = asked(&plane, &own("credentials"), Some(&bearer)).await;
    assert_eq!(held["stronger_sign_in_needed"], true, "{held}");
    assert_eq!(held["apps"].as_array().map(Vec::len), Some(1), "{held}");

    prove_sign_in_reaching(&plane, chrono::Utc::now().timestamp(), 2).await;
    let (status, _, told) = sent(
        &plane,
        Method::DELETE,
        &own("credentials/cred-totp"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
}
