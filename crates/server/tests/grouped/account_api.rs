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
use services::account::api::{ACCOUNT_CONSOLE, compose_account_console_redirect};
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;
const INVALID_TOKEN: &str = r#"Bearer error="invalid_token""#;
const ELSEWHERE: &str = "session-elsewhere";
const REPLACEMENT: &str = "a-fresh-password-of-decent-length";

fn mounted(plane: &Plane) -> Mounted {
    mounted_dialling(plane, config::serving::Egress::Outward)
}

/// The same plane, told where it may dial. A rig whose application listens on
/// this machine is a deployment whose relying parties share its network, which
/// is what the wider setting is for.
fn mounted_dialling(plane: &Plane, egress: config::serving::Egress) -> Mounted {
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
        egress,
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
    let transaction = plane.scoped(&within()).await;
    services::realm::provisioning::provision_account_console(
        &transaction,
        support::TENANT,
        REALM,
        &services::realm::provisioning::AccountConsole {
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
    let transaction = plane.scoped(&within()).await;
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
    sent_dialling(
        plane,
        method,
        path,
        bearer,
        body,
        config::serving::Egress::Outward,
    )
    .await
}

async fn sent_dialling(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
    egress: config::serving::Egress,
) -> (StatusCode, String, Value) {
    let app =
        test::init_service(App::new().configure(register(&mounted_dialling(plane, egress)))).await;
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
    let transaction = plane.scoped(&within()).await;
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
    let transaction = plane.scoped(&within()).await;
    store::providers::sessions::load(&transaction, session_id)
        .await
        .expect("the sessions table")
        .is_some()
}

async fn held_password_is(plane: &Plane, offered: &str) -> bool {
    let transaction = plane.scoped(&within()).await;
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
    let transaction = plane.scoped(&within()).await;
    store::providers::directory::webauthn::enrol(
        &transaction,
        &store::providers::directory::webauthn::EnrolledCredential {
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
    let transaction = plane.scoped(&within()).await;
    store::providers::directory::credentials::replace_recovery_codes(
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

/// The change keeps the counts per address every door keeps: a guess the
/// person's lock refused still counts and is kept, and past the threshold the
/// address is told to wait in the catalogue's words, the password untouched.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_current_password_guessed_from_one_address_is_turned_away() {
    let plane = Plane::with_actions(&[]).await;
    plane.count_logins(2).await;
    plane
        .throttle_sources(models::entities::realm::SourceThrottle {
            throttled: true,
            max_failures: 100,
            max_name_failures: 4,
            window_seconds: 900,
        })
        .await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    prove_sign_in_reaching(&plane, chrono::Utc::now().timestamp(), 1).await;

    let mut heard = Vec::new();
    for _ in 0..5 {
        let app = test::init_service(App::new().configure(register(&mounted_dialling(
            &plane,
            config::serving::Egress::Outward,
        ))))
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::put()
                .uri(&own("password"))
                .peer_addr("203.0.113.7:40000".parse().expect("an address"))
                .insert_header(("authorization", format!("Bearer {bearer}")))
                .set_json(json!({
                    "current_password": "not-the-password-at-all",
                    "new_password": REPLACEMENT,
                }))
                .to_request(),
        )
        .await;
        let status = response.status().as_u16();
        let told: Value = test::read_body_json(response).await;
        heard.push((
            status,
            told["error_code"].as_str().unwrap_or_default().to_owned(),
        ));
    }
    let expected = [
        (422, "user.password.current_mismatch"),
        (422, "user.password.current_mismatch"),
        (429, "user.locked_out"),
        (429, "user.locked_out"),
        (429, "too_many_requests"),
    ]
    .map(|(status, code)| (status, code.to_owned()));
    assert_eq!(heard, expected);
    assert!(held_password_is(&plane, support::PASSWORD).await);
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

const CHROME_ON_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                                 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

async fn open_login(
    plane: &Plane,
    session_id: &str,
    user_id: &str,
    state: UserSessionState,
    expiration: Option<i64>,
    user_agent: Option<&str>,
) {
    let transaction = plane.scoped(&within()).await;
    store::providers::sessions::open(
        &transaction,
        &UserSessionModel {
            browser_state: None,
            tenant: support::TENANT.into(),
            session_id: session_id.into(),
            realm_id: support::REALM.into(),
            user_id: user_id.into(),
            login_username: user_id.into(),
            broker_session_id: None,
            broker_user_id: None,
            auth_method: Some("browser".into()),
            ip_address: Some("203.0.113.7".into()),
            user_agent: user_agent.map(str::to_owned),
            started_at: chrono::Utc::now().timestamp(),
            auth_time: None,
            loa: None,
            expiration,
            state,
            remember_me: None,
            last_session_refresh: None,
            is_offline: None,
            notes: None,
        },
    )
    .await
    .expect("a login");
    transaction.commit().await.expect("the login kept");
}

async fn plant_grant(
    plane: &Plane,
    session_id: &str,
    user_id: &str,
    client_id: &str,
    offline: bool,
) {
    let now = chrono::Utc::now().timestamp();
    let transaction = plane.scoped(&within()).await;
    store::providers::sessions::open_client_session(
        &transaction,
        &models::sessions::records::ClientSessionModel {
            tenant: support::TENANT.into(),
            session_id: format!("{session_id}-{client_id}"),
            realm_id: support::REALM.into(),
            user_id: user_id.into(),
            user_session_id: session_id.into(),
            client_id: client_id.into(),
            auth_method: Some("authorization_code".into()),
            redirect_uri: None,
            started_at: now,
            expiration: Some(now + 3600),
            notes: None,
            current_refresh_token: None,
            current_refresh_token_use_count: None,
            offline: Some(offline),
            requested_claims: None,
        },
    )
    .await
    .expect("the client sessions table");
    transaction.commit().await.expect("the grant kept");
}

async fn grants_of(plane: &Plane, session_id: &str) -> Vec<String> {
    let transaction = plane.scoped(&within()).await;
    store::providers::sessions::client_sessions_of(&transaction, session_id)
        .await
        .expect("the client sessions table")
        .into_iter()
        .map(|grant| grant.client_id)
        .collect()
}

async fn plant_another_person(plane: &Plane) -> String {
    let transaction = plane.scoped(&within()).await;
    let grace = services::admin::users::create(
        &transaction,
        &support::provider(),
        support::TENANT,
        REALM,
        "root",
        "grace",
        &services::admin::users::Spec {
            email: Some("grace@example.test".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|_| panic!("another person was not made"));
    transaction.commit().await.expect("the person kept");
    grace.user_id
}

/// A client's ear: one HTTP request accepted on a port of its own, its body handed
/// back, a 200 sent. What a relying party's back-channel endpoint is.
fn listening_client() -> (String, std::sync::mpsc::Receiver<String>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("a caller");
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).unwrap_or(0);
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..read]);
            let text = String::from_utf8_lossy(&raw).to_string();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length: usize = head
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("Content-Length: ")
                            .or_else(|| line.strip_prefix("content-length: "))
                    })
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                if body.len() >= length {
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    let _ = sender.send(body[..length].to_owned());
                    break;
                }
            }
        }
    });
    (format!("http://127.0.0.1:{port}/logout-token"), receiver)
}

/// A person sees the logins that still stand, the one the request rides marked, with
/// where each came from and what each application holds. A login closed with nothing
/// left, or run out, is not shown, and a closed login shows only the offline grant
/// that outlives it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_sees_the_logins_that_still_stand_and_what_applications_hold() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    let now = chrono::Utc::now().timestamp();
    open_login(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        UserSessionState::LoggedIn,
        None,
        Some(CHROME_ON_WINDOWS),
    )
    .await;
    plant_grant(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        support::CONFIDENTIAL,
        false,
    )
    .await;
    open_login(
        &plane,
        "session-offline",
        support::SUBJECT,
        UserSessionState::LoggedOut,
        None,
        None,
    )
    .await;
    plant_grant(
        &plane,
        "session-offline",
        support::SUBJECT,
        support::CONFIDENTIAL,
        true,
    )
    .await;
    plant_grant(
        &plane,
        "session-offline",
        support::SUBJECT,
        support::PUBLIC,
        false,
    )
    .await;
    open_login(
        &plane,
        "session-closed",
        support::SUBJECT,
        UserSessionState::LoggedOut,
        None,
        None,
    )
    .await;
    open_login(
        &plane,
        "session-run-out",
        support::SUBJECT,
        UserSessionState::LoggedIn,
        Some(now - 60),
        None,
    )
    .await;

    let (status, _, told) = asked(&plane, &own("sessions"), Some(&bearer)).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let listed = told.as_array().cloned().unwrap_or_default();
    let login = |id: &str| {
        listed
            .iter()
            .find(|login| login["session_id"] == id)
            .cloned()
    };
    assert!(
        login("session-closed").is_none(),
        "a login closed with nothing left was shown: {told}"
    );
    assert!(
        login("session-run-out").is_none(),
        "a login run out was shown: {told}"
    );
    let current = login(support::SESSION).expect("the login the request rides");
    assert_eq!(
        (current["current"].as_bool(), current["open"].as_bool()),
        (Some(true), Some(true)),
        "{told}"
    );
    let elsewhere = login(ELSEWHERE).expect("the other open login");
    assert_eq!(
        (elsewhere["current"].as_bool(), elsewhere["open"].as_bool()),
        (Some(false), Some(true)),
        "{told}"
    );
    assert_eq!(elsewhere["ip_address"], "203.0.113.7", "{told}");
    assert!(
        elsewhere["browser"].is_string() && elsewhere["system"].is_string(),
        "{told}"
    );
    assert!(elsewhere.get("user_agent").is_none(), "{told}");
    assert_eq!(
        elsewhere["grants"].as_array().map(Vec::len),
        Some(1),
        "{told}"
    );
    assert_eq!(
        elsewhere["grants"][0]["client_id"],
        support::CONFIDENTIAL,
        "{told}"
    );
    assert!(
        elsewhere["grants"][0]["name"]
            .as_str()
            .is_some_and(|name| !name.is_empty()),
        "{told}"
    );
    let offline = login("session-offline").expect("the closed login an offline grant outlives");
    assert_eq!(offline["open"], false, "{told}");
    assert_eq!(
        offline["grants"].as_array().map(Vec::len),
        Some(1),
        "{told}"
    );
    assert_eq!(
        (
            offline["grants"][0]["client_id"].as_str(),
            offline["grants"][0]["offline"].as_bool()
        ),
        (Some(support::CONFIDENTIAL), Some(true)),
        "{told}"
    );
}

/// A person ends one of their logins, and everything its applications got from it
/// goes with it, offline grants included; the applications registered to hear of it
/// are told, and the login the request rides keeps working. Somebody else's login,
/// or one nobody holds, is not found.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_ends_one_of_their_logins_and_its_applications_are_told() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    open_login(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        UserSessionState::LoggedIn,
        None,
        None,
    )
    .await;
    plant_grant(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        support::CONFIDENTIAL,
        true,
    )
    .await;
    let (uri, heard) = listening_client();
    plane
        .register_backchannel(support::CONFIDENTIAL, &uri)
        .await;
    let grace = plant_another_person(&plane).await;
    open_login(
        &plane,
        "session-grace",
        &grace,
        UserSessionState::LoggedIn,
        None,
        None,
    )
    .await;

    for foreign in ["session-grace", "no-such-login"] {
        let (status, _, told) = sent(
            &plane,
            Method::DELETE,
            &own(&format!("sessions/{foreign}")),
            Some(&bearer),
            None,
        )
        .await;
        assert_eq!(
            (status, told["error_code"].as_str()),
            (StatusCode::NOT_FOUND, Some("auth.session.not_found")),
            "{told}"
        );
    }
    assert!(
        login_stands(&plane, "session-grace").await,
        "somebody else's login was ended"
    );

    let (status, _, told) = sent_dialling(
        &plane,
        Method::DELETE,
        &own(&format!("sessions/{ELSEWHERE}")),
        Some(&bearer),
        None,
        config::serving::Egress::Anywhere,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    assert!(
        !login_stands(&plane, ELSEWHERE).await,
        "the login outlived its ending"
    );
    assert!(
        grants_of(&plane, ELSEWHERE).await.is_empty(),
        "an offline grant outlived its login"
    );
    let posted = heard
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the application was not told");
    let token = posted
        .strip_prefix("logout_token=")
        .expect("a logout token");
    let payload = token.split('.').nth(1).expect("a payload");
    let claims: Value = serde_json::from_slice(
        &data_encoding::BASE64URL_NOPAD
            .decode(payload.as_bytes())
            .expect("base64url"),
    )
    .expect("claims");
    assert_eq!(claims["sid"], ELSEWHERE, "{claims}");
    assert!(
        login_stands(&plane, support::SESSION).await,
        "the login the request rides ended"
    );
    let (status, _, told) = asked(&plane, &me(), Some(&bearer)).await;
    assert_eq!(status, StatusCode::OK, "{told}");
}

/// A person ends every login but the one the request rides, closed logins still
/// holding an offline grant included, and is told how many ended.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_ends_every_other_login_and_keeps_the_one_they_ride() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    open_login(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        UserSessionState::LoggedIn,
        None,
        None,
    )
    .await;
    plant_grant(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        support::CONFIDENTIAL,
        true,
    )
    .await;
    open_login(
        &plane,
        "session-offline",
        support::SUBJECT,
        UserSessionState::LoggedOut,
        None,
        None,
    )
    .await;
    plant_grant(
        &plane,
        "session-offline",
        support::SUBJECT,
        support::CONFIDENTIAL,
        true,
    )
    .await;

    let (status, _, told) = sent(
        &plane,
        Method::DELETE,
        &own("sessions"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["ended_sessions"], 2, "{told}");
    for ended in [ELSEWHERE, "session-offline"] {
        assert!(
            !login_stands(&plane, ended).await,
            "{ended} outlived the ending"
        );
        assert!(
            grants_of(&plane, ended).await.is_empty(),
            "a grant of {ended} outlived it"
        );
    }
    assert!(
        login_stands(&plane, support::SESSION).await,
        "the login the request rides ended"
    );
    let (status, _, told) = asked(&plane, &me(), Some(&bearer)).await;
    assert_eq!(status, StatusCode::OK, "{told}");
}

/// A person takes back what one application got from one of their logins, and the
/// login and every other application keep theirs. A grant already taken, a login
/// nobody holds and somebody else's login are not found.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_takes_back_what_one_application_got_from_a_login() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    open_login(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        UserSessionState::LoggedIn,
        None,
        None,
    )
    .await;
    plant_grant(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        support::CONFIDENTIAL,
        true,
    )
    .await;
    plant_grant(&plane, ELSEWHERE, support::SUBJECT, support::PUBLIC, false).await;
    let (uri, heard) = listening_client();
    plane
        .register_backchannel(support::CONFIDENTIAL, &uri)
        .await;
    let grace = plant_another_person(&plane).await;
    open_login(
        &plane,
        "session-grace",
        &grace,
        UserSessionState::LoggedIn,
        None,
        None,
    )
    .await;
    plant_grant(&plane, "session-grace", &grace, support::CONFIDENTIAL, true).await;

    let taken = own(&format!(
        "sessions/{ELSEWHERE}/grants/{}",
        support::CONFIDENTIAL
    ));
    let (status, _, told) = sent_dialling(
        &plane,
        Method::DELETE,
        &taken,
        Some(&bearer),
        None,
        config::serving::Egress::Anywhere,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    assert!(
        login_stands(&plane, ELSEWHERE).await,
        "the login went with one grant"
    );
    let told_of = read_logout_claims(&heard);
    assert_eq!(told_of["sid"], ELSEWHERE, "{told_of}");
    assert_eq!(grants_of(&plane, ELSEWHERE).await, [support::PUBLIC]);

    let (status, _, told) = sent(&plane, Method::DELETE, &taken, Some(&bearer), None).await;
    assert_eq!(
        (status, told["error_code"].as_str()),
        (StatusCode::NOT_FOUND, Some("auth.grant.not_found")),
        "{told}"
    );
    for foreign in ["session-grace", "no-such-login"] {
        let path = own(&format!(
            "sessions/{foreign}/grants/{}",
            support::CONFIDENTIAL
        ));
        let (status, _, told) = sent(&plane, Method::DELETE, &path, Some(&bearer), None).await;
        assert_eq!(
            (status, told["error_code"].as_str()),
            (StatusCode::NOT_FOUND, Some("auth.session.not_found")),
            "{told}"
        );
    }
    assert_eq!(
        grants_of(&plane, "session-grace").await,
        [support::CONFIDENTIAL],
        "somebody else's grant was taken"
    );
}

/// Ending the login the request rides is allowed, and signs the console out: its
/// token no longer reaches the account API.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn ending_the_login_the_request_rides_signs_the_console_out() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());

    let (status, _, told) = sent(
        &plane,
        Method::DELETE,
        &own(&format!("sessions/{}", support::SESSION)),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (status, challenge, told) = asked(&plane, &me(), Some(&bearer)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(challenge, INVALID_TOKEN, "{told}");
}

/// The account console's own service calls, run by its contract suite against
/// this server on a real socket: every path it asks for is taken, and every answer
/// it keeps fits the type it reads the answer as.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG) and the account console's packages (pnpm install)"]
async fn the_account_console_contract_holds_against_a_live_server() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    // The person signed in elsewhere too, and an application got offline access
    // there: what the console lists, takes back and ends without ending its own.
    open_login(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        UserSessionState::LoggedIn,
        None,
        Some(CHROME_ON_WINDOWS),
    )
    .await;
    plant_grant(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        support::CONFIDENTIAL,
        true,
    )
    .await;
    // Ways to sign in beside the planted app, and a sign-in recent enough to change
    // them: what the console lists, removes, and refuses a wrong password against.
    plane
        .enrol_totp("cred-contract", support::TOTP_SECRET)
        .await;
    plant_key(&plane, b"key-contract").await;
    plant_recovery_codes(&plane).await;
    prove_sign_in_reaching(&plane, chrono::Utc::now().timestamp(), 1).await;
    // A consent to another application, and what one more got from the login the
    // console rides: what the console withdraws and takes back, leaving the login
    // elsewhere to the calls on logins.
    keep_consent(&plane, support::SUBJECT, support::OTHER, &["openid"]).await;
    plant_grant(
        &plane,
        support::SESSION,
        support::SUBJECT,
        support::PUBLIC,
        false,
    )
    .await;
    let bearer = plane.token(&account_claims());

    let served = mounted(&plane);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let server = actix_web::HttpServer::new(move || App::new().configure(register(&served)))
        .listen(listener)
        .expect("a listener")
        .workers(1)
        .disable_signals()
        .run();
    tokio::spawn(server);

    let console = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../account");
    assert!(
        console.join("node_modules").is_dir(),
        "the account console's packages are not installed: run pnpm install"
    );
    let run = tokio::task::spawn_blocking(move || {
        Command::new("pnpm")
            .args(["run", "contract"])
            .current_dir(console)
            .env("SAFFUI_CONTRACT_ORIGIN", format!("http://127.0.0.1:{port}"))
            .env("SAFFUI_CONTRACT_TOKEN", bearer)
            .env("SAFFUI_CONTRACT_REALM", REALM)
            .output()
    })
    .await
    .expect("the run comes back")
    .expect("pnpm starts");
    assert!(
        run.status.success(),
        "the account console contract broke:\n{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

/// A person signs in through the account console the way its app does, and the
/// token that comes back opens the account API: the realm's provisioned console,
/// its registered return, its scope and the claims the guard reads fit together.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_sign_in_through_the_account_console_opens_the_account_api() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let (verifier, challenge) = support::pkce_pair();
    let redirect = compose_account_console_redirect(&support::origin().issuer(REALM));

    let asking = [
        ("response_type", "code"),
        ("client_id", ACCOUNT_CONSOLE),
        ("redirect_uri", redirect.as_str()),
        ("scope", "openid account"),
        ("state", "opaque-state"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("ui_locales", "fr"),
    ]
    .iter()
    .map(|(key, value)| format!("{key}={}", support::urlencode(value)))
    .collect::<Vec<_>>()
    .join("&");
    let opened = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/auth?{asking}"
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        opened.status(),
        StatusCode::FOUND,
        "the account console's sign-in did not open"
    );
    let set: Vec<String> = opened
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let binding = support::cookie_value(&set, support::AUTH_SESSION_COOKIE)
        .expect("a login bound to the browser");

    let answered = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/login"))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .set_json(json!({ "username": support::SUBJECT, "password": support::PASSWORD }))
            .to_request(),
    )
    .await;
    let told: Value = test::read_body_json(answered).await;
    let landing = told["redirect_to"]
        .as_str()
        .unwrap_or_else(|| panic!("nobody was admitted: {told}"));
    assert!(
        landing.starts_with(&format!("{redirect}?")),
        "the sign-in did not come back to the console: {landing}"
    );
    let code = landing
        .split_once("code=")
        .unwrap_or_else(|| panic!("no code came back: {landing}"))
        .1
        .split('&')
        .next()
        .expect("a code")
        .to_owned();

    let spent = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", redirect.as_str()),
                ("client_id", ACCOUNT_CONSOLE),
                ("code_verifier", verifier.as_str()),
            ])
            .to_request(),
    )
    .await;
    let status = spent.status();
    let granted: Value = test::read_body_json(spent).await;
    assert_eq!(status, StatusCode::OK, "the code was not spent: {granted}");
    let bearer = granted["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no access token: {granted}"));

    let (status, challenge, me) = asked(&plane, &me(), Some(bearer)).await;
    assert_eq!(status, StatusCode::OK, "{challenge} {me}");
    assert_eq!(
        me["preferred_username"].as_str(),
        Some(support::SUBJECT),
        "{me}"
    );
}

async fn keep_consent(plane: &Plane, user_id: &str, client_id: &str, scopes: &[&str]) {
    let transaction = plane.scoped(&within()).await;
    let scopes: Vec<String> = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    store::providers::directory::consents::keep(
        &transaction,
        user_id,
        client_id,
        &scopes,
        chrono::Utc::now(),
    )
    .await
    .expect("the consents table");
    transaction.commit().await.expect("the consent kept");
}

async fn consent_held(plane: &Plane, user_id: &str, client_id: &str) -> bool {
    let transaction = plane.scoped(&within()).await;
    store::providers::directory::consents::held(&transaction, user_id, client_id)
        .await
        .expect("the consents table")
        .is_some()
}

async fn reshape_client(
    plane: &Plane,
    client_id: &str,
    reshape: impl FnOnce(&mut models::entities::client::ClientModel),
) {
    let transaction = plane.scoped(&within()).await;
    let mut client = store::providers::clients::load(&transaction, client_id)
        .await
        .expect("the clients table")
        .expect("a planted client");
    reshape(&mut client);
    store::providers::clients::update(&transaction, &client)
        .await
        .expect("the clients table");
    transaction.commit().await.expect("the client kept");
}

/// The claims of the logout token an application was posted.
fn read_logout_claims(heard: &std::sync::mpsc::Receiver<String>) -> Value {
    let posted = heard
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the application was not told");
    let token = posted
        .strip_prefix("logout_token=")
        .expect("a logout token");
    let payload = token.split('.').nth(1).expect("a payload");
    serde_json::from_slice(
        &data_encoding::BASE64URL_NOPAD
            .decode(payload.as_bytes())
            .expect("base64url"),
    )
    .expect("claims")
}

/// A person sees each application that holds something of theirs: what they agreed it
/// may have, and what it holds from their logins, gathered across them. The realm's own
/// console is not listed, nor is somebody else's application, and an address a browser
/// should not follow is not offered.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_sees_the_applications_that_hold_something_of_theirs() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    open_login(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        UserSessionState::LoggedIn,
        None,
        None,
    )
    .await;
    plant_grant(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        support::CONFIDENTIAL,
        true,
    )
    .await;
    plant_grant(
        &plane,
        support::SESSION,
        support::SUBJECT,
        support::CONFIDENTIAL,
        false,
    )
    .await;
    plant_grant(
        &plane,
        support::SESSION,
        support::SUBJECT,
        ACCOUNT_CONSOLE,
        false,
    )
    .await;
    keep_consent(
        &plane,
        support::SUBJECT,
        support::PUBLIC,
        &["openid", "profile"],
    )
    .await;
    reshape_client(&plane, support::CONFIDENTIAL, |client| {
        client.client_uri = Some("https://app.example/home".to_owned());
    })
    .await;
    reshape_client(&plane, support::PUBLIC, |client| {
        client.client_uri = Some("javascript:alert(1)".to_owned());
        client.consent_required = Some(true);
    })
    .await;
    let grace = plant_another_person(&plane).await;
    open_login(
        &plane,
        "session-grace",
        &grace,
        UserSessionState::LoggedIn,
        None,
        None,
    )
    .await;
    plant_grant(&plane, "session-grace", &grace, support::OTHER, false).await;

    let (status, _, held) = asked(&plane, &own("applications"), Some(&bearer)).await;
    assert_eq!(status, StatusCode::OK, "{held}");
    let listed: Vec<&str> = held
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|application| application["client_id"].as_str())
        .collect();
    assert_eq!(listed, [support::CONFIDENTIAL, support::PUBLIC], "{held}");
    let app = &held[0];
    assert_eq!(
        (
            app["name"].as_str(),
            app["home"].as_str(),
            app["access"]["logins"].as_i64(),
            app["access"]["offline"].as_bool(),
            app["consent"].is_null(),
        ),
        (
            Some(support::CONFIDENTIAL),
            Some("https://app.example/home"),
            Some(2),
            Some(true),
            true,
        ),
        "{held}"
    );
    let agreed = &held[1];
    assert_eq!(
        (
            agreed["home"].is_null(),
            agreed["access"].is_null(),
            agreed["consent"]["scopes"].clone(),
            agreed["consent"]["asks_consent"].as_bool(),
        ),
        (true, true, json!(["openid", "profile"]), Some(true)),
        "{held}"
    );
}

/// A person withdraws what they agreed an application may have, and the application
/// keeps what it holds. A consent already withdrawn, the realm's own console and
/// somebody else's consent are not found, and nothing of theirs changes.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_withdraws_a_consent_and_the_application_keeps_what_it_holds() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    keep_consent(&plane, support::SUBJECT, support::CONFIDENTIAL, &["openid"]).await;
    plant_grant(
        &plane,
        support::SESSION,
        support::SUBJECT,
        support::CONFIDENTIAL,
        true,
    )
    .await;
    let grace = plant_another_person(&plane).await;
    keep_consent(&plane, &grace, support::PUBLIC, &["openid"]).await;
    keep_consent(&plane, support::SUBJECT, ACCOUNT_CONSOLE, &["openid"]).await;

    let withdrawn = own(&format!("applications/{}/consent", support::CONFIDENTIAL));
    let (status, _, told) = sent(&plane, Method::DELETE, &withdrawn, Some(&bearer), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    assert!(
        !consent_held(&plane, support::SUBJECT, support::CONFIDENTIAL).await,
        "the consent outlived its withdrawal"
    );
    assert_eq!(
        grants_of(&plane, support::SESSION).await,
        [support::CONFIDENTIAL],
        "withdrawing a consent took back a grant"
    );

    for refused in [
        withdrawn,
        own(&format!("applications/{ACCOUNT_CONSOLE}/consent")),
        own(&format!("applications/{}/consent", support::PUBLIC)),
    ] {
        let (status, _, told) = sent(&plane, Method::DELETE, &refused, Some(&bearer), None).await;
        assert_eq!(
            (status, told["error_code"].as_str()),
            (StatusCode::NOT_FOUND, Some("auth.consent.not_found")),
            "{refused}: {told}"
        );
    }
    assert!(
        consent_held(&plane, &grace, support::PUBLIC).await,
        "somebody else's consent was withdrawn"
    );
    assert!(
        consent_held(&plane, support::SUBJECT, ACCOUNT_CONSOLE).await,
        "the console's own consent was withdrawn"
    );
}

/// A person takes back everything one application got from their logins, offline
/// grants included, and the application is told for the login it was signed in
/// through; the logins and every other application keep theirs. An application
/// holding nothing more, the realm's own console and somebody else's grants are not
/// found, and stay.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_takes_back_an_applications_access_from_every_login_and_it_is_told() {
    let plane = Plane::with_actions(&[]).await;
    provision_account_console(&plane).await;
    let bearer = plane.token(&account_claims());
    open_login(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        UserSessionState::LoggedIn,
        None,
        None,
    )
    .await;
    plant_grant(
        &plane,
        ELSEWHERE,
        support::SUBJECT,
        support::CONFIDENTIAL,
        true,
    )
    .await;
    plant_grant(&plane, ELSEWHERE, support::SUBJECT, support::PUBLIC, false).await;
    plant_grant(
        &plane,
        support::SESSION,
        support::SUBJECT,
        support::PUBLIC,
        false,
    )
    .await;
    plant_grant(
        &plane,
        support::SESSION,
        support::SUBJECT,
        ACCOUNT_CONSOLE,
        false,
    )
    .await;
    let (uri, heard) = listening_client();
    plane
        .register_backchannel(support::CONFIDENTIAL, &uri)
        .await;
    let grace = plant_another_person(&plane).await;
    open_login(
        &plane,
        "session-grace",
        &grace,
        UserSessionState::LoggedIn,
        None,
        None,
    )
    .await;
    plant_grant(&plane, "session-grace", &grace, support::PUBLIC, false).await;

    let (status, _, told) = sent_dialling(
        &plane,
        Method::DELETE,
        &own(&format!("applications/{}/access", support::CONFIDENTIAL)),
        Some(&bearer),
        None,
        config::serving::Egress::Anywhere,
    )
    .await;
    assert_eq!(
        (status, told["ended_grants"].as_i64()),
        (StatusCode::OK, Some(1)),
        "{told}"
    );
    assert_eq!(grants_of(&plane, ELSEWHERE).await, [support::PUBLIC]);
    let told_of = read_logout_claims(&heard);
    assert_eq!(told_of["sid"], ELSEWHERE, "{told_of}");
    assert!(
        login_stands(&plane, ELSEWHERE).await,
        "the login went with the application"
    );

    let taken_everywhere = own(&format!("applications/{}/access", support::PUBLIC));
    let (status, _, told) = sent(
        &plane,
        Method::DELETE,
        &taken_everywhere,
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(
        (status, told["ended_grants"].as_i64()),
        (StatusCode::OK, Some(2)),
        "{told}"
    );
    assert!(grants_of(&plane, ELSEWHERE).await.is_empty());
    assert_eq!(grants_of(&plane, support::SESSION).await, [ACCOUNT_CONSOLE]);

    for refused in [
        taken_everywhere,
        own(&format!("applications/{ACCOUNT_CONSOLE}/access")),
    ] {
        let (status, _, told) = sent(&plane, Method::DELETE, &refused, Some(&bearer), None).await;
        assert_eq!(
            (status, told["error_code"].as_str()),
            (StatusCode::NOT_FOUND, Some("auth.grant.not_found")),
            "{refused}: {told}"
        );
    }
    assert_eq!(
        grants_of(&plane, "session-grace").await,
        [support::PUBLIC],
        "somebody else's grant was taken"
    );
    let (status, _, told) = asked(&plane, &me(), Some(&bearer)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the console lost its own sign-in: {told}"
    );
}
