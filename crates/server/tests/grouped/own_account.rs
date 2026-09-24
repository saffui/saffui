#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use models::entities::realm::PasswordPolicy;
use models::entities::user::RequiredAction;
use models::sessions::records::{UserSessionModel, UserSessionState};
use secrecy::SecretBox;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;
const REPLACEMENT: &str = "a-fresh-password-of-decent-length";
const ELSEWHERE: &str = "session-elsewhere";

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
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
        ceiling: support::ceiling(),
    }
}

async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asking = test::TestRequest::default()
        .method(method)
        .uri(path)
        .insert_header(("authorization", format!("Bearer {bearer}")));
    if let Some(body) = body {
        asking = asking.set_json(body);
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    let told = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, told)
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, support::REALM)
}

fn own_password() -> String {
    format!("/admin/realms/{REALM}/account/password")
}

fn change(current: &str, replacement: &str) -> Value {
    json!({ "current_password": current, "new_password": replacement })
}

/// A login of the same person on another device.
async fn open_login_elsewhere(plane: &Plane) {
    let transaction = plane.scoped(&within()).await;
    store::providers::protocol::sessions::open(
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
    store::providers::protocol::sessions::load(&transaction, session_id)
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

async fn pending_actions(plane: &Plane) -> Vec<RequiredAction> {
    let transaction = plane.scoped(&within()).await;
    store::providers::directory::users::load(&transaction, support::SUBJECT)
        .await
        .expect("the users table")
        .expect("the planted person")
        .required_actions
        .unwrap_or_default()
}

/// A person replaces their own password with the current one: every other
/// login of theirs ends, and the one making the change keeps working.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_password_changed_with_the_current_one_ends_every_other_login() {
    let plane = Plane::with_actions(&[AdminAction::AccountWrite, AdminAction::UserRead]).await;
    let bearer = plane.token(&support::claims());
    open_login_elsewhere(&plane).await;
    {
        let transaction = plane.scoped(&within()).await;
        store::providers::directory::users::require_action(
            &transaction,
            support::SUBJECT,
            RequiredAction::UpdatePassword,
        )
        .await
        .expect("the users table");
        transaction.commit().await.expect("the instruction kept");
    }

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &own_password(),
        &bearer,
        Some(change("not-the-password-at-all", REPLACEMENT)),
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

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &own_password(),
        &bearer,
        Some(change(support::PASSWORD, REPLACEMENT)),
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
    assert!(
        !pending_actions(&plane)
            .await
            .contains(&RequiredAction::UpdatePassword),
        "the instruction to replace the password outlived its replacement"
    );

    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/users/{}", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the login that made the change was signed out: {told}"
    );
}

/// A wrong current password counts against the lock a sign-in counts against,
/// and the count holds although the change was refused.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_wrong_current_password_counts_and_the_lock_holds() {
    let plane = Plane::with_actions(&[AdminAction::AccountWrite]).await;
    plane.count_logins(2).await;
    let bearer = plane.token(&support::claims());

    for attempt in 1..=2 {
        let (status, told) = asked(
            &plane,
            Method::PUT,
            &own_password(),
            &bearer,
            Some(change("not-the-password-at-all", REPLACEMENT)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "attempt {attempt}: {told}"
        );
    }

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &own_password(),
        &bearer,
        Some(change(support::PASSWORD, REPLACEMENT)),
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

/// The change keeps the counts per address every door keeps, the name under
/// the key every door uses: a guess the person's lock refused still counts and
/// is kept, and past the threshold the address is told to wait in the
/// catalogue's words, the password untouched.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_current_password_guessed_from_one_address_is_turned_away() {
    let plane = Plane::with_actions(&[AdminAction::AccountWrite]).await;
    plane.count_logins(2).await;
    plane
        .throttle_sources(models::entities::realm::SourceThrottle {
            throttled: true,
            max_failures: 100,
            max_name_failures: 4,
            window_seconds: 900,
        })
        .await;
    let bearer = plane.token(&support::claims());

    let mut heard = Vec::new();
    for _ in 0..5 {
        let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
        let response = test::call_service(
            &app,
            test::TestRequest::put()
                .uri(&own_password())
                .peer_addr("203.0.113.7:40000".parse().expect("an address"))
                .insert_header(("authorization", format!("Bearer {bearer}")))
                .set_json(change("not-the-password-at-all", REPLACEMENT))
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
    assert_eq!(
        plane.named_failures().await,
        [(support::keyed_name(support::SUBJECT), 4)],
        "the change counted the name under another key than the other doors"
    );
}

/// The realm's policy speaks here as at every other door, and a refused
/// replacement leaves the password and every login as they were.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_replacement_the_realm_refuses_changes_nothing() {
    let plane = Plane::with_actions(&[AdminAction::AccountWrite]).await;
    let bearer = plane.token(&support::claims());
    {
        let transaction = plane.scoped(&within()).await;
        let mut realm = store::providers::realms::load(&transaction, support::REALM)
            .await
            .expect("the realms table")
            .expect("a planted realm");
        realm.password_policy = Some(PasswordPolicy {
            min_length: Some(40),
            ..PasswordPolicy::default()
        });
        store::providers::realms::update(&transaction, &realm)
            .await
            .expect("the realms table");
        transaction.commit().await.expect("the policy kept");
    }
    open_login_elsewhere(&plane).await;

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &own_password(),
        &bearer,
        Some(change(support::PASSWORD, REPLACEMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(told["error_code"], "validation_error", "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|why| why.contains("too short")),
        "the refusal is not the policy's: {told}"
    );
    assert!(
        held_password_is(&plane, support::PASSWORD).await,
        "a refused replacement was kept"
    );
    assert!(
        login_stands(&plane, ELSEWHERE).await,
        "a refused replacement ended a login"
    );
}

/// A password a directory owns, or no password at all, is not changed here.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_password_kept_elsewhere_is_not_changed_here() {
    let plane = Plane::with_actions(&[AdminAction::AccountWrite]).await;
    let bearer = plane.token(&support::claims());
    {
        let transaction = plane.scoped(&within()).await;
        transaction
            .execute(
                "UPDATE users SET user_storage = 'ldap' WHERE user_id = $1",
                &[&support::SUBJECT],
            )
            .await
            .expect("the users table");
        transaction.commit().await.expect("the storage kept");
    }

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &own_password(),
        &bearer,
        Some(change(support::PASSWORD, REPLACEMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "user.password.not_held_here", "{told}");
    assert!(
        held_password_is(&plane, support::PASSWORD).await,
        "a directory's password was written over locally"
    );

    {
        let transaction = plane.scoped(&within()).await;
        transaction
            .execute(
                "UPDATE users SET user_storage = 'local' WHERE user_id = $1",
                &[&support::SUBJECT],
            )
            .await
            .expect("the users table");
        store::providers::directory::credentials::delete_quietly(&transaction, "cred-1")
            .await
            .expect("the credentials table");
        transaction.commit().await.expect("the password gone");
    }

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &own_password(),
        &bearer,
        Some(change(support::PASSWORD, REPLACEMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "user.password.not_held_here", "{told}");
}

/// Writing other people's accounts does not carry changing one's own through
/// this door: the route costs its own capability.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn changing_ones_own_password_costs_its_own_capability() {
    let plane = Plane::with_actions(&[AdminAction::UserWrite]).await;
    let bearer = plane.token(&support::claims());

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &own_password(),
        &bearer,
        Some(change(support::PASSWORD, REPLACEMENT)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{told}");
    assert!(
        held_password_is(&plane, support::PASSWORD).await,
        "a refused caller changed the password"
    );
}

async fn prove_sign_in_at(plane: &Plane, at: i64) {
    prove_sign_in_reaching(plane, at, 1).await;
}

async fn prove_sign_in_reaching(plane: &Plane, at: i64, level: i32) {
    let transaction = plane.scoped(&within()).await;
    store::providers::protocol::sessions::record_authentication(
        &transaction,
        support::SESSION,
        at,
        Some(level),
    )
    .await
    .expect("the sessions table");
    transaction.commit().await.expect("the sign-in kept");
}

async fn plant_app(plane: &Plane, credential_id: &str) {
    use models::entities::credentials::{
        CredentialModel, CredentialSecret, OtpAlgorithm, OtpParameters,
    };
    let transaction = plane.scoped(&within()).await;
    store::providers::directory::credentials::create(
        &transaction,
        &CredentialModel::otp(
            credential_id.to_owned(),
            support::REALM.into(),
            support::SUBJECT.into(),
            CredentialSecret::new("JBSWY3DPEHPK3PXP".to_owned()),
            OtpAlgorithm::Sha1,
            OtpParameters::totp_default(),
            models::auditable::AuditableModel::from_creator(
                support::TENANT.to_owned(),
                support::SUBJECT.to_owned(),
            ),
        ),
    )
    .await
    .expect("the credentials table");
    transaction.commit().await.expect("the app kept");
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

async fn credential_changes_told(plane: &Plane) -> i64 {
    let transaction = plane.scoped(&within()).await;
    transaction
        .query_one(
            "SELECT count(*) FROM event_outbox WHERE kind = $1 AND user_id = $2",
            &[
                &store::providers::events::outbox::CREDENTIAL_CHANGED,
                &support::SUBJECT,
            ],
        )
        .await
        .expect("the outbox")
        .get(0)
}

fn own(leaf: &str) -> String {
    format!("/admin/realms/{REALM}/account/{leaf}")
}

/// A person reads what they hold to sign in with: kinds, names and dates, why
/// a factor has to stay, and never a secret.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_reads_their_own_factors_and_what_has_to_stay() {
    let plane = Plane::with_actions(&[AdminAction::AccountRead]).await;
    let bearer = plane.token(&support::claims());
    plant_recovery_codes(&plane).await;
    prove_sign_in_at(&plane, chrono::Utc::now().timestamp()).await;

    let (status, held) = asked(&plane, Method::GET, &own("credentials"), &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert_eq!(held["password"], true, "{held}");
    assert_eq!(held["apps"].as_array().map(Vec::len), Some(1), "{held}");
    assert_eq!(held["apps"][0]["id"], "cred-totp", "{held}");
    assert_eq!(held["apps"][0]["kind"], "totp", "{held}");
    assert!(
        held["apps"][0]["kept_because"]
            .as_str()
            .is_some_and(|why| why.contains("last second factor")),
        "the only app was offered for removal: {held}"
    );
    assert_eq!(held["recovery_codes"], 2, "{held}");
    assert!(held["fresh_until"].is_i64(), "{held}");
    for secret in plane.subject_totp_secrets().await {
        assert!(
            !held.to_string().contains(&secret),
            "a secret left the plane: {held}"
        );
    }

    plant_key(&plane, b"key-one").await;
    let (_, held) = asked(&plane, Method::GET, &own("credentials"), &bearer, None).await;
    assert!(
        held["apps"][0]["kept_because"].is_null(),
        "an app with a key beside it was kept: {held}"
    );
    assert_eq!(held["keys"][0]["label"], "laptop", "{held}");
    assert!(held["keys"][0]["kept_because"].is_null(), "{held}");
}

/// A removal is taken only from a login proven moments ago.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn removing_a_factor_needs_a_recent_sign_in() {
    let plane = Plane::with_actions(&[AdminAction::AccountWrite]).await;
    let bearer = plane.token(&support::claims());
    plant_app(&plane, "app-one").await;
    plant_key(&plane, b"key-one").await;
    let path = own("credentials/app-one");

    let (status, told) = asked(&plane, Method::DELETE, &path, &bearer, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{told}");
    assert_eq!(
        told["error_code"], "account.reauthentication_required",
        "{told}"
    );

    let long_ago = chrono::Utc::now().timestamp() - services::account::FRESH_SIGN_IN_SECONDS - 60;
    prove_sign_in_at(&plane, long_ago).await;
    let (status, told) = asked(&plane, Method::DELETE, &path, &bearer, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a sign-in proven long ago removed a factor: {told}"
    );

    prove_sign_in_at(&plane, chrono::Utc::now().timestamp()).await;
    let before = credential_changes_told(&plane).await;
    let (status, told) = asked(&plane, Method::DELETE, &path, &bearer, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    assert_eq!(
        credential_changes_told(&plane).await,
        before + 1,
        "a removed app went unannounced"
    );
    let changes = plane.credential_changes_of(support::SUBJECT).await;
    assert_eq!(
        changes.last().map(|change| &change["change_type"]),
        Some(&json!("delete")),
        "a holder's own app went as something other than a deletion: {changes:?}"
    );
    let (status, told) = asked(&plane, Method::DELETE, &path, &bearer, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
}

/// A recent sign-in is not enough when the flow the console signs in with lets
/// the person reach a stronger one: with a code step behind the password, the
/// password alone removes nothing, and the page is told to ask for more.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_factor_goes_only_by_a_sign_in_as_strong_as_the_flow_allows() {
    let plane = Plane::with_actions(&[AdminAction::AccountRead, AdminAction::AccountWrite]).await;
    let bearer = plane.token(&support::claims());
    plane
        .bind_browser_flow(support::PARTY, support::STRONG_FLOW)
        .await;
    plant_app(&plane, "app-one").await;
    let path = own("credentials/app-one");

    prove_sign_in_reaching(&plane, chrono::Utc::now().timestamp(), 1).await;
    let (status, held) = asked(&plane, Method::GET, &own("credentials"), &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert!(held["fresh_until"].is_null(), "{held}");
    assert_eq!(held["stronger_sign_in_needed"], true, "{held}");
    let (status, told) = asked(&plane, Method::DELETE, &path, &bearer, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{told}");
    assert_eq!(
        told["error_code"], "account.stronger_sign_in_required",
        "{told}"
    );

    prove_sign_in_reaching(&plane, chrono::Utc::now().timestamp(), 2).await;
    let (_, held) = asked(&plane, Method::GET, &own("credentials"), &bearer, None).await;
    assert!(held["fresh_until"].is_i64(), "{held}");
    assert_eq!(held["stronger_sign_in_needed"], false, "{held}");
    let (status, told) = asked(&plane, Method::DELETE, &path, &bearer, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
}

/// A step for a factor the person does not hold raises no bar: behind a key
/// step, a person holding no key is asked only for what they can use.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_step_for_a_factor_the_person_lacks_raises_no_bar() {
    let plane = Plane::with_actions(&[AdminAction::AccountWrite]).await;
    let bearer = plane.token(&support::claims());
    plane
        .bind_browser_flow(support::PARTY, support::KEYED_FLOW)
        .await;
    plant_app(&plane, "app-one").await;

    prove_sign_in_reaching(&plane, chrono::Utc::now().timestamp(), 1).await;
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &own("credentials/app-one"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
}

/// The last second factor stays until another takes its place, and a removal
/// reaches nothing the caller does not hold.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_last_second_factor_stays_until_another_takes_its_place() {
    let plane = Plane::with_actions(&[AdminAction::AccountWrite]).await;
    let bearer = plane.token(&support::claims());
    prove_sign_in_at(&plane, chrono::Utc::now().timestamp()).await;

    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &own("credentials/cred-totp"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "account.last_factor", "{told}");

    plant_key(&plane, b"key-one").await;
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &own("credentials/cred-totp"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    let key = data_encoding::BASE64URL_NOPAD.encode(b"key-one");
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &own(&format!("keys/{key}")),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the key left alone was taken: {told}"
    );

    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &own("credentials/not-an-app-of-mine"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
}

/// An account without a password signs in by key, so its last key stays even
/// with an app beside it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_account_without_a_password_keeps_its_last_key() {
    let plane = Plane::with_actions(&[AdminAction::AccountWrite]).await;
    let bearer = plane.token(&support::claims());
    prove_sign_in_at(&plane, chrono::Utc::now().timestamp()).await;
    {
        let transaction = plane.scoped(&within()).await;
        store::providers::directory::credentials::delete_quietly(&transaction, "cred-1")
            .await
            .expect("the credentials table");
        transaction.commit().await.expect("the password gone");
    }
    plant_key(&plane, b"key-one").await;
    plant_app(&plane, "app-one").await;
    let key_one = own(&format!(
        "keys/{}",
        data_encoding::BASE64URL_NOPAD.encode(b"key-one")
    ));

    let (status, told) = asked(&plane, Method::DELETE, &key_one, &bearer, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|why| why.contains("only way")),
        "{told}"
    );

    plant_key(&plane, b"key-two").await;
    let (status, told) = asked(&plane, Method::DELETE, &key_one, &bearer, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let changes = plane.credential_changes_of(support::SUBJECT).await;
    let removal = changes.last().expect("the removal was announced");
    assert_eq!(removal["credential_type"], "webauthn", "{removal}");
    assert_eq!(
        removal["change_type"], "delete",
        "a holder's own key went as something other than a deletion: {removal}"
    );
}

/// The sheet of recovery codes is a way back, not a defence, so it may always
/// go, and it goes whole.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_recovery_sheet_may_always_go() {
    let plane = Plane::with_actions(&[AdminAction::AccountRead, AdminAction::AccountWrite]).await;
    let bearer = plane.token(&support::claims());
    prove_sign_in_at(&plane, chrono::Utc::now().timestamp()).await;
    plant_recovery_codes(&plane).await;

    let before = credential_changes_told(&plane).await;
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &own("recovery-codes"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    assert_eq!(
        credential_changes_told(&plane).await,
        before + 1,
        "the sheet went without one announcement"
    );
    let changes = plane.credential_changes_of(support::SUBJECT).await;
    let removal = changes.last().expect("the removal was announced");
    assert_eq!(removal["credential_type"], "recovery-code", "{removal}");
    assert_eq!(removal["change_type"], "delete", "{removal}");
    let (_, held) = asked(&plane, Method::GET, &own("credentials"), &bearer, None).await;
    assert_eq!(held["recovery_codes"], 0, "{held}");
    assert_eq!(held["apps"][0]["id"], "cred-totp", "{held}");

    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &own("recovery-codes"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
}

/// Reading one's factors and removing them cost their own capabilities.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn reading_and_removing_ones_factors_cost_their_own_capabilities() {
    let reader = Plane::with_actions(&[AdminAction::AccountRead]).await;
    let bearer = reader.token(&support::claims());
    prove_sign_in_at(&reader, chrono::Utc::now().timestamp()).await;
    let (status, told) = asked(
        &reader,
        Method::DELETE,
        &own("recovery-codes"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{told}");
    drop(reader);

    let writer = Plane::with_actions(&[AdminAction::AccountWrite, AdminAction::UserRead]).await;
    let bearer = writer.token(&support::claims());
    let (status, told) = asked(&writer, Method::GET, &own("credentials"), &bearer, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{told}");
}
