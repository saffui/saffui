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

async fn pending_actions(plane: &Plane) -> Vec<RequiredAction> {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    store::providers::users::load(&transaction, support::SUBJECT)
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
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
        store::providers::users::require_action(
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

/// The realm's policy speaks here as at every other door, and a refused
/// replacement leaves the password and every login as they were.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_replacement_the_realm_refuses_changes_nothing() {
    let plane = Plane::with_actions(&[AdminAction::AccountWrite]).await;
    let bearer = plane.token(&support::claims());
    {
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
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
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
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
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
        transaction
            .execute(
                "UPDATE users SET user_storage = 'local' WHERE user_id = $1",
                &[&support::SUBJECT],
            )
            .await
            .expect("the users table");
        store::providers::credentials::delete_quietly(&transaction, "cred-1")
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
