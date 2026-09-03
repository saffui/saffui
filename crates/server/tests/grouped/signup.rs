//! The self-registration door: opened by the realm, shaped by the realm, and
//! never a way to read who already exists here.

#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use serde_json::Value;
use server::api::config::register;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;

fn mounted(plane: &Plane) -> server::api::config::Plane {
    server::api::config::Plane {
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

async fn posted(plane: &Plane, body: Value) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let request = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect/signup"))
        .set_json(&body)
        .to_request();
    let response = test::call_service(&app, request).await;
    let status = response.status();
    let body = test::read_body(response).await;
    let told = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, told)
}

async fn reshape_realm(
    plane: &Plane,
    reshape: impl FnOnce(&mut models::entities::realm::RealmModel),
) {
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
    reshape(&mut realm);
    store::providers::realms::update(&transaction, &realm)
        .await
        .expect("the realms table");
    transaction.commit().await.expect("the setting kept");
}

async fn person(plane: &Plane, user_name: &str) -> Option<models::entities::user::UserModel> {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    store::providers::users::load_by_name(&transaction, user_name)
        .await
        .expect("the users table")
}

/// Closed, the door is a page that is not there; open, an account is born
/// carrying what the realm asks of newcomers.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_door_opens_only_where_the_realm_says() {
    let plane = Plane::with_actions(&[]).await;
    let body = serde_json::json!({
        "username": "newcomer",
        "email": "newcomer@acme.test",
        "password": "a-password-of-decent-length",
    });

    let (status, _) = posted(&plane, body.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    reshape_realm(&plane, |realm| {
        realm.registration_allowed = Some(true);
    })
    .await;
    let (status, told) = posted(&plane, body).await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    assert_eq!(told["status"], "registered");
    assert_eq!(told["verify"], false);
    let born = person(&plane, "newcomer").await.expect("a born account");
    assert_eq!(born.email, "newcomer@acme.test");
    assert_eq!(born.email_verified, Some(false));
}

/// A realm registering by address alone keys the account on it, and the
/// name field counts for nothing.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_address_realm_registers_by_address_alone() {
    let plane = Plane::with_actions(&[]).await;
    reshape_realm(&plane, |realm| {
        realm.registration_allowed = Some(true);
        realm.register_email_as_username = Some(true);
    })
    .await;

    let (status, told) = posted(
        &plane,
        serde_json::json!({
            "username": "ignored-entirely",
            "email": "only@acme.test",
            "password": "a-password-of-decent-length",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    assert!(person(&plane, "only@acme.test").await.is_some());
    assert!(person(&plane, "ignored-entirely").await.is_none());
}

/// The verifying realm: a fresh account owes the verification, and a held
/// address answers exactly like a fresh one without bearing a second account.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_verifying_realm_says_one_thing_to_everybody() {
    let plane = Plane::with_actions(&[]).await;
    reshape_realm(&plane, |realm| {
        realm.registration_allowed = Some(true);
        realm.verify_email = Some(true);
    })
    .await;

    let (status, told) = posted(
        &plane,
        serde_json::json!({
            "username": "checked",
            "email": "checked@acme.test",
            "password": "a-password-of-decent-length",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    assert_eq!(told["verify"], true);
    let born = person(&plane, "checked").await.expect("a born account");
    assert!(
        born.required_actions
            .unwrap_or_default()
            .contains(&models::entities::user::RequiredAction::VerifyEmail),
        "the verification was not owed"
    );

    // The same address again: the same sentence, and nobody new.
    let (status, again) = posted(
        &plane,
        serde_json::json!({
            "username": "impostor",
            "email": "checked@acme.test",
            "password": "a-password-of-decent-length",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{again}");
    assert_eq!(again["status"], "registered");
    assert_eq!(again["verify"], true);
    assert!(
        person(&plane, "impostor").await.is_none(),
        "a second account was born"
    );
}

/// Where nothing is verified, refusals speak: a taken name, a held address,
/// a password the policy refuses.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn refusals_speak_where_speaking_cannot_enumerate() {
    let plane = Plane::with_actions(&[]).await;
    reshape_realm(&plane, |realm| {
        realm.registration_allowed = Some(true);
        realm.password_policy = Some(models::entities::realm::PasswordPolicy {
            min_length: Some(12),
            ..Default::default()
        });
    })
    .await;

    let (_, _) = posted(
        &plane,
        serde_json::json!({
            "username": "holder",
            "email": "holder@acme.test",
            "password": "a-password-of-decent-length",
        }),
    )
    .await;

    let (status, told) = posted(
        &plane,
        serde_json::json!({
            "username": "holder",
            "email": "other@acme.test",
            "password": "a-password-of-decent-length",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["reason"], "this name is taken");

    let (status, told) = posted(
        &plane,
        serde_json::json!({
            "username": "another",
            "email": "holder@acme.test",
            "password": "a-password-of-decent-length",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["reason"], "an account already uses this address");

    let (status, told) = posted(
        &plane,
        serde_json::json!({
            "username": "hasty",
            "email": "hasty@acme.test",
            "password": "short",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["reason"], "the password is too short");
}
