#[allow(unused_imports)]
use super::support;
use super::support::{Plane, Postbox};
use actix_web::http::StatusCode;
use actix_web::{App, test};
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;

fn mounted(plane: &Plane, postbox: Option<&Postbox>) -> Mounted {
    let mut sealing = support::sealing();
    sealing.sender = postbox.map(|held| {
        std::sync::Arc::new(held.clone()) as std::sync::Arc<dyn auth::messaging::Deliver>
    });
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
        sealing,
        egress: config::serving::Egress::Outward,
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, support::REALM)
}

async fn allow_reset(plane: &Plane, allowed: bool) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let mut realm = store::providers::realms::load(&transaction, support::REALM)
        .await
        .expect("the realms table")
        .expect("a planted realm");
    realm.reset_password_allowed = Some(allowed);
    store::providers::realms::update(&transaction, &realm)
        .await
        .expect("the realms table");
    transaction.commit().await.expect("the setting kept");
}

async fn arrange_mail(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let sealing = support::sealing();
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        support::TENANT,
        support::REALM,
    )
    .await
    .expect("a keyring");
    store::providers::mail::keep(
        &transaction,
        &ring,
        &sealing.envelope,
        &models::entities::mail::MailSettings {
            host: "mail.example.test".into(),
            port: 587,
            from_address: "no-reply@example.test".into(),
            from_name: "saffui".into(),
            reply_to: None,
            implicit_tls: false,
            credentials: None,
        },
    )
    .await
    .expect("the mail settings kept");
    transaction.commit().await.expect("the settings kept");
}

async fn asked_for_link(plane: &Plane, postbox: &Postbox, named: &str) -> StatusCode {
    let app =
        test::init_service(App::new().configure(register(&mounted(plane, Some(postbox))))).await;
    test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/forgot-password",
                support::REALM
            ))
            .set_json(serde_json::json!({ "username": named }))
            .to_request(),
    )
    .await
    .status()
}

async fn set_password(
    plane: &Plane,
    token: &str,
    user: &str,
    password: &str,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane, None)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/reset-password",
                support::REALM
            ))
            .set_json(serde_json::json!({
                "token": token, "user": user, "password": password,
            }))
            .to_request(),
    )
    .await;
    let status = response.status();
    let body = test::read_body(response).await;
    let told = serde_json::from_slice(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
    (status, told)
}

fn token_in(body: &str) -> String {
    body.split("token=")
        .nth(1)
        .expect("a token")
        .split('&')
        .next()
        .expect("a token")
        .to_owned()
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_link_sets_a_password_and_ends_every_session() {
    let plane = Plane::with_actions(&[]).await;
    allow_reset(&plane, true).await;
    arrange_mail(&plane).await;
    let postbox = Postbox::default();

    assert_eq!(
        asked_for_link(&plane, &postbox, support::SUBJECT).await,
        StatusCode::ACCEPTED
    );
    let held = postbox.held();
    assert_eq!(held.len(), 1, "{held:?}");
    let token = token_in(&held[0].body);

    let (status, body) =
        set_password(&plane, &token, support::SUBJECT, "a-brand-new-password").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Spent: the same link a second time buys nothing.
    let (status, body) = set_password(&plane, &token, support::SUBJECT, "another-one-again").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["status"].as_str(), Some("no-such-link"), "{body}");

    // Somebody resetting is often somebody whose old password is known to
    // another person, and that person's session must not survive it.
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let left: i64 = transaction
        .query_one(
            "SELECT count(*) FROM user_sessions WHERE user_id = $1",
            &[&support::SUBJECT],
        )
        .await
        .expect("a count")
        .get(0);
    assert_eq!(
        left, 0,
        "a session outlived the reset that was meant to end it"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_name_nobody_holds_is_answered_the_same_way() {
    let plane = Plane::with_actions(&[]).await;
    allow_reset(&plane, true).await;
    arrange_mail(&plane).await;
    let postbox = Postbox::default();

    assert_eq!(
        asked_for_link(&plane, &postbox, "nobody-by-that-name").await,
        StatusCode::ACCEPTED,
        "a name nobody holds was answered differently"
    );
    assert!(
        postbox.held().is_empty(),
        "a message went to a name nobody holds"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_that_does_not_offer_it_says_so() {
    let plane = Plane::with_actions(&[]).await;
    arrange_mail(&plane).await;
    let postbox = Postbox::default();
    assert_eq!(
        asked_for_link(&plane, &postbox, support::SUBJECT).await,
        StatusCode::NOT_FOUND
    );
    assert!(postbox.held().is_empty());
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_password_the_policy_refuses_does_not_cost_the_link() {
    let plane = Plane::with_actions(&[]).await;
    allow_reset(&plane, true).await;
    arrange_mail(&plane).await;
    demand_length(&plane, 12).await;
    let postbox = Postbox::default();

    asked_for_link(&plane, &postbox, support::SUBJECT).await;
    let token = token_in(&postbox.held()[0].body);

    let (status, body) = set_password(&plane, &token, support::SUBJECT, "short").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["status"].as_str(), Some("refused"), "{body}");

    // The link survived, because the policy is read before it is spent.
    let (status, body) =
        set_password(&plane, &token, support::SUBJECT, "long-enough-for-this").await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a refused password cost the link: {body}"
    );
}

async fn demand_length(plane: &Plane, least: i64) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let mut realm = store::providers::realms::load(&transaction, support::REALM)
        .await
        .expect("the realms table")
        .expect("a planted realm");
    realm.password_policy = Some(models::entities::realm::PasswordPolicy {
        min_length: Some(least),
        ..models::entities::realm::PasswordPolicy::default()
    });
    store::providers::realms::update(&transaction, &realm)
        .await
        .expect("the realms table");
    transaction.commit().await.expect("the policy kept");
}
