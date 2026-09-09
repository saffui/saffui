#[allow(unused_imports)]
use super::support;
use super::support::{Plane, Postbox};
use actix_web::http::StatusCode;
use actix_web::{App, test};
use models::compliance::subject_request::Jurisdiction;
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
        ceiling: support::ceiling(),
        egress: config::serving::Egress::Outward,
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, support::REALM)
}

async fn open_door(plane: &Plane, jurisdiction: Jurisdiction, days: Option<i32>) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let mut realm = store::providers::realms::load(&transaction, support::REALM)
        .await
        .expect("the realms table")
        .expect("a planted realm");
    realm.dsar_jurisdiction = Some(jurisdiction);
    realm.dsar_response_days = days;
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

async fn asked(plane: &Plane, postbox: &Postbox, named: &str, kind: &str) -> StatusCode {
    let app =
        test::init_service(App::new().configure(register(&mounted(plane, Some(postbox))))).await;
    test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/privacy-request",
                support::REALM
            ))
            .set_json(serde_json::json!({ "username": named, "kind": kind }))
            .to_request(),
    )
    .await
    .status()
}

async fn confirmed(plane: &Plane, token: &str, user: &str, kind: &str) -> (StatusCode, String) {
    let app = test::init_service(App::new().configure(register(&mounted(plane, None)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/privacy-confirm",
                support::REALM
            ))
            .set_form(serde_json::json!({ "token": token, "user": user, "kind": kind }))
            .to_request(),
    )
    .await;
    let status = response.status();
    let body = String::from_utf8_lossy(&test::read_body(response).await).into_owned();
    (status, body)
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

async fn register_rows(plane: &Plane) -> Vec<(String, String, i64, i64)> {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    transaction
        .query(
            "SELECT kind, stage, received_at, due_at FROM subject_requests ORDER BY received_at",
            &[],
        )
        .await
        .expect("the register read")
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect()
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_confirmed_ask_lands_verified_with_the_laws_clock() {
    let plane = Plane::with_actions(&[]).await;
    open_door(&plane, Jurisdiction::Eu, None).await;
    arrange_mail(&plane).await;
    let postbox = Postbox::default();

    assert_eq!(
        asked(&plane, &postbox, support::SUBJECT, "access").await,
        StatusCode::ACCEPTED
    );
    let held = postbox.held();
    assert_eq!(held.len(), 1, "{held:?}");
    let token = token_in(&held[0].body);

    // The landing page is a page, not the act: a scanner following the GET
    // must leave the register exactly as it found it.
    let app = test::init_service(App::new().configure(register(&mounted(&plane, None)))).await;
    let landing = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/privacy-confirm?token={token}&user={}&kind=access",
                support::REALM,
                support::SUBJECT
            ))
            .to_request(),
    )
    .await;
    assert_eq!(landing.status(), StatusCode::OK);
    assert!(
        register_rows(&plane).await.is_empty(),
        "opening the link lodged a request before anybody confirmed it"
    );

    let (status, body) = confirmed(&plane, &token, support::SUBJECT, "access").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Request received"), "{body}");

    let rows = register_rows(&plane).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (kind, stage, received, due) = &rows[0];
    assert_eq!(kind, "access");
    assert_eq!(
        stage, "verified",
        "the mail round-trip is the identity proof; the row must not wait for another"
    );
    assert_eq!(due - received, 30 * 86_400, "the EU clock is thirty days");

    // Spent: the same link a second time buys nothing, and lodges nothing.
    let (status, body) = confirmed(&plane, &token, support::SUBJECT, "access").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("no longer works"), "{body}");
    assert_eq!(register_rows(&plane).await.len(), 1);
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_realms_own_window_beats_the_laws() {
    let plane = Plane::with_actions(&[]).await;
    open_door(&plane, Jurisdiction::Nigeria, Some(10)).await;
    arrange_mail(&plane).await;
    let postbox = Postbox::default();

    asked(&plane, &postbox, support::SUBJECT, "erasure").await;
    let token = token_in(&postbox.held()[0].body);
    let (status, body) = confirmed(&plane, &token, support::SUBJECT, "erasure").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let rows = register_rows(&plane).await;
    let (kind, _, received, due) = &rows[0];
    assert_eq!(kind, "erasure");
    assert_eq!(
        due - received,
        10 * 86_400,
        "Nigeria fixes no window; the realm's ten days must be the clock"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_name_nobody_holds_is_answered_the_same_way() {
    let plane = Plane::with_actions(&[]).await;
    open_door(&plane, Jurisdiction::Eu, None).await;
    arrange_mail(&plane).await;
    let postbox = Postbox::default();

    assert_eq!(
        asked(&plane, &postbox, "nobody-by-that-name", "erasure").await,
        StatusCode::ACCEPTED,
        "a name nobody holds was answered differently"
    );
    assert!(
        postbox.held().is_empty(),
        "a message went to a name nobody holds"
    );
    assert!(
        register_rows(&plane).await.is_empty(),
        "an unconfirmed ask grew the register"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn asking_twice_inside_the_cooldown_mails_once() {
    let plane = Plane::with_actions(&[]).await;
    open_door(&plane, Jurisdiction::Eu, None).await;
    arrange_mail(&plane).await;
    let postbox = Postbox::default();

    asked(&plane, &postbox, support::SUBJECT, "access").await;
    assert_eq!(
        asked(&plane, &postbox, support::SUBJECT, "access").await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        postbox.held().len(),
        1,
        "the second ask inside the cooldown went out anyway"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_without_the_door_says_so() {
    let plane = Plane::with_actions(&[]).await;
    arrange_mail(&plane).await;
    let postbox = Postbox::default();

    assert_eq!(
        asked(&plane, &postbox, support::SUBJECT, "access").await,
        StatusCode::NOT_FOUND
    );
    assert!(postbox.held().is_empty());

    let (status, _) = confirmed(&plane, "whatever", support::SUBJECT, "access").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
