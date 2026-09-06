#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;

fn mounted(plane: &Plane, egress: config::serving::Egress) -> Mounted {
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
        egress,
        sealing: support::sealing(),
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, support::REALM)
}

async fn put_settings(
    plane: &Plane,
    bearer: &str,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let app = test::init_service(
        App::new().configure(register(&mounted(plane, config::serving::Egress::Outward))),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::put()
            .uri(&format!("/admin/realms/{}/sms", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .set_json(body)
            .to_request(),
    )
    .await;
    let status = response.status();
    let body = String::from_utf8_lossy(&test::read_body(response).await).into_owned();
    (status, body)
}

async fn held_settings(plane: &Plane) -> Option<models::entities::sms::SmsSettings> {
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
    store::providers::sms::load(&transaction, &ring, &sealing.envelope)
        .await
        .expect("the settings read")
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_sms_token_is_sealed_and_never_answered_with() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());

    let (status, told) = put_settings(
        &plane,
        &bearer,
        serde_json::json!({
            "url": "https://gateway.example/send",
            "sender": "saffui",
            "token": "an-sms-token",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let held: Vec<u8> = transaction
        .query_one("SELECT sealed_token FROM realm_sms", &[])
        .await
        .expect("the settings")
        .get(0);
    assert!(
        !String::from_utf8_lossy(&held).contains("an-sms-token"),
        "the token is readable in the column"
    );
    drop(transaction);
    drop(connection);

    let app = test::init_service(
        App::new().configure(register(&mounted(&plane, config::serving::Egress::Outward))),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/admin/realms/{}/sms", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let shown = String::from_utf8(test::read_body(response).await.to_vec()).expect("a body");
    assert!(
        !shown.contains("an-sms-token") && !shown.contains("token\":\""),
        "the plane answered with a token: {shown}"
    );
    assert!(shown.contains("\"has_token\":true"), "{shown}");
}

/// Writing without one keeps the one held; writing an empty one forgets it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_is_kept_by_silence_and_forgotten_by_a_blank() {
    let plane = Plane::with_actions(&[AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());

    put_settings(
        &plane,
        &bearer,
        serde_json::json!({
            "url": "https://gateway.example/send",
            "sender": "saffui",
            "token": "an-sms-token",
        }),
    )
    .await;
    let (status, told) = put_settings(
        &plane,
        &bearer,
        serde_json::json!({ "url": "https://gateway2.example/send", "sender": "acme" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let held = held_settings(&plane).await.expect("settings");
    assert_eq!(held.url, "https://gateway2.example/send");
    assert_eq!(
        secrecy::ExposeSecret::expose_secret(held.token.as_ref().expect("token kept")),
        "an-sms-token",
        "the token was blanked by an edit that did not name one"
    );

    let (status, _) = put_settings(
        &plane,
        &bearer,
        serde_json::json!({
            "url": "https://gateway2.example/send",
            "sender": "acme",
            "token": "",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let held = held_settings(&plane).await.expect("settings");
    assert!(held.token.is_none(), "an empty token was kept");
}

/// The gateway URL has to be somewhere the server can post.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_gateway_that_is_not_http_is_refused() {
    let plane = Plane::with_actions(&[AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let (status, told) = put_settings(
        &plane,
        &bearer,
        serde_json::json!({ "url": "gopher://gateway.example", "sender": "saffui" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(told.contains("http"), "{told}");
}

/// Forgetting removes the row; a realm that holds nothing says so.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn forgetting_removes_the_settings_and_absence_says_so() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let app = test::init_service(
        App::new().configure(register(&mounted(&plane, config::serving::Egress::Outward))),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/admin/realms/{}/sms", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    put_settings(
        &plane,
        &bearer,
        serde_json::json!({ "url": "https://gateway.example/send", "sender": "saffui" }),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri(&format!("/admin/realms/{}/sms", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(held_settings(&plane).await.is_none(), "the row survived");

    let response = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri(&format!("/admin/realms/{}/sms", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .to_request(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "forgetting nothing pretended to have forgotten something"
    );
}

/// The test text drives the realm's own gateway and speaks the refusal.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_test_text_wants_a_number_and_speaks_the_gateways_refusal() {
    let plane = Plane::with_actions(&[AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let app = test::init_service(
        App::new().configure(register(&mounted(&plane, config::serving::Egress::Outward))),
    )
    .await;

    let asked = |to: &str| {
        test::TestRequest::post()
            .uri(&format!("/admin/realms/{}/sms/test", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .set_json(serde_json::json!({ "to": to }))
            .to_request()
    };

    let response = test::call_service(&app, asked("0790123456")).await;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a national-form number was accepted"
    );

    let response = test::call_service(&app, asked("+22890123456")).await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a test went out with no settings held"
    );

    // A gateway nothing listens on: the refusal is immediate and spoken.
    // Dialled under the anywhere policy, since the address is the point.
    let anywhere = test::init_service(App::new().configure(register(&mounted(
        &plane,
        config::serving::Egress::Anywhere,
    ))))
    .await;
    let response = test::call_service(
        &anywhere,
        test::TestRequest::put()
            .uri(&format!("/admin/realms/{}/sms", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .set_json(serde_json::json!({ "url": "http://127.0.0.1:9/send", "sender": "saffui" }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = test::call_service(&anywhere, asked("+22890123456")).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let told = String::from_utf8_lossy(&test::read_body(response).await).into_owned();
    assert!(told.contains("gateway refused"), "{told}");
}

/// An outward deployment neither writes a cleartext gateway nor dials its
/// own network, and the second refusal is the resolver's: the address is
/// judged when the name is resolved, not when it was written.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_outward_deployment_keeps_the_dial_outside() {
    let plane = Plane::with_actions(&[AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());

    let (status, told) = put_settings(
        &plane,
        &bearer,
        serde_json::json!({ "url": "http://gateway.example/send", "sender": "saffui" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(told.contains("only over https"), "{told}");

    // The write takes the name; the dial refuses where it points. A live
    // listener tells refusal-at-resolution apart from a failed connection:
    // the address must be turned away before a single packet reaches it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a local ear");
    listener.set_nonblocking(true).expect("a patient ear");
    let port = listener.local_addr().expect("an address").port();
    let (status, told) = put_settings(
        &plane,
        &bearer,
        serde_json::json!({ "url": format!("https://127.0.0.1:{port}/send"), "sender": "saffui" }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    let app = test::init_service(
        App::new().configure(register(&mounted(&plane, config::serving::Egress::Outward))),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/admin/realms/{}/sms/test", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .set_json(serde_json::json!({ "to": "+22890123456" }))
            .to_request(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a dial reached inside the deployment"
    );
    assert!(
        matches!(listener.accept(), Err(why) if why.kind() == std::io::ErrorKind::WouldBlock),
        "a connection reached an address inside the deployment"
    );
}
