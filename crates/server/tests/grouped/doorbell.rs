#[allow(unused_imports)]
use super::support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use data_encoding::BASE64;
use models::entities::attributes::AttributeValue;
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;
use super::support::Plane;

const REALM: &str = support::REALM;
const SSO_COOKIE: &str = server::api::rest::endpoints::protocol::binding::SSO_SESSION;

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
        sealing: support::sealing(),
        egress: config::serving::Egress::Outward,
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, REALM)
}

async fn opted_in(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
        .await
        .unwrap()
        .expect("the client");
    client.configs.get_or_insert_with(Default::default).insert(
        "ciba.delivery_mode".to_owned(),
        AttributeValue::Str("poll".to_owned()),
    );
    assert!(
        store::providers::clients::update(&transaction, &client)
            .await
            .unwrap()
    );
    transaction.commit().await.unwrap();
}

/// A live browser login for ada, whose id is what the SSO cookie carries.
async fn signed_in_session(plane: &Plane) -> String {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let session_id = "a-browser-session".to_owned();
    store::providers::sessions::open(
        &transaction,
        &models::sessions::records::UserSessionModel {
            browser_state: None,
            tenant: support::TENANT.into(),
            session_id: session_id.clone(),
            realm_id: REALM.into(),
            user_id: support::SUBJECT.into(),
            login_username: support::SUBJECT.into(),
            broker_session_id: None,
            broker_user_id: None,
            auth_method: None,
            ip_address: None,
            user_agent: None,
            started_at: chrono::Utc::now().timestamp(),
            auth_time: Some(chrono::Utc::now().timestamp()),
            loa: None,
            expiration: Some(chrono::Utc::now().timestamp() + 3600),
            state: models::sessions::records::UserSessionState::LoggedIn,
            remember_me: None,
            last_session_refresh: None,
            is_offline: None,
            notes: None,
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    session_id
}

async fn posted(plane: &Plane, path: &str, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let request = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect{path}"))
        .insert_header(("authorization", format!("Basic {encoded}")))
        .set_form(form)
        .to_request();
    let response = test::call_service(&app, request).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

/// The doorbell rings for the browser's own login: the page is served, the
/// pending listing and the decision ride the SSO cookie, and the counter's
/// poll collects what the person approved. A visitor with neither bearer nor
/// login is told to sign in, and learns nothing else.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_doorbell_answers_to_the_signed_in_browser() {
    let plane = Plane::with_actions(&[]).await;
    opted_in(&plane).await;

    let (status, opened) = posted(
        &plane,
        "/bc-authorize",
        &[
            ("scope", "openid"),
            ("login_hint", support::SUBJECT),
            ("binding_message", "till 4"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let auth_req_id = opened["auth_req_id"].as_str().expect("an id").to_owned();

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/requests"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = String::from_utf8(test::read_body(response).await.to_vec()).expect("a page");
    assert!(page.contains("Waiting requests"), "{page:.200}");

    // Nobody signed in: the listing refuses, and says nothing more.
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/bc-pending"
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // The signed-in browser sees what waits, and approves it.
    let session = signed_in_session(&plane).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/bc-pending"
            ))
            .insert_header(("cookie", format!("{SSO_COOKIE}={session}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let told: Value = test::read_body_json(response).await;
    let pending = told["pending"].as_array().expect("a listing");
    assert_eq!(pending.len(), 1, "{told}");
    assert_eq!(pending[0]["binding_message"], "till 4", "{told}");
    let request_digest = pending[0]["request"].as_str().expect("a digest").to_owned();

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/bc-decide"
            ))
            .insert_header(("cookie", format!("{SSO_COOKIE}={session}")))
            .set_json(serde_json::json!({ "request": request_digest, "decision": "approve" }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // The shelf is empty now, and the counter's poll collects.
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/bc-pending"
            ))
            .insert_header(("cookie", format!("{SSO_COOKIE}={session}")))
            .to_request(),
    )
    .await;
    let told: Value = test::read_body_json(response).await;
    assert_eq!(told["pending"].as_array().map(Vec::len), Some(0), "{told}");

    let (status, granted) = posted(
        &plane,
        "/token",
        &[
            ("grant_type", "urn:openid:params:grant-type:ciba"),
            ("auth_req_id", &auth_req_id),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{granted}");
    assert!(granted["access_token"].is_string(), "{granted}");
}
