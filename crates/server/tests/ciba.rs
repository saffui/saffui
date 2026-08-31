mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use data_encoding::BASE64;
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;
use support::Plane;

const REALM: &str = support::REALM;
const GRANT: &str = "urn:openid:params:grant-type:ciba";

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

async fn posted(plane: &Plane, path: &str, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect{path}"))
            .insert_header(("authorization", format!("Basic {encoded}")))
            .set_form(form)
            .to_request(),
    )
    .await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn as_person(
    plane: &Plane,
    method: actix_web::http::Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asking = test::TestRequest::default()
        .method(method)
        .uri(&format!("/realms/{REALM}/protocol/openid-connect{path}"))
        .insert_header(("authorization", format!("Bearer {bearer}")));
    if let Some(body) = body {
        asking = asking.set_json(body);
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn opted_in(plane: &Plane) {
    use models::entities::attributes::AttributeValue;
    use store::tenancy::TenantContext;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
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

fn ada_bearer(plane: &Plane) -> String {
    plane.token(&support::claims())
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_counter_signs_ada_in_from_her_own_device() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead]).await;

    // No opt-in yet: the counter has no such window.
    let (status, told) = posted(
        &plane,
        "/bc-authorize",
        &[("scope", "openid"), ("login_hint", support::SUBJECT)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "unauthorized_client", "{told}");

    opted_in(&plane).await;

    // Two hints are refused; one opens the request.
    let (status, told) = posted(
        &plane,
        "/bc-authorize",
        &[("login_hint", support::SUBJECT), ("id_token_hint", "x.y.z")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");

    let (status, opened) = posted(
        &plane,
        "/bc-authorize",
        &[
            ("scope", "openid profile"),
            ("login_hint", support::SUBJECT_EMAIL),
            ("binding_message", "Virement 240 EUR - code 7G2"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let auth_req_id = opened["auth_req_id"]
        .as_str()
        .expect("a request id")
        .to_owned();
    assert_eq!(opened["interval"], 5, "{opened}");

    // Polling straight away is told to slow down; after the interval it is
    // told nobody has decided.
    let (status, told) = posted(
        &plane,
        "/token",
        &[("grant_type", GRANT), ("auth_req_id", &auth_req_id)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "authorization_pending", "{told}");
    let (_, told) = posted(
        &plane,
        "/token",
        &[("grant_type", GRANT), ("auth_req_id", &auth_req_id)],
    )
    .await;
    assert_eq!(told["error"], "slow_down", "{told}");

    // Ada sees the request on her own device, binding message included.
    let bearer = ada_bearer(&plane);
    let (status, pending) = as_person(
        &plane,
        actix_web::http::Method::GET,
        "/bc-pending",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    let shown = &pending["pending"][0];
    assert_eq!(shown["client_id"], support::CONFIDENTIAL, "{pending}");
    assert_eq!(shown["binding_message"], "Virement 240 EUR - code 7G2");
    let handle = shown["request"].as_str().expect("a handle").to_owned();

    // Grace cannot decide ada's request: the refusal wears one face.
    plane.plant_shadow("grace", "any-password-here").await;
    let grace = {
        let mut payload = support::claims();
        payload.set_subject("grace");
        plane.token(&payload)
    };
    let (status, told) = as_person(
        &plane,
        actix_web::http::Method::POST,
        "/bc-decide",
        &grace,
        Some(json!({ "request": handle, "decision": "approve" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");

    // Ada approves.
    let (status, told) = as_person(
        &plane,
        actix_web::http::Method::POST,
        "/bc-decide",
        &bearer,
        Some(json!({ "request": handle, "decision": "approve" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    // The next poll collects: real tokens, a real session behind them.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let (status, minted) = posted(
        &plane,
        "/token",
        &[("grant_type", GRANT), ("auth_req_id", &auth_req_id)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    let claims = plane
        .claims_of(minted["access_token"].as_str().expect("a token"))
        .await;
    assert_eq!(claims["sub"], support::SUBJECT, "{claims}");
    let sid = claims["sid"].as_str().expect("a session id").to_owned();
    assert!(plane.session_exists(&sid).await, "no session stands behind");
    let id_claims = plane
        .claims_of(minted["id_token"].as_str().expect("an id token"))
        .await;
    assert_eq!(id_claims["sub"], support::SUBJECT, "{id_claims}");
    assert!(id_claims["auth_time"].is_i64(), "{id_claims}");
    assert!(minted["refresh_token"].is_string(), "{minted}");

    // Collected once: the same auth_req_id is gone.
    let (status, told) = posted(
        &plane,
        "/token",
        &[("grant_type", GRANT), ("auth_req_id", &auth_req_id)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "invalid_grant", "{told}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_refusal_an_expiry_and_a_ghost_all_answer_their_own_words() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead]).await;
    opted_in(&plane).await;
    let bearer = ada_bearer(&plane);

    // Denied.
    let (_, opened) = posted(&plane, "/bc-authorize", &[("login_hint", support::SUBJECT)]).await;
    let denied_id = opened["auth_req_id"].as_str().expect("an id").to_owned();
    let (_, pending) = as_person(
        &plane,
        actix_web::http::Method::GET,
        "/bc-pending",
        &bearer,
        None,
    )
    .await;
    let handle = pending["pending"][0]["request"]
        .as_str()
        .expect("a handle")
        .to_owned();
    let (status, _) = as_person(
        &plane,
        actix_web::http::Method::POST,
        "/bc-decide",
        &bearer,
        Some(json!({ "request": handle, "decision": "deny" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, told) = posted(
        &plane,
        "/token",
        &[("grant_type", GRANT), ("auth_req_id", &denied_id)],
    )
    .await;
    assert_eq!(told["error"], "access_denied", "{told}");

    // Expired: a one-second window, waited out.
    let (_, opened) = posted(
        &plane,
        "/bc-authorize",
        &[("login_hint", support::SUBJECT), ("requested_expiry", "1")],
    )
    .await;
    let brief = opened["auth_req_id"].as_str().expect("an id").to_owned();
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let (_, told) = posted(
        &plane,
        "/token",
        &[("grant_type", GRANT), ("auth_req_id", &brief)],
    )
    .await;
    assert_eq!(told["error"], "expired_token", "{told}");

    // A ghost: an unknown hint answers exactly like a known one, pends the
    // same, and shows up on nobody's device.
    let (status, opened) = posted(&plane, "/bc-authorize", &[("login_hint", "nobody-here")]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unknown hint was told apart: {opened}"
    );
    let ghost = opened["auth_req_id"].as_str().expect("an id").to_owned();
    let (_, told) = posted(
        &plane,
        "/token",
        &[("grant_type", GRANT), ("auth_req_id", &ghost)],
    )
    .await;
    assert_eq!(told["error"], "authorization_pending", "{told}");
    let (_, pending) = as_person(
        &plane,
        actix_web::http::Method::GET,
        "/bc-pending",
        &bearer,
        None,
    )
    .await;
    assert!(
        pending["pending"].as_array().is_some_and(|held| held
            .iter()
            .all(|entry| entry["client_id"].is_string() && entry["binding_message"].is_null())),
        "the ghost leaked somewhere: {pending}"
    );

    // Discovery names the door and its one delivery mode.
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/realms/{REALM}/.well-known/openid-configuration"))
            .to_request(),
    )
    .await;
    let discovery: Value = test::read_body_json(response).await;
    assert!(
        discovery["backchannel_authentication_endpoint"]
            .as_str()
            .is_some_and(|held| held.ends_with("/bc-authorize")),
        "{discovery}"
    );
    assert_eq!(
        discovery["backchannel_token_delivery_modes_supported"],
        json!(["poll"]),
        "{discovery}"
    );
    assert!(
        discovery["grant_types_supported"]
            .as_array()
            .is_some_and(|held| held.iter().any(|grant| grant == GRANT)),
        "{discovery}"
    );
}
