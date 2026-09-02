mod support;

use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::Value;
use support::Plane;

/// Ask the plane, with a body or without one.
async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    use actix_web::{App, test};
    use server::api::config::register;
    use server::middleware::admin_policy::AdminPolicy;
    let app = test::init_service(App::new().configure(register(&server::api::config::Plane {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    })))
    .await;
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

/// A realm is born ready or not at all: the row, the standard scopes, this
/// deployment's console and a signing key arrive together, a second create
/// is a conflict, and the switches are rewritten in place afterwards.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_is_created_ready_and_reshaped_in_place() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmCreate,
        AdminAction::RealmWrite,
        AdminAction::RealmRead,
        AdminAction::ClientRead,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    // A name that will not survive a URL is refused before anything is made.
    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(serde_json::json!({ "name": "no spaces", "display_name": "x", "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, born) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(serde_json::json!({ "name": "staging", "display_name": "Staging", "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    assert_eq!(born["name"], "staging", "{born}");

    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(serde_json::json!({ "name": "staging", "display_name": "Again", "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    // Born ready: the standard scopes and the admin scope are in place, and
    // the deployment's console is registered and pointed at this server.
    let (status, scopes) = asked(
        &plane,
        Method::GET,
        "/admin/realms/staging/client-scopes",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{scopes}");
    let names: Vec<&str> = scopes
        .as_array()
        .expect("a scope catalogue")
        .iter()
        .filter_map(|held| held["name"].as_str())
        .collect();
    for wanted in ["profile", "email", "offline_access", support::SCOPE] {
        assert!(names.contains(&wanted), "{wanted} missing from {names:?}");
    }

    let (status, console) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/staging/clients/{}", support::PARTY),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{console}");

    // Reshaped: the mentioned switches move, the name does not.
    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({
            "display_name": "Staging ground",
            "access_token_lifespan": 600,
            "require_pushed_authorization_requests": true,
            "registration_bounds": {
                "max_clients": 5,
                "requires_consent": true,
                "trusted_hosts": ["apps.test"]
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["name"], "staging", "{shaped}");
    assert_eq!(shaped["display_name"], "Staging ground", "{shaped}");
    assert_eq!(shaped["access_token_lifespan"], 600, "{shaped}");
    assert_eq!(shaped["require_pushed_authorization_requests"], true);
    assert_eq!(shaped["registration_bounds"]["max_clients"], 5, "{shaped}");

    let (status, read) = asked(
        &plane,
        Method::GET,
        "/admin/realms/staging?briefRepresentation=false",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(read["access_token_lifespan"], 600, "{read}");
    assert_eq!(read["display_name"], "Staging ground", "{read}");

    // Reshaping what does not exist is not creating it.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/nowhere",
        &bearer,
        Some(serde_json::json!({ "display_name": "ghost" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
}
