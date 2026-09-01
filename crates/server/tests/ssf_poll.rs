mod support;

use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;
use support::Plane;

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
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn walked(plane: &Plane) {
    server::jobs::deliver_every_realm(
        &plane.pool(),
        &plane.tenancy(),
        &support::sealing(),
        &support::origin(),
        1,
    )
    .await;
}

/// A collector's whole visit: subscribe by row, let the walker queue what
/// happened, come by with the sealed bearer, take the token, acknowledge it,
/// and find the shelf empty. A stranger's bearer is nobody.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_collector_takes_its_events_and_acknowledges_them() {
    let plane = Plane::with_actions(&[
        AdminAction::IdpRead,
        AdminAction::IdpWrite,
        AdminAction::UserRead,
        AdminAction::UserWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    walked(&plane).await;

    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        Some(json!({
            "provider_id": "the-collector",
            "name": "the-collector",
            "display_name": "", "description": "", "trust_email": false,
            "configs": {
                "kind": { "Str": "caep-push" },
                "delivery": { "Str": "poll" },
                "audience": { "Str": "https://collector.example" },
                "bearer": { "Str": "collector-secret" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");

    // A second login for ada, revoked by the admin: something to collect.
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::sessions::open(
            &transaction,
            &models::sessions::records::UserSessionModel {
                browser_state: None,
                tenant: support::TENANT.into(),
                session_id: "session-2".into(),
                realm_id: REALM.into(),
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
    }
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!(
            "/admin/realms/{REALM}/users/{}/sessions/session-2",
            support::SUBJECT
        ),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    walked(&plane).await;

    // A stranger's bearer collects nothing, and learns nothing.
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/realms/{REALM}/ssf/poll"),
        "not-the-collector",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The collector takes its token, verified against the realm's own keys.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/realms/{REALM}/ssf/poll"),
        "collector-secret",
        Some(json!({ "maxEvents": 10 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let sets = told["sets"].as_object().expect("a sets object");
    assert_eq!(sets.len(), 1, "{told}");
    assert_eq!(told["moreAvailable"], false, "{told}");
    let (jti, set) = sets.iter().next().expect("one set");
    let claims = plane.claims_of(set.as_str().expect("a token")).await;
    assert_eq!(claims["aud"], "https://collector.example", "{claims}");
    assert!(
        claims["events"]["https://schemas.openid.net/secevent/caep/event-type/session-revoked"]
            .is_object(),
        "{claims}"
    );
    assert_eq!(claims["jti"], jti.as_str(), "{claims}");

    // Not acknowledged, it waits; acknowledged, it is gone.
    let (_, again) = asked(
        &plane,
        Method::POST,
        &format!("/realms/{REALM}/ssf/poll"),
        "collector-secret",
        Some(json!({})),
    )
    .await;
    assert_eq!(
        again["sets"].as_object().map(serde_json::Map::len),
        Some(1),
        "{again}"
    );
    let (status, emptied) = asked(
        &plane,
        Method::POST,
        &format!("/realms/{REALM}/ssf/poll"),
        "collector-secret",
        Some(json!({ "ack": [jti] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{emptied}");
    assert_eq!(
        emptied["sets"].as_object().map(serde_json::Map::len),
        Some(0),
        "{emptied}"
    );

    // The fixed name says both ways of taking delivery.
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/realms/{REALM}/.well-known/ssf-configuration"))
            .to_request(),
    )
    .await;
    let told: Value = test::read_body_json(response).await;
    assert!(
        told["delivery_methods_supported"]
            .as_array()
            .is_some_and(|held| held.iter().any(|urn| urn == "urn:ietf:rfc:8936")),
        "{told}"
    );
}
