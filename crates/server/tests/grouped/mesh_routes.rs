#[allow(unused_imports)]
use super::support;
use super::support::{AUDIENCE, PARTY, Plane, REALM, SCOPE, claims};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};
use server::middleware::admin_policy::AdminPolicy;
use store::tenancy::TenantContext;

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: AdminPolicy {
            audiences: vec![AUDIENCE.to_owned()],
            parties: vec![PARTY.to_owned()],
            scope: SCOPE.to_owned(),
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
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// Ask the enforcement door about a request the way a proxy would: a verb
/// and a path, and nothing about what they mean.
async fn about_route(
    plane: &Plane,
    bearer: &str,
    method: &str,
    path: &str,
    decision_id: &str,
) -> (StatusCode, Value) {
    asked(
        plane,
        Method::POST,
        "/authz/decision",
        bearer,
        Some(json!({
            "kind": "route",
            "method": method,
            "path": path,
            "action": "ignored",
            "decision_id": decision_id,
        })),
    )
    .await
}

/// The decision this identifier was written under, as the record keeps it.
async fn recorded(plane: &Plane, decision_id: &str) -> Option<(String, String, String)> {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    store::providers::authz_policies::recent(&transaction, 50)
        .await
        .unwrap()
        .into_iter()
        .find(|held| held.decision_id == decision_id)
        .map(|held| {
            (
                held.resource_kind,
                held.resource_ref.unwrap_or_default(),
                held.action,
            )
        })
}

/// A token for the protected application itself, since an application asks
/// about its own routes and no other.
fn as_the_application(plane: &Plane) -> String {
    let mut mine = claims();
    mine.set_audience(vec![support::CONFIDENTIAL]);
    plane.token(&mine)
}

/// The realm states what a path means, and the enforcement door answers a
/// proxy that knows only the request it is forwarding.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_path_means_what_the_realm_says_it_means() {
    let plane = Plane::with_actions(&[AdminAction::UmaRead, AdminAction::UmaWrite]).await;
    let admin = plane.token(&claims());
    let application = as_the_application(&plane);
    let base = format!(
        "/admin/realms/{REALM}/authz/servers/{}",
        support::CONFIDENTIAL
    );
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &admin,
        Some(json!({ "enforcement_mode": "enforcing", "decision_strategy": "unanimous" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");

    let route = |route_id: &str| format!("/admin/realms/{REALM}/authz/routes/{route_id}");

    // The writing door refuses what the matcher could not read, and a route
    // whose application nobody protects.
    for (body, why) in [
        (
            json!({ "path": "/api/*", "server_id": support::CONFIDENTIAL,
                 "resource": "orders", "scope": "read" }),
            "no method",
        ),
        (
            json!({ "method": "GET", "server_id": support::CONFIDENTIAL,
                 "resource": "orders", "scope": "read" }),
            "no path",
        ),
        (
            json!({ "method": "GET", "path": "/api/*/deep", "server_id": support::CONFIDENTIAL,
                 "resource": "orders", "scope": "read" }),
            "a star in the middle",
        ),
        (
            json!({ "method": "GET", "path": "/api/*", "server_id": "nobody",
                 "resource": "orders", "scope": "read" }),
            "an unprotected application",
        ),
    ] {
        let (status, told) = asked(&plane, Method::PUT, &route("bad"), &admin, Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{why}: {told}");
    }

    // Three routes, in the operator's own order: the strict exact one first,
    // the looser prefixes behind it.
    for (route_id, body) in [
        (
            "exact",
            json!({ "method": "*", "path": "/api/orders", "server_id": support::CONFIDENTIAL,
                    "resource": "orders", "scope": "write", "action": "write",
                    "priority": 5 }),
        ),
        (
            "admin",
            json!({ "method": "*", "path": "/api/admin/*", "server_id": support::CONFIDENTIAL,
                    "resource": "console", "scope": "manage", "action": "manage",
                    "priority": 10 }),
        ),
        (
            "reads",
            json!({ "method": "GET", "path": "/api/*", "server_id": support::CONFIDENTIAL,
                    "resource": "orders", "scope": "read", "action": "read",
                    "priority": 20 }),
        ),
    ] {
        let (status, told) = asked(&plane, Method::PUT, &route(route_id), &admin, Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{told}");
    }

    // A path the realm has said nothing about is not an open one, and
    // nothing is written down: no rule was consulted.
    let (status, told) = about_route(&plane, &application, "GET", "/health", "d-unmapped").await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["decision"], "deny", "{told}");
    assert!(recorded(&plane, "d-unmapped").await.is_none());

    // A mapped path is decided as the permission the map names, and the
    // record keeps the map's words rather than the caller's.
    let (status, told) = about_route(&plane, &application, "GET", "/api/invoices", "d-read").await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        recorded(&plane, "d-read").await,
        Some((
            "permission".to_owned(),
            "orders#read".to_owned(),
            "read".to_owned()
        )),
        "the route the map chose is not the one that was decided"
    );

    // The first route that covers the request answers it, whatever a later
    // one would have said.
    let (_, told) = about_route(&plane, &application, "GET", "/api/admin/users", "d-first").await;
    assert_eq!(told["decision"], "deny", "{told}");
    assert_eq!(
        recorded(&plane, "d-first").await,
        Some((
            "permission".to_owned(),
            "console#manage".to_owned(),
            "manage".to_owned()
        )),
        "a later route answered ahead of the one written first"
    );

    // The verb narrows: a write on a path only the read route covers falls
    // off the end of the map.
    let (_, told) = about_route(&plane, &application, "POST", "/api/invoices", "d-write").await;
    assert_eq!(told["decision"], "deny", "{told}");
    assert!(recorded(&plane, "d-write").await.is_none());

    // The query is the caller's to write, so it cannot choose the route. The
    // danger is not the strict route failing to match: it is the request
    // falling past it onto a looser one further down, which is a caller
    // picking the permission it faces by appending a character.
    let (_, strict) = about_route(&plane, &application, "GET", "/api/orders", "d-strict").await;
    assert_eq!(strict["decision"], "deny", "{strict}");
    assert_eq!(
        recorded(&plane, "d-strict").await.map(|held| held.1),
        Some("orders#write".to_owned())
    );
    let (_, told) = about_route(&plane, &application, "GET", "/api/orders?x=1", "d-dressed").await;
    assert_eq!(told["decision"], "deny", "{told}");
    assert_eq!(
        recorded(&plane, "d-dressed").await.map(|held| held.1),
        Some("orders#write".to_owned()),
        "a query string walked the request past its own route onto a looser one"
    );

    // An application asks about its own routes and no one else's: the guard
    // the named question carries covers the resolved one too.
    let (status, _) = about_route(
        &plane,
        &plane.token(&claims()),
        "GET",
        "/api/orders",
        "d-other",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a token asked about an application it was not issued for"
    );

    // A route taken down stops answering, and taking down what is not there
    // says so.
    for route_id in ["reads", "exact"] {
        let (status, _) = asked(&plane, Method::DELETE, &route(route_id), &admin, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let (status, _) = asked(&plane, Method::DELETE, &route("reads"), &admin, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, told) = about_route(&plane, &application, "GET", "/api/orders", "d-gone").await;
    assert_eq!(told["decision"], "deny", "{told}");
    assert!(
        recorded(&plane, "d-gone").await.is_none(),
        "a route that was taken down still answered"
    );

    let (status, listed) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/authz/routes"),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed.as_array().expect("a list").len(), 1, "{listed}");
}
