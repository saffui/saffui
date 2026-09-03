#[allow(unused_imports)]
use super::support;

use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use super::support::Plane;

const REALM: &str = support::REALM;

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

fn count(document: &Value, section: &str) -> usize {
    document[section].as_array().map(Vec::len).unwrap_or(0)
}

/// A realm leaves as a document and lands whole under another name, the
/// same realm and not a copy: every identifier, attachment and manner
/// crosses verbatim.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_crosses_as_a_document() {
    let plane = Plane::with_actions(&[AdminAction::RealmExport, AdminAction::RealmImport]).await;
    let bearer = plane.token(&support::claims());

    let (status, document) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/export"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{document}");
    assert_eq!(document["format_version"], 1);
    assert_eq!(document["realm"]["realm_id"], REALM);
    assert_eq!(document["sections"].as_array().expect("sections").len(), 12);
    assert!(count(&document, "clients") >= 4, "{document}");
    assert!(count(&document, "client_scopes") >= 5);
    assert!(count(&document, "flows") >= 3);
    assert!(count(&document, "users") >= 1);
    assert!(count(&document, "executions") >= 3);

    // The same name is already taken: a document lands beside its original
    // only under another.
    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms/import",
        &bearer,
        Some(document.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms/import?as=twin",
        &bearer,
        Some(document.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    assert_eq!(told["realm_id"], "twin");

    // The twin answers with the same inventory, re-exported through the
    // same door.
    let (status, twin) = asked(
        &plane,
        Method::GET,
        "/admin/realms/twin/export",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{twin}");
    assert_eq!(twin["realm"]["realm_id"], "twin");
    for section in [
        "clients",
        "client_scopes",
        "protocol_mappers",
        "flows",
        "executions",
        "roles",
        "groups",
        "organizations",
        "users",
        "required_actions",
        "authorization",
    ] {
        assert_eq!(
            count(&twin, section),
            count(&document, section),
            "the {section} did not cross whole"
        );
    }

    // Identity, not likeness: the client ids are the originals, and how a
    // scope is held crosses with it.
    let named = |document: &Value| -> Vec<String> {
        let mut ids: Vec<String> = document["clients"]
            .as_array()
            .expect("clients")
            .iter()
            .map(|held| {
                held["client"]["client_id"]
                    .as_str()
                    .expect("an identity")
                    .to_owned()
            })
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(named(&twin), named(&document));
    let manner_of = |document: &Value, client_id: &str| -> Vec<(String, bool)> {
        let mut held: Vec<(String, bool)> = document["clients"]
            .as_array()
            .expect("clients")
            .iter()
            .find(|held| held["client"]["client_id"] == client_id)
            .expect("the client")["scopes"]
            .as_array()
            .expect("attachments")
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().expect("a scope").to_owned(),
                    pair[1].as_bool().expect("a manner"),
                )
            })
            .collect();
        held.sort();
        held
    };
    let crossed = manner_of(&twin, support::CONFIDENTIAL);
    assert_eq!(crossed, manner_of(&document, support::CONFIDENTIAL));
    assert!(
        crossed
            .iter()
            .any(|(scope, optional)| scope == "address" && *optional),
        "the optional manner did not cross: {crossed:?}"
    );

    // A format this build does not write is refused before anything lands.
    let mut unread = document.clone();
    unread["format_version"] = json!(2);
    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms/import?as=unreadable",
        &bearer,
        Some(unread),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
}

/// Carrying a realm out and writing one in are different powers.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_portability_capabilities_split_where_they_should() {
    let plane = Plane::with_actions(&[AdminAction::RealmExport]).await;
    let bearer = plane.token(&support::claims());

    let (status, document) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/export"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{document}");

    let (status, _) = asked(
        &plane,
        Method::POST,
        "/admin/realms/import?as=elsewhere",
        &bearer,
        Some(document),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
