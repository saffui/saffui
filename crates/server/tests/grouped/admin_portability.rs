#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};

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
        ceiling: support::ceiling(),
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
async fn the_other_birth_door_answers_to_the_same_rules() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmExport,
        AdminAction::RealmImport,
        AdminAction::RealmCreate,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    let (status, document) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{}/export", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{document}");

    // Named, so the landing realm holds somebody who can answer for it. An
    // export carries users and no secrets, so without this the realm arrives
    // with accounts nobody can sign in as.
    let (status, landed) = asked(
        &plane,
        Method::POST,
        "/admin/realms/import?as=arrival&administrator=root",
        &bearer,
        Some(document.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{landed}");
    let password = landed["administrator"]["password"]
        .as_str()
        .expect("the landing handed back a way in");
    assert!(password.len() >= 40, "a drawn password, not a placeholder");

    // The ceiling counts an import like any other arrival. Two realms stand
    // now, so a ceiling of two is reached before the next document lands.
    plane.cap_realms(2).await;
    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms/import?as=overflow",
        &bearer,
        Some(document),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the import walked past the ceiling: {told}"
    );

    // And the arrival is written above the realms, where a deletion cannot
    // take it with the row.
    let (owner, connection) = support::owner()
        .connect(tokio_postgres::NoTls)
        .await
        .expect("the owner");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let rows = owner
        .query(
            "SELECT envelope FROM tenant_events WHERE tenant = $1 AND \
             envelope ->> 'realm' = 'arrival'",
            &[&support::TENANT],
        )
        .await
        .expect("the owner reads the chain");
    assert_eq!(rows.len(), 1, "the arrival left no trace above the realms");
    let envelope: serde_json::Value = rows[0].get("envelope");
    assert_eq!(envelope["kind"], "realm.imported", "{envelope}");
}

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

    // The twin holds the same inventory. It is re-exported through the
    // service rather than the door: this token belongs to another realm,
    // and no token administers a realm it did not come from. What is under
    // test is the document's round trip, not who may ask for it.
    let twin = {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(
                &mut connection,
                &TenantContext::new(support::TENANT, "twin"),
            )
            .await;
        let document =
            services::admin::portability::export_realm(&transaction, "twin", chrono::Utc::now())
                .await
                .expect("the twin exports");
        serde_json::to_value(document).expect("a document")
    };

    // And the door refuses, which is the same statement from the other
    // side: a realm is imported here and exported from its own console.
    let (status, _) = asked(
        &plane,
        Method::GET,
        "/admin/realms/twin/export",
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the importing token exported the realm it made"
    );
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
