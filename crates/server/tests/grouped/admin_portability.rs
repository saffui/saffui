#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};

const REALM: &str = support::REALM;

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_configuration_export_can_be_previewed_and_merged() {
    let plane = Plane::with_actions(&[AdminAction::RealmExport, AdminAction::RealmImport]).await;
    let bearer = plane.token(&support::claims());

    let (status, document) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/export?include_users=false"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{document}");
    assert_eq!(count(&document, "users"), 0, "{document}");
    assert!(
        !document["sections"]
            .as_array()
            .expect("sections")
            .iter()
            .any(|section| section == "users")
    );

    let request = json!({ "document": document, "collision": "skip" });
    let (status, preview) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/import/preview"),
        &bearer,
        Some(request.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert!(preview["collision_count"].as_u64().unwrap_or(0) > 0);

    let (status, applied) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/import"),
        &bearer,
        Some(request),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_partial_import_refuses_accounts() {
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

    let (status, refused) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/import/preview"),
        &bearer,
        Some(json!({ "document": document, "collision": "fail" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
}

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
async fn concurrent_imports_share_one_ceiling_count() {
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
    plane.cap_realms(2).await;

    let left = asked(
        &plane,
        Method::POST,
        "/admin/realms/import?as=import-left",
        &bearer,
        Some(document.clone()),
    );
    let right = asked(
        &plane,
        Method::POST,
        "/admin/realms/import?as=import-right",
        &bearer,
        Some(document),
    );
    let (left, right) = tokio::join!(left, right);
    let statuses = [left.0, right.0];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CREATED)
            .count(),
        1,
        "{left:?} {right:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::UNPROCESSABLE_ENTITY)
            .count(),
        1,
        "{left:?} {right:?}"
    );

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &store::tenancy::TenantContext::tenant_wide(support::TENANT),
        )
        .await;
    assert_eq!(
        store::providers::tenants::count_realms(&transaction)
            .await
            .unwrap(),
        2
    );
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

/// A configuration export carries no people, so it carries nobody's grants or
/// memberships either, and it lands whole beside its original under another
/// name.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_configuration_export_lands_beside_its_original() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmExport,
        AdminAction::RealmImport,
        AdminAction::GroupWrite,
        AdminAction::OrgWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    join_a_group_and_an_organization(&plane, &bearer).await;

    let (status, document) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/export?include_users=false"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{document}");
    let nobody_named = |section: &str, field: &str| {
        document[section]
            .as_array()
            .expect("a section")
            .iter()
            .all(|row| row[field].as_array().is_some_and(Vec::is_empty))
    };
    assert!(nobody_named("roles", "held_by_users"), "{document}");
    assert!(nobody_named("groups", "members"), "{document}");
    assert!(nobody_named("organizations", "members"), "{document}");

    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms/import?as=configured",
        &bearer,
        Some(document),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");

    // What landed holds the group and the organization, and nobody in them.
    let landed = {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(
                &mut connection,
                &TenantContext::new(support::TENANT, "configured"),
            )
            .await;
        services::admin::portability::export_realm(&transaction, "configured", chrono::Utc::now())
            .await
            .expect("what landed exports")
    };
    assert!(
        landed
            .groups
            .iter()
            .any(|held| held.group.name == "editors" && held.members.is_empty())
    );
    assert!(
        landed
            .organizations
            .iter()
            .any(|held| held.organization.name == "acme-org" && held.members.is_empty())
    );
    assert!(
        landed
            .roles
            .iter()
            .all(|held| held.held_by_users.is_empty())
    );
}

/// A document whose grants or memberships name people it does not carry is
/// refused in words, each kind in turn, and nothing of it lands.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_document_naming_people_it_leaves_behind_is_refused() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmExport,
        AdminAction::RealmImport,
        AdminAction::GroupWrite,
        AdminAction::OrgWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    join_a_group_and_an_organization(&plane, &bearer).await;

    let (status, mut document) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/export"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{document}");
    let people: Vec<String> = document["users"]
        .as_array()
        .expect("the accounts")
        .iter()
        .filter_map(|user| user["user_id"].as_str().map(str::to_owned))
        .collect();
    document["users"] = json!([]);

    // Each check names its own kind and a person left behind, and the next is
    // reached once the one before it has nobody left to name.
    for (kind, section, field) in [
        ("role ", "roles", "held_by_users"),
        ("group ", "groups", "members"),
        ("organization ", "organizations", "members"),
    ] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            "/admin/realms/import?as=orphaned",
            &bearer,
            Some(document.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        let said = told["message"].as_str().unwrap_or_default();
        assert!(
            said.starts_with(kind)
                && said.contains("does not carry")
                && people.iter().any(|person| said.contains(person.as_str())),
            "expected a {kind}refusal naming a person left behind: {told}"
        );
        for row in document[section].as_array_mut().expect("a section") {
            row[field] = json!([]);
        }
    }

    // Nothing of the refused attempts landed: the name is still free.
    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms/import?as=orphaned",
        &bearer,
        Some(document),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
}

/// Ada already holds the planted role; she joins a group named editors and an
/// organization named acme-org, so all three kinds of membership are in play.
async fn join_a_group_and_an_organization(plane: &Plane, bearer: &str) {
    let (status, group) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/groups"),
        bearer,
        Some(json!({ "name": "editors", "description": "", "parent_id": null })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    let group_id = group["group_id"].as_str().expect("an identity").to_owned();
    let (status, told) = asked(
        plane,
        Method::PUT,
        &format!(
            "/admin/realms/{REALM}/groups/{group_id}/members/{}",
            support::SUBJECT
        ),
        bearer,
        None,
    )
    .await;
    assert!(status.is_success(), "{status}: {told}");
    let (status, organization) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/organizations"),
        bearer,
        Some(json!({ "name": "acme-org" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{organization}");
    let org_id = organization["org_id"]
        .as_str()
        .expect("an identity")
        .to_owned();
    let (status, told) = asked(
        plane,
        Method::PUT,
        &format!(
            "/admin/realms/{REALM}/organizations/{org_id}/members/{}",
            support::SUBJECT
        ),
        bearer,
        None,
    )
    .await;
    assert!(status.is_success(), "{status}: {told}");
}
