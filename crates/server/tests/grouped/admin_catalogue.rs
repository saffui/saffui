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

const SCHEMA: &str = "
definition user {}

definition group {
    relation member: user | group#member
}

definition folder {
    relation viewer: user | group#member
    permission view = viewer
}
";

/// The relationship schema rules what may be written under it, and every
/// refusal comes in the compiler's or the engine's own words.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_relationship_schema_rules_what_is_written() {
    let plane = Plane::with_actions(&[AdminAction::RebacRead, AdminAction::RebacWrite]).await;
    let bearer = plane.token(&support::claims());
    let schema = format!("/admin/realms/{REALM}/rebac/schema");
    let relations = format!("/admin/realms/{REALM}/rebac/relations");

    let (status, told) = asked(&plane, Method::GET, &schema, &bearer, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "rebac.schema.not_found");

    // An edge against no schema is told which absence it hit.
    let edge = |relation: &str, subject_relation: &str| {
        json!({
            "object_type": "folder", "object_id": "plans",
            "relation": relation,
            "subject_type": "user", "subject_id": "ada",
            "subject_relation": subject_relation,
        })
    };
    let (status, told) = asked(
        &plane,
        Method::POST,
        &relations,
        &bearer,
        Some(edge("viewer", "")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");

    // What does not compile is refused in the compiler's words.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &schema,
        &bearer,
        Some(json!({ "source": "definition folder { relation viewer: ghost }" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|why| why.contains("ghost")),
        "the fault does not name the ghost: {told}"
    );

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &schema,
        &bearer,
        Some(json!({ "source": SCHEMA })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, told) = asked(&plane, Method::GET, &schema, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert!(
        told["source"]
            .as_str()
            .is_some_and(|held| held.contains("definition folder")),
        "{told}"
    );

    // Written edges obey the schema: a permission stores nothing, an unknown
    // relation is named, a fine edge lands.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &relations,
        &bearer,
        Some(edge("view", "")),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|why| why.contains("stores no edges")),
        "{told}"
    );
    let (status, told) = asked(
        &plane,
        Method::POST,
        &relations,
        &bearer,
        Some(edge("owner", "")),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|why| why.contains("no relation named 'owner'")),
        "{told}"
    );
    let (status, told) = asked(
        &plane,
        Method::POST,
        &relations,
        &bearer,
        Some(edge("viewer", "")),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("{relations}?object_type=folder&object_id=plans&relation=viewer"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told[0]["subject_id"], "ada", "{told}");

    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &relations,
        &bearer,
        Some(edge("viewer", "")),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &relations,
        &bearer,
        Some(edge("viewer", "")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "rebac.edge.not_found");
}

/// The decision log forgets only when told, and only up to the named
/// instant.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_decision_log_forgets_only_when_told() {
    use models::entities::authz::{AuthzDecisionRecord, Decision, ReportedDecision};
    let plane = Plane::with_actions(&[
        AdminAction::AuthzDecisionRead,
        AdminAction::AuthzDecisionWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::authz_policies::record(
            &transaction,
            &AuthzDecisionRecord {
                decision_id: "remembered".to_owned(),
                tenant: support::TENANT.to_owned(),
                realm_id: REALM.to_owned(),
                subject_type: "user".to_owned(),
                subject_id: "ada".to_owned(),
                resource_kind: "resource".to_owned(),
                resource_ref: Some("doc".to_owned()),
                action: "read".to_owned(),
                reported: ReportedDecision::Permit,
                computed: Decision::Permit,
                detail: json!({}),
                duration_us: 10,
                trace_id: None,
                occurred_at_millis: None,
            },
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }

    let decisions = format!("/admin/realms/{REALM}/authz/decisions");
    let (status, told) = asked(&plane, Method::GET, &decisions, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert!(!told.as_array().expect("a log").is_empty());

    // No bound, no forgetting: everything must be asked for in so many words.
    let (status, _) = asked(&plane, Method::DELETE, &decisions, &bearer, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A cut before the record leaves it standing.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{decisions}?before=2000-01-01T00:00:00Z"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["removed"], 0);

    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{decisions}?before=2100-01-01T00:00:00Z"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["removed"], 1);
    let (_, told) = asked(&plane, Method::GET, &decisions, &bearer, None).await;
    assert!(told.as_array().expect("a log").is_empty(), "{told}");
}

/// The last three families split like all the others, and the feature
/// registry answers what the build carries.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_last_capabilities_split_where_they_should() {
    let plane = Plane::with_actions(&[
        AdminAction::RebacRead,
        AdminAction::AuthzDecisionRead,
        AdminAction::FeatureRead,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    let (status, told) = asked(&plane, Method::GET, "/admin/features", &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let listed = told.as_array().expect("a registry");
    assert_eq!(listed.len(), commons::feature::Feature::ALL.len(), "{told}");
    assert!(
        listed.iter().any(|held| held["slug"] == "pq-hybrid"
            && held["compiled"].is_boolean()
            && held["enabled"].is_boolean()),
        "{told}"
    );

    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/rebac/schema"),
        &bearer,
        Some(json!({ "source": "definition user {}" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/authz/decisions?before=2100-01-01T00:00:00Z"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The realm's edges list a page at a time in key order, narrow by what the
/// query names, and answer only a reader of the graph.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_realms_edges_list_a_page_at_a_time_and_narrow() {
    let plane = Plane::with_actions(&[AdminAction::RebacRead, AdminAction::RebacWrite]).await;
    let bearer = plane.token(&support::claims());
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/rebac/schema"),
        &bearer,
        Some(json!({
            "source": "definition user {}\n\ndefinition group {\n    relation member: user | group#member\n}\n\ndefinition folder {\n    relation viewer: user | group#member\n}\n"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    for (object_id, subject_type, subject_id, subject_relation) in [
        ("plans", "user", "ada", ""),
        ("plans", "user", "grace", ""),
        ("roadmap", "group", "eng", "member"),
    ] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &format!("/admin/realms/{REALM}/rebac/relations"),
            &bearer,
            Some(json!({
                "object_type": "folder",
                "object_id": object_id,
                "relation": "viewer",
                "subject_type": subject_type,
                "subject_id": subject_id,
                "subject_relation": subject_relation,
            })),
        )
        .await;
        assert!(status.is_success(), "{told}");
    }

    let tuples = |query: &str| format!("/admin/realms/{REALM}/rebac/tuples{query}");
    let edges = |page: &Value| {
        page["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| {
                format!(
                    "{}:{}",
                    item["object_id"].as_str().unwrap_or_default(),
                    item["subject_id"].as_str().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
    };
    let (status, page) = asked(
        &plane,
        Method::GET,
        &tuples("?first=0&max=2"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(edges(&page), vec!["plans:ada", "plans:grace"], "{page}");
    let (_, page) = asked(
        &plane,
        Method::GET,
        &tuples("?first=2&max=2"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(edges(&page), vec!["roadmap:eng"], "{page}");
    assert_eq!(page["items"][0]["subject_relation"], "member", "{page}");
    assert!(page["items"][0]["created_at"].is_string(), "{page}");
    let (_, page) = asked(
        &plane,
        Method::GET,
        &tuples("?subject_type=group"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(edges(&page), vec!["roadmap:eng"], "{page}");
    let (_, page) = asked(
        &plane,
        Method::GET,
        &tuples("?subject_id=ada&relation=viewer"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(edges(&page), vec!["plans:ada"], "{page}");
    let (_, page) = asked(&plane, Method::GET, &tuples("?object_type="), &bearer, None).await;
    assert_eq!(
        edges(&page).len(),
        3,
        "an empty filter narrowed the listing: {page}"
    );
    drop(plane);

    let writer = Plane::with_actions(&[AdminAction::RebacWrite]).await;
    let bearer = writer.token(&support::claims());
    let (status, told) = asked(&writer, Method::GET, &tuples(""), &bearer, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{told}");
}
