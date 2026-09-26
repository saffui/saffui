#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use crate::admin_authz::asked;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};

const REALM: &str = support::REALM;

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
    crate::relations::relations_running();
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

/// The realm's edges list a page at a time in key order, narrow by what the
/// query names, and answer only a reader of the graph.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_realms_edges_list_a_page_at_a_time_and_narrow() {
    crate::relations::relations_running();
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

/// Closing the authorization capability shuts the doors that serve it, and
/// closing it does not touch what belongs to something else.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn closing_one_capability_shuts_its_doors_and_no_others() {
    crate::relations::relations_running();
    let plane = Plane::with_actions(&[
        AdminAction::FeatureRead,
        AdminAction::FeatureWrite,
        AdminAction::UmaRead,
        AdminAction::RebacRead,
        AdminAction::OrgRead,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let realm = support::REALM;

    let asking = |leaf: &'static str| async move { format!("/admin/realms/{realm}/{leaf}") };
    let policies = asking("authz/servers/app/policies").await;
    let relations = asking("rebac/relations?first=0&max=1").await;
    let organizations = asking("organizations").await;

    for path in [&policies, &relations, &organizations] {
        let (status, _) = asked(&plane, Method::GET, path, &bearer, None).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "{path} is shut to begin with"
        );
    }

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{realm}/features/authorization"),
        &bearer,
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    let (status, _) = asked(&plane, Method::GET, &policies, &bearer, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the authz doors still answer"
    );

    // The neighbours are their own capability and did not move with it.
    for path in [&relations, &organizations] {
        let (status, _) = asked(&plane, Method::GET, path, &bearer, None).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "{path} was shut by somebody else's capability"
        );
    }
}
