mod support;

use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use support::Plane;

const REALM: &str = support::REALM;

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
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn protection() -> Value {
    json!({ "enforcement_mode": "enforcing", "decision_strategy": "unanimous" })
}

/// The surface, end to end: protect a client, hang a resource, a scope and a
/// policy off it, and take it down bindings first.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_protected_application_lives_over_the_plane() {
    let plane = Plane::with_actions(&[
        AdminAction::UmaRead,
        AdminAction::UmaWrite,
        AdminAction::RoleRead,
        AdminAction::RoleWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let base = format!(
        "/admin/realms/{REALM}/authz/servers/{}",
        support::CONFIDENTIAL
    );

    // The rule binds roles by identity, and the join has a key to keep: a
    // policy naming a role nobody made is refused by the schema, so the role
    // comes first, over its own API.
    let (_, editor) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/roles"),
        &bearer,
        Some(json!({ "name": "editor" })),
    )
    .await;
    let editor_id = editor["role_id"].as_str().expect("an identity").to_owned();

    let (status, made) = asked(&plane, Method::POST, &base, &bearer, Some(protection())).await;
    assert_eq!(status, StatusCode::CREATED, "{made}");

    // Protecting what is protected is a conflict, not a second protection.
    let (status, told) = asked(&plane, Method::POST, &base, &bearer, Some(protection())).await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    // A client nobody registered cannot be protected, and is named as absent.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/authz/servers/nobody"),
        &bearer,
        Some(protection()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "client.not_found", "{told}");

    let (status, resource) = asked(
        &plane,
        Method::POST,
        &format!("{base}/resources"),
        &bearer,
        Some(json!({
            "name": "orders",
            "display_name": "",
            "description": "",
            "resource_uris": ["/orders/*"],
            "resource_type": "urn:app:orders",
            "resource_owner": "app",
            "user_managed_access": false,
            "configs": null,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{resource}");

    let (status, scope) = asked(
        &plane,
        Method::POST,
        &format!("{base}/scopes"),
        &bearer,
        Some(json!({ "name": "orders:read", "display_name": "", "description": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{scope}");

    let (status, policy) = asked(
        &plane,
        Method::POST,
        &format!("{base}/policies"),
        &bearer,
        Some(json!({
            "name": "editors-only",
            "description": "",
            "decision": "unanimous",
            "logic": "positive",
            "policy_owner": "app",
            "policies": [],
            "resources": [],
            "scopes": [],
            "policy_type": "role",
            "roles": [editor_id],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{policy}");

    let (status, listed) = asked(
        &plane,
        Method::GET,
        &format!("{base}/policies"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        listed.as_array().is_some_and(|held| !held.is_empty()),
        "{listed}"
    );

    let (status, _) = asked(&plane, Method::DELETE, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The store's refusals travel out with their own words.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_the_store_refuses_reaches_the_caller_in_its_own_words() {
    let plane = Plane::with_actions(&[
        AdminAction::UmaRead,
        AdminAction::UmaWrite,
        AdminAction::RoleRead,
        AdminAction::RoleWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let base = format!(
        "/admin/realms/{REALM}/authz/servers/{}",
        support::CONFIDENTIAL
    );
    let (status, _) = asked(&plane, Method::POST, &base, &bearer, Some(protection())).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, editor) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/roles"),
        &bearer,
        Some(json!({ "name": "editor" })),
    )
    .await;
    let editor_id = editor["role_id"].as_str().expect("an identity").to_owned();

    // An empty role policy decides nothing, and the answer says so.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("{base}/policies"),
        &bearer,
        Some(json!({
            "name": "empty",
            "description": "",
            "decision": "unanimous",
            "logic": "positive",
            "policy_owner": "app",
            "policies": [], "resources": [], "scopes": [],
            "policy_type": "role", "roles": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|held| held.contains("decides nothing")),
        "the store's sentence was restated or dropped: {told}"
    );

    // A condition another policy reads cannot be deleted from under it.
    let mint = |name: &str, roles: Value, conditions: Value| {
        json!({
            "name": name, "description": "",
            "decision": "unanimous", "logic": "positive",
            "policy_owner": "app",
            "policies": conditions, "resources": [], "scopes": [],
            "policy_type": if roles.as_array().is_some_and(|a| !a.is_empty()) { "role" } else { "aggregated" },
            "roles": roles,
        })
    };
    let (_, base_policy) = asked(
        &plane,
        Method::POST,
        &format!("{base}/policies"),
        &bearer,
        Some(mint("editors", json!([editor_id.clone()]), json!([]))),
    )
    .await;
    let condition_id = base_policy["policy_id"]
        .as_str()
        .expect("an identity")
        .to_owned();
    let (status, aggregate) = asked(
        &plane,
        Method::POST,
        &format!("{base}/policies"),
        &bearer,
        Some(json!({
            "name": "over-editors", "description": "",
            "decision": "unanimous", "logic": "positive",
            "policy_owner": "app",
            "policies": [condition_id], "resources": [], "scopes": [],
            "policy_type": "aggregated",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{aggregate}");

    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/policies/{condition_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|held| held.contains("condition of another policy")),
        "{told}"
    );
}

/// Reading the surface is not rewriting it, and the decision log has its own
/// capability: watching what the engine decided is not editing what it reads.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_capabilities_split_where_they_should() {
    let plane = Plane::with_actions(&[AdminAction::UmaRead]).await;
    let bearer = plane.token(&support::claims());
    let base = format!(
        "/admin/realms/{REALM}/authz/servers/{}",
        support::CONFIDENTIAL
    );

    let (status, _) = asked(&plane, Method::POST, &base, &bearer, Some(protection())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // uma:read does not read the decision log.
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/authz/decisions"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
