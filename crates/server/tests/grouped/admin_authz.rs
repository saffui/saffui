#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};

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
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn protection() -> Value {
    json!({ "enforcement_mode": "enforcing", "decision_strategy": "unanimous" })
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn evaluator_accepts_the_exact_username_and_user_id() {
    let plane = Plane::with_actions(&[AdminAction::AuthzDecisionWrite]).await;
    let bearer = plane.token(&support::claims());
    plane.rename_subject("ada-renamed").await;
    for named in [support::SUBJECT, "ada-renamed"] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &format!("/admin/realms/{REALM}/authz/evaluate"),
            &bearer,
            Some(json!({
                "subject": named,
                "question": {
                    "kind": "relationship",
                    "object_type": "document",
                    "object_id": "one",
                    "relation": "viewer",
                },
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{named}: {told}");
    }
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

    // A policy naming a role nobody made is a caller's mistake, told in the
    // store's words. It used to die on the join's foreign key as an internal
    // error, which this probe would catch coming back.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("{base}/policies"),
        &bearer,
        Some(json!({
            "name": "haunted",
            "description": "",
            "decision": "unanimous",
            "logic": "positive",
            "policy_owner": "app",
            "policies": [], "resources": [], "scopes": [],
            "policy_type": "role", "roles": [editor_id, "nobody"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|held| held.contains("no role answers to nobody")),
        "the missing member is not named: {told}"
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

/// The simulator asks the engine itself: a role policy denies the subject
/// who lacks the role with its reasons on show, permits once granted, and a
/// subject nobody is answers not-found.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_simulated_decision_is_the_engine_speaking() {
    let plane = Plane::with_actions(&[
        AdminAction::UmaRead,
        AdminAction::UmaWrite,
        AdminAction::RoleRead,
        AdminAction::RoleWrite,
        AdminAction::AuthzDecisionWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let base = format!(
        "/admin/realms/{REALM}/authz/servers/{}",
        support::CONFIDENTIAL
    );

    let (_, editor) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/roles"),
        &bearer,
        Some(json!({ "name": "editor" })),
    )
    .await;
    let editor_id = editor["role_id"].as_str().expect("a role").to_owned();
    let (status, _) = asked(&plane, Method::POST, &base, &bearer, Some(protection())).await;
    assert_eq!(status, StatusCode::CREATED);
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
    let policy_id = policy["policy_id"].as_str().expect("a policy").to_owned();

    let question = |subject: &str| {
        json!({
            "subject": subject,
            "question": {
                "kind": "policy",
                "server_id": support::CONFIDENTIAL,
                "policy_id": policy_id,
            },
        })
    };

    // Without the role: denied, and the trace says what the engine met.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/authz/evaluate"),
        &bearer,
        Some(question(support::SUBJECT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["computed"], "deny", "{told}");
    assert!(told["detail"]["reasons"].is_array(), "{told}");

    // Granted the role, the same question permits.
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!(
            "/admin/realms/{REALM}/roles/{editor_id}/holders/{}",
            support::SUBJECT
        ),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/authz/evaluate"),
        &bearer,
        Some(question(support::SUBJECT)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["computed"], "permit", "{told}");

    // A subject nobody is answers not-found, before any engine runs.
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/authz/evaluate"),
        &bearer,
        Some(question("nobody-here")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A resource and a scope are reworked in place, and neither can be reached
/// through a resource server that does not hold it.
///
/// Editing in place is the whole point: a policy binds a resource by
/// identity, so replacing the row under a new id would break the binding
/// while looking on screen like a rename. And the server on the path has to
/// be the one that holds it, or a caller with one protected client could edit
/// another's surface by knowing an identifier.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_surface_is_reworked_in_place_and_never_through_another_server() {
    let plane = Plane::with_actions(&[AdminAction::UmaRead, AdminAction::UmaWrite]).await;
    let bearer = plane.token(&support::claims());
    let here = format!(
        "/admin/realms/{REALM}/authz/servers/{}",
        support::CONFIDENTIAL
    );
    let elsewhere = format!("/admin/realms/{REALM}/authz/servers/{}", support::OTHER);

    for base in [&here, &elsewhere] {
        let (status, told) = asked(&plane, Method::POST, base, &bearer, Some(protection())).await;
        assert_eq!(status, StatusCode::CREATED, "{told}");
    }

    let (status, made) = asked(
        &plane,
        Method::POST,
        &format!("{here}/resources"),
        &bearer,
        Some(json!({
            "name": "invoice", "display_name": "Invoice", "description": "one bill",
            "resource_uris": ["/invoices/*"], "resource_type": "urn:invoice",
            "resource_owner": support::SUBJECT, "user_managed_access": false,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    let resource_id = made["resource_id"].as_str().expect("an id").to_owned();

    let reworked = json!({
        "name": "invoice", "display_name": "Invoice, archived", "description": "one bill, kept",
        "resource_uris": ["/invoices/*", "/archive/invoices/*"], "resource_type": "urn:invoice",
        "resource_owner": support::SUBJECT, "user_managed_access": false,
    });

    // The other server does not hold it, and saying so is a not-found rather
    // than a refusal: the caller learns nothing about what the neighbour holds.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{elsewhere}/resources/{resource_id}"),
        &bearer,
        Some(reworked.clone()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a surface was edited through a stranger: {told}"
    );

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{here}/resources/{resource_id}"),
        &bearer,
        Some(reworked),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        told["resource_id"], resource_id,
        "the identity moved: {told}"
    );
    assert_eq!(told["display_name"], "Invoice, archived", "{told}");
    assert_eq!(
        told["resource_uris"].as_array().expect("uris").len(),
        2,
        "{told}"
    );

    // And the listing agrees, which is what the screen reads.
    let (status, listed) = asked(
        &plane,
        Method::GET,
        &format!("{here}/resources"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let rows = listed.as_array().expect("a listing");
    assert_eq!(rows.len(), 1, "an edit made a second row: {listed}");
    assert_eq!(rows[0]["display_name"], "Invoice, archived", "{listed}");

    // A scope goes the same way.
    let (status, made) = asked(
        &plane,
        Method::POST,
        &format!("{here}/scopes"),
        &bearer,
        Some(json!({ "name": "read", "display_name": "Read", "description": "look" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    let scope_id = made["scope_id"].as_str().expect("an id").to_owned();

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{here}/scopes/{scope_id}"),
        &bearer,
        Some(json!({ "name": "read", "display_name": "Read, including archived", "description": "look" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["scope_id"], scope_id, "the identity moved: {told}");
    assert_eq!(told["display_name"], "Read, including archived", "{told}");
}

/// A resource is shared only where both the server and the resource say it
/// may be, and only as a relation the published graph describes.
///
/// `user_managed_access` was stored on both and read nowhere, which made it a
/// promise nothing kept. Every refusal below is that promise being kept.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_resource_is_shared_only_where_it_is_user_managed_and_the_graph_says_how() {
    let plane = Plane::with_actions(&[
        AdminAction::UmaRead,
        AdminAction::UmaWrite,
        AdminAction::RebacRead,
        AdminAction::RebacWrite,
        AdminAction::AuthzDecisionWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let base = format!(
        "/admin/realms/{REALM}/authz/servers/{}",
        support::CONFIDENTIAL
    );

    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({
            "enforcement_mode": "enforcing",
            "decision_strategy": "unanimous",
            "user_managed_access": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");

    // A graph that describes the resource's own type, and one relation on it.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/rebac/schema"),
        &bearer,
        Some(json!({
            "source": "definition user {}\n\ndefinition invoice {\n    relation viewer: user\n}\n"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let make = |managed: bool, name: &str| {
        json!({
            "name": name, "display_name": name, "description": "",
            "resource_uris": [], "resource_type": "invoice",
            "resource_owner": support::SUBJECT, "user_managed_access": managed,
        })
    };
    let (_, open) = asked(
        &plane,
        Method::POST,
        &format!("{base}/resources"),
        &bearer,
        Some(make(true, "shared")),
    )
    .await;
    let (_, shut) = asked(
        &plane,
        Method::POST,
        &format!("{base}/resources"),
        &bearer,
        Some(make(false, "private")),
    )
    .await;
    let open_id = open["resource_id"].as_str().expect("an id").to_owned();
    let shut_id = shut["resource_id"].as_str().expect("an id").to_owned();

    let with =
        json!({ "relation": "viewer", "subject_type": "user", "subject_id": support::SUBJECT });

    // A resource that is not user managed is not shareable, whatever the
    // server says.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("{base}/resources/{shut_id}/shares"),
        &bearer,
        Some(with.clone()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a private resource was shared: {told}"
    );

    // A relation the graph does not describe is refused rather than written
    // as a tuple the walk would never follow.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("{base}/resources/{open_id}/shares"),
        &bearer,
        Some(
            json!({ "relation": "editor", "subject_type": "user", "subject_id": support::SUBJECT }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an undescribed relation was written: {told}"
    );

    // And the share the graph does describe lands, and the engine walks it.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("{base}/resources/{open_id}/shares"),
        &bearer,
        Some(with.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    let (status, verdict) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/authz/evaluate"),
        &bearer,
        Some(json!({
            "subject": support::SUBJECT,
            "question": {
                "kind": "relationship",
                "object_type": "invoice",
                "object_id": open_id,
                "relation": "viewer",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verdict}");
    assert_eq!(
        verdict["computed"], "permit",
        "the share was not walked: {verdict}"
    );

    // The simulation says where it went, which is what an author reads.
    let steps = verdict["walk"]["steps"].as_array().expect("a walk");
    assert!(!steps.is_empty(), "a walk with no steps: {verdict}");
    assert_eq!(
        steps[0]["asked"],
        format!("invoice:{open_id}#viewer"),
        "{verdict}"
    );

    // Unsharing goes back the same way, and the engine stops walking it.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/resources/{open_id}/shares"),
        &bearer,
        Some(with),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    let (_, verdict) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/authz/evaluate"),
        &bearer,
        Some(json!({
            "subject": support::SUBJECT,
            "question": {
                "kind": "relationship",
                "object_type": "invoice",
                "object_id": open_id,
                "relation": "viewer",
            },
        })),
    )
    .await;
    assert_ne!(
        verdict["computed"], "permit",
        "the share outlived being taken back: {verdict}"
    );
}

/// Sharing closes and reopens on the server itself. The PUT used to take the
/// flag and drop it, so a server opened at birth stayed open whatever its
/// caller was told.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_server_closes_and_reopens_sharing_in_place() {
    let plane = Plane::with_actions(&[
        AdminAction::UmaRead,
        AdminAction::UmaWrite,
        AdminAction::RebacWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let base = format!(
        "/admin/realms/{REALM}/authz/servers/{}",
        support::CONFIDENTIAL
    );
    let protection = |shareable: bool| {
        json!({
            "enforcement_mode": "enforcing",
            "decision_strategy": "unanimous",
            "user_managed_access": shareable,
        })
    };

    let (status, told) = asked(&plane, Method::POST, &base, &bearer, Some(protection(true))).await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/rebac/schema"),
        &bearer,
        Some(json!({
            "source": "definition user {}\n\ndefinition invoice {\n    relation viewer: user\n}\n"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, made) = asked(
        &plane,
        Method::POST,
        &format!("{base}/resources"),
        &bearer,
        Some(json!({
            "name": "shared", "display_name": "shared", "description": "",
            "resource_uris": [], "resource_type": "invoice",
            "resource_owner": support::SUBJECT, "user_managed_access": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    let shares = format!(
        "{base}/resources/{}/shares",
        made["resource_id"].as_str().expect("an id")
    );
    let share = |reader: &str| json!({ "relation": "viewer", "subject_type": "user", "subject_id": reader });

    let (status, told) = asked(&plane, Method::PUT, &base, &bearer, Some(protection(false))).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (_, held) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(
        held["user_managed_access"], false,
        "the closed ceiling was not kept: {held}"
    );
    let (status, told) = asked(
        &plane,
        Method::POST,
        &shares,
        &bearer,
        Some(share("first-reader")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a closed server let a resource be shared: {told}"
    );

    let (status, told) = asked(&plane, Method::PUT, &base, &bearer, Some(protection(true))).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, told) = asked(
        &plane,
        Method::POST,
        &shares,
        &bearer,
        Some(share("second-reader")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a reopened server still refused to share: {told}"
    );
}
