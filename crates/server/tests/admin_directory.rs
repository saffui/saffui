mod support;

use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::Value;
use support::Plane;

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

/// The whole life of a role: born, listed, renamed without losing its grants,
/// refused deletion while granted, deleted once it is not.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_role_lives_and_dies_over_the_plane() {
    let plane = Plane::with_actions(&[AdminAction::RoleRead, AdminAction::RoleWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/roles");

    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({
            "name": "auditor",
            "display_name": "Auditor",
            "description": "reads everything, writes nothing",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let role_id = born["role_id"].as_str().expect("an identity").to_owned();

    // A second of the same name is a conflict, not a second role.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({ "name": "auditor" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    let (status, listed) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        listed["items"]
            .as_array()
            .expect("a page")
            .iter()
            .any(|held| held["name"] == "auditor"),
        "{listed}"
    );

    // Renamed, the identity stays: what grants point at does not move.
    let (status, renamed) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{role_id}"),
        &bearer,
        Some(serde_json::json!({ "name": "reviewer", "display_name": "Reviewer" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{renamed}");
    assert_eq!(renamed["role_id"], role_id.as_str(), "{renamed}");

    // Granted, deletion is told no rather than the holder losing it silently.
    plane
        .grant_role_to_subject(&role_id, support::SUBJECT)
        .await;
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{role_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a held role was deleted: {told}"
    );

    plane
        .revoke_role_from_subject(&role_id, support::SUBJECT)
        .await;
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{role_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("{base}/{role_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Reading is not writing: the capability the route charges is the one the
/// token has to carry.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn reading_roles_does_not_allow_writing_them() {
    let plane = Plane::with_actions(&[AdminAction::RoleRead]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/roles");

    let (status, _) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({ "name": "escalation" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{told}");
}

/// Groups: the same shape, plus the default flag travelling.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_group_lives_and_dies_over_the_plane() {
    let plane = Plane::with_actions(&[AdminAction::GroupRead, AdminAction::GroupWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/groups");

    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({ "name": "staff", "is_default": true })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    assert_eq!(born["is_default"], true);
    let group_id = born["group_id"].as_str().expect("an identity").to_owned();

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{group_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// Organizations: created, updated, and deletable even with members, because
/// a member loses a label and not an entitlement.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_organization_lives_and_dies_over_the_plane() {
    let plane = Plane::with_actions(&[AdminAction::OrgRead, AdminAction::OrgWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/organizations");

    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({
            "name": "acme",
            "display_name": "Acme",
            "description": "",
            "enabled": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let org_id = born["org_id"].as_str().expect("an identity").to_owned();

    let (status, changed) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{org_id}"),
        &bearer,
        Some(serde_json::json!({
            "name": "acme",
            "display_name": "Acme Corp",
            "description": "",
            "enabled": false,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    assert_eq!(changed["enabled"], false);
    assert_eq!(changed["org_id"], org_id.as_str(), "{changed}");

    plane.add_org_member(&org_id, support::SUBJECT).await;
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{org_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "membership blocked the deletion"
    );
}
