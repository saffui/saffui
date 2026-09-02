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

    // Granted over the plane, deletion is told no rather than the holder
    // losing it silently.
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{role_id}/holders/{}", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
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

    // The refusal points here: who holds it, and through what.
    let (status, held) = asked(
        &plane,
        Method::GET,
        &format!("{base}/{role_id}/holders"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(held["users"][0], support::SUBJECT, "{held}");

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{role_id}/holders/{}", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
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

/// Granting is charged by what is granted: holding the group is not holding
/// its roles, or group curators could hand themselves anything.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn granting_a_role_to_a_group_costs_the_role_capability() {
    let plane = Plane::with_actions(&[
        AdminAction::GroupRead,
        AdminAction::GroupWrite,
        AdminAction::RoleRead,
        AdminAction::RoleWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    let (_, group) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/groups"),
        &bearer,
        Some(serde_json::json!({ "name": "curators" })),
    )
    .await;
    let group_id = group["group_id"].as_str().expect("an identity").to_owned();
    let (_, role) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/roles"),
        &bearer,
        Some(serde_json::json!({ "name": "curation" })),
    )
    .await;
    let role_id = role["role_id"].as_str().expect("an identity").to_owned();

    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/groups/{group_id}/roles/{role_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The grant shows up in the group's membership, and holds the deletion.
    let (_, membership) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/groups/{group_id}/membership"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(membership["roles"][0], role_id.as_str(), "{membership}");
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/roles/{role_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a group-held role was deleted"
    );
}

/// Each missing end of a grant is named for what it is.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_grant_names_which_end_is_missing() {
    let plane = Plane::with_actions(&[AdminAction::RoleRead, AdminAction::RoleWrite]).await;
    let bearer = plane.token(&support::claims());
    let (_, role) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/roles"),
        &bearer,
        Some(serde_json::json!({ "name": "orphaned" })),
    )
    .await;
    let role_id = role["role_id"].as_str().expect("an identity").to_owned();

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/roles/{role_id}/holders/nobody-here"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(told["error_code"], "user.not_found", "{told}");

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!(
            "/admin/realms/{REALM}/roles/role-that-is-not/holders/{}",
            support::SUBJECT
        ),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(told["error_code"], "role.not_found", "{told}");
}

/// An organization's membership over the plane, end to end.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn organization_membership_lives_over_the_plane() {
    let plane = Plane::with_actions(&[AdminAction::OrgRead, AdminAction::OrgWrite]).await;
    let bearer = plane.token(&support::claims());
    let (_, org) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/organizations"),
        &bearer,
        Some(serde_json::json!({ "name": "guild" })),
    )
    .await;
    let org_id = org["org_id"].as_str().expect("an identity").to_owned();
    let base = format!("/admin/realms/{REALM}/organizations/{org_id}/members");

    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{}", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, members) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(members[0]["user_id"], support::SUBJECT, "{members}");

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{}", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, members) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(members.as_array().map(Vec::len), Some(0), "{members}");
}

/// The narrow half of the charge, on its own plane: two planted worlds in one
/// process wait on each other's pool forever, so the wide and the narrow
/// caller each get a test. The guard charges before the handler runs, so the
/// ids need not exist for the refusal to be the capability's.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn holding_the_group_is_not_holding_its_roles() {
    let plane = Plane::with_actions(&[AdminAction::GroupRead, AdminAction::GroupWrite]).await;
    let bearer = plane.token(&support::claims());
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/groups/any/roles/any"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A domain's whole life on an organization: claimed with a challenge the
/// operator can publish, listed pending on the organization itself, proven,
/// and taken away. Nothing routes while unproven, and an unknown domain or
/// organization answers not-found.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_domain_is_claimed_proven_and_taken_away() {
    let plane = Plane::with_actions(&[AdminAction::OrgRead, AdminAction::OrgWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/organizations");

    let (_, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({
            "name": "acme", "display_name": "Acme Corp",
            "description": "", "enabled": true,
        })),
    )
    .await;
    let org = born["org_id"].as_str().expect("an identity").to_owned();

    let (status, claimed) = asked(
        &plane,
        Method::POST,
        &format!("{base}/{org}/domains"),
        &bearer,
        Some(serde_json::json!({ "domain": " Acme.Example " })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{claimed}");
    assert_eq!(claimed["domain"], "acme.example", "{claimed}");
    assert!(
        claimed["challenge"]
            .as_str()
            .is_some_and(|held| held.starts_with("saffui-domain-")),
        "{claimed}"
    );

    // The organization now carries it, unproven.
    let (_, held) = asked(&plane, Method::GET, &format!("{base}/{org}"), &bearer, None).await;
    assert_eq!(held["domains"][0]["name"], "acme.example", "{held}");
    assert_eq!(held["domains"][0]["verified"], false, "{held}");

    // A second claim of the same domain is a conflict, not a rewrite.
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("{base}/{org}/domains"),
        &bearer,
        Some(serde_json::json!({ "domain": "acme.example" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("{base}/{org}/domains/acme.example/verify"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, held) = asked(&plane, Method::GET, &format!("{base}/{org}"), &bearer, None).await;
    assert_eq!(held["domains"][0]["verified"], true, "{held}");

    // Verifying what is not claimed, on this or any organization, is 404.
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("{base}/{org}/domains/nowhere.example/verify"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{org}/domains/acme.example"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, held) = asked(&plane, Method::GET, &format!("{base}/{org}"), &bearer, None).await;
    assert_eq!(held["domains"].as_array().map(Vec::len), Some(0), "{held}");
}
