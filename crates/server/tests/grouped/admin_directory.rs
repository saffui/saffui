#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::Value;

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

/// Birthright membership: a group marked default receives every account
/// created after, whichever door made it, and unmarking stops the intake
/// without touching anyone already inside.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_default_group_receives_the_newly_born() {
    let plane = Plane::with_actions(&[
        AdminAction::GroupRead,
        AdminAction::GroupWrite,
        AdminAction::UserRead,
        AdminAction::UserWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let groups = format!("/admin/realms/{REALM}/groups");

    let (status, born) = asked(
        &plane,
        Method::POST,
        &groups,
        &bearer,
        Some(serde_json::json!({ "name": "everyone", "description": "all of us" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let group_id = born["group_id"].as_str().expect("an identity").to_owned();

    let (status, marked) = asked(
        &plane,
        Method::PUT,
        &format!("{groups}/{group_id}"),
        &bearer,
        Some(serde_json::json!({ "name": "everyone", "is_default": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{marked}");

    let (status, made) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/users"),
        &bearer,
        Some(serde_json::json!({ "user_name": "newborn", "email": "new@acme.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");

    let (status, held) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/users/newborn/groups"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert!(
        held["groups"]
            .as_array()
            .expect("a membership listing")
            .iter()
            .any(|g| g["group_id"] == group_id.as_str() || g == &serde_json::json!(group_id)),
        "the newborn missed the default group: {held}"
    );

    // Unmarked, the intake stops; the next account stays out.
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("{groups}/{group_id}"),
        &bearer,
        Some(serde_json::json!({ "name": "everyone", "is_default": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/users"),
        &bearer,
        Some(serde_json::json!({ "user_name": "later", "email": "later@acme.test" })),
    )
    .await;
    let (_, held) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/users/later/groups"),
        &bearer,
        None,
    )
    .await;
    assert!(
        !held.to_string().contains(&group_id),
        "an unmarked group still swallowed the next account: {held}"
    );
}

/// A sub-group is a narrower slice of its parent: joining it is standing in
/// the parent too, so the parent's roles reach the member. The membership
/// listing stays literal, showing only the group actually joined.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_sub_group_hands_down_what_the_parent_holds() {
    let plane = Plane::with_actions(&[
        AdminAction::UserRead,
        AdminAction::RoleRead,
        AdminAction::RoleWrite,
        AdminAction::GroupRead,
        AdminAction::GroupWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}");

    let (status, parent) = asked(
        &plane,
        Method::POST,
        &format!("{base}/groups"),
        &bearer,
        Some(serde_json::json!({ "name": "engineering" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{parent}");
    let parent = parent["group_id"].as_str().expect("a group").to_owned();

    let (status, child) = asked(
        &plane,
        Method::POST,
        &format!("{base}/groups"),
        &bearer,
        Some(serde_json::json!({ "name": "backend", "parent_id": parent })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{child}");
    assert_eq!(child["parent_id"], parent.as_str(), "{child}");
    let child = child["group_id"].as_str().expect("a group").to_owned();

    let (_, role) = asked(
        &plane,
        Method::POST,
        &format!("{base}/roles"),
        &bearer,
        Some(serde_json::json!({ "name": "deployer", "description": "" })),
    )
    .await;
    let role = role["role_id"].as_str().expect("a role").to_owned();
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/groups/{parent}/roles/{role}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/groups/{child}/members/{}", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, roles) = asked(
        &plane,
        Method::GET,
        &format!("{base}/users/{}/roles", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{roles}");
    assert!(
        roles["roles"]
            .as_array()
            .expect("a list")
            .iter()
            .any(|held| held["name"] == "deployer"),
        "the parent's role did not reach the sub-group's member: {roles}"
    );

    let (_, held) = asked(
        &plane,
        Method::GET,
        &format!("{base}/users/{}/groups", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    let listed = held["groups"].as_array().expect("a membership listing");
    assert!(
        listed.iter().any(|g| g["group_id"] == child.as_str()),
        "{held}"
    );
    assert!(
        !listed.iter().any(|g| g["group_id"] == parent.as_str()),
        "the listing invented a membership nobody joined: {held}"
    );
}

/// The chain refuses to close on itself, a parent must exist, and a parent
/// still carrying sub-groups is not deleted.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_group_chain_stays_a_tree() {
    let plane = Plane::with_actions(&[AdminAction::GroupRead, AdminAction::GroupWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/groups");

    let (_, top) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({ "name": "ops" })),
    )
    .await;
    let top = top["group_id"].as_str().expect("a group").to_owned();
    let (_, under) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({ "name": "oncall", "parent_id": top })),
    )
    .await;
    let under = under["group_id"].as_str().expect("a group").to_owned();

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{top}"),
        &bearer,
        Some(serde_json::json!({ "name": "ops", "parent_id": under })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({ "name": "orphan", "parent_id": "group-nobody" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{top}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{under}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{top}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// An address is either absent or the shape of one, at birth and on rewrite.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_address_that_is_not_one_is_refused() {
    let plane = Plane::with_actions(&[AdminAction::UserRead, AdminAction::UserWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/users");

    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({ "user_name": "misspelt", "email": "not-an-address" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, made) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({ "user_name": "spelt", "email": "spelt@acme.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/spelt"),
        &bearer,
        Some(serde_json::json!({ "email": "two@@ats" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // Clearing is not misspelling: emptiness is absence.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/spelt"),
        &bearer,
        Some(serde_json::json!({ "email": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
}

/// An address one account holds is refused to a second, until the realm says
/// sharing is allowed; the holder may keep re-stating their own.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_address_is_one_accounts_until_the_realm_shares_it() {
    let plane = Plane::with_actions(&[AdminAction::UserRead, AdminAction::UserWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/users");

    let (status, made) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({ "user_name": "first", "email": "shared@acme.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");

    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({ "user_name": "second", "email": "shared@acme.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // The holder repeating their own address is not a collision.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/first"),
        &bearer,
        Some(serde_json::json!({ "email": "shared@acme.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    // The realm opens sharing, and the second account is let in.
    plane.share_addresses(true).await;
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({ "user_name": "second", "email": "shared@acme.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
}

/// An account is born with a drawn identity apart from its name, answers to
/// both, and is renamed only where the realm allows it; the identity and
/// everything pointing at it never move.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_name_is_the_persons_and_the_identity_is_the_realms() {
    let plane = Plane::with_actions(&[
        AdminAction::UserRead,
        AdminAction::UserWrite,
        AdminAction::RealmRead,
        AdminAction::RealmWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/users");

    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(serde_json::json!({ "user_name": "grace", "email": "grace@acme.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let drawn = born["user_id"].as_str().expect("an identity").to_owned();
    assert_ne!(drawn, "grace", "the identity is still the name");
    assert_eq!(drawn.len(), 36, "not a UUID: {drawn}");
    assert_eq!(drawn.matches('-').count(), 4, "not a UUID: {drawn}");

    // Both handles answer, and they answer the same person.
    let (status, by_name) =
        asked(&plane, Method::GET, &format!("{base}/grace"), &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{by_name}");
    assert_eq!(by_name["user_id"], drawn.as_str());
    let (status, by_id) = asked(
        &plane,
        Method::GET,
        &format!("{base}/{drawn}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{by_id}");

    // Renaming is the realm's to allow.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{drawn}"),
        &bearer,
        Some(serde_json::json!({ "user_name": "grace-hopper" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}"),
        &bearer,
        Some(serde_json::json!({ "edit_user_name_allowed": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, renamed) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{drawn}"),
        &bearer,
        Some(serde_json::json!({ "user_name": "grace-hopper" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{renamed}");
    assert_eq!(
        renamed["user_id"],
        drawn.as_str(),
        "the rename moved the identity"
    );
    assert_eq!(renamed["user_name"], "grace-hopper");

    // The new name answers; the old one is nobody.
    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("{base}/grace-hopper"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["user_id"], drawn.as_str());
    let (status, _) = asked(&plane, Method::GET, &format!("{base}/grace"), &bearer, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
