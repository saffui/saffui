
#[allow(unused_imports)]
use super::support;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use super::support::Plane;

const REALM: &str = support::REALM;

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        sealing: support::sealing(),
        egress: config::serving::Egress::Outward,
    }
}

async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
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

/// A user's memberships are answerable from the user: the roles they hold
/// directly and through their groups as one deduplicated list, the groups
/// themselves, and their organizations. A name nobody holds answers 404.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_user_answers_for_their_own_memberships() {
    let plane = Plane::with_actions(&[
        AdminAction::UserRead,
        AdminAction::RoleRead,
        AdminAction::RoleWrite,
        AdminAction::GroupRead,
        AdminAction::GroupWrite,
        AdminAction::OrgRead,
        AdminAction::OrgWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}");

    // A role granted directly, and another reached only through a group.
    let (status, direct) = asked(
        &plane,
        Method::POST,
        &format!("{base}/roles"),
        &bearer,
        Some(
            serde_json::json!({ "name": "auditor", "display_name": "Auditor",
            "description": "" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{direct}");
    let direct = direct["role_id"].as_str().expect("a role").to_owned();
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/roles/{direct}/holders/{}", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, inherited) = asked(
        &plane,
        Method::POST,
        &format!("{base}/roles"),
        &bearer,
        Some(
            serde_json::json!({ "name": "reader", "display_name": "Reader",
            "description": "" }),
        ),
    )
    .await;
    let inherited = inherited["role_id"].as_str().expect("a role").to_owned();
    let (status, group) = asked(
        &plane,
        Method::POST,
        &format!("{base}/groups"),
        &bearer,
        Some(
            serde_json::json!({ "name": "finance", "display_name": "Finance",
            "description": "" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    let group = group["group_id"].as_str().expect("a group").to_owned();
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/groups/{group}/members/{}", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/groups/{group}/roles/{inherited}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // An organization membership beside them.
    let (_, org) = asked(
        &plane,
        Method::POST,
        &format!("{base}/organizations"),
        &bearer,
        Some(
            serde_json::json!({ "name": "acme", "display_name": "Acme Corp",
            "description": "", "enabled": true }),
        ),
    )
    .await;
    let org = org["org_id"].as_str().expect("an org").to_owned();
    plane.add_org_member(&org, support::SUBJECT).await;

    // The user answers with all of it.
    let (status, roles) = asked(
        &plane,
        Method::GET,
        &format!("{base}/users/{}/roles", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{roles}");
    let names: Vec<&str> = roles["roles"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|role| role["name"].as_str())
        .collect();
    assert!(names.contains(&"auditor"), "{roles}");
    assert!(
        names.contains(&"reader"),
        "the group's role was not folded in: {roles}"
    );

    let (status, groups) = asked(
        &plane,
        Method::GET,
        &format!("{base}/users/{}/groups", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{groups}");
    assert_eq!(groups["groups"][0]["name"], "finance", "{groups}");

    let (status, organizations) = asked(
        &plane,
        Method::GET,
        &format!("{base}/users/{}/organizations", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{organizations}");
    assert_eq!(
        organizations["organizations"][0]["display_name"], "Acme Corp",
        "{organizations}"
    );

    // A name nobody holds answers not-found, on all three.
    for leaf in ["roles", "groups", "organizations"] {
        let (status, _) = asked(
            &plane,
            Method::GET,
            &format!("{base}/users/nobody-here/{leaf}"),
            &bearer,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{leaf}");
    }
}
