#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;

fn mounted(plane: &Plane) -> server::api::config::Plane {
    server::api::config::Plane {
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
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
        ceiling: support::ceiling(),
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

async fn planted_role(plane: &Plane, role: &str) {
    use models::auditable::AuditableModel;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let model = models::entities::authz::RoleMutationModel {
        name: role.into(),
        description: String::new(),
        display_name: String::new(),
        client_id: None,
        admin_actions: None,
    }
    .into_model(
        role.into(),
        REALM.into(),
        AuditableModel::from_creator(support::TENANT.into(), "root".into()),
    );
    store::providers::roles::create(&transaction, &model)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

/// A group carrying one role, so the membership door is a second way to
/// reach the toxic pair.
async fn planted_group_holding(plane: &Plane, group: &str, role: &str) {
    use models::auditable::AuditableModel;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let model = models::entities::authz::GroupModel {
        group_id: group.into(),
        realm_id: REALM.into(),
        name: group.into(),
        display_name: String::new(),
        description: String::new(),
        is_default: false,
        parent_id: None,
        metadata: AuditableModel::from_creator(support::TENANT.into(), "root".into()),
    };
    store::providers::roles::create_group(&transaction, &model)
        .await
        .unwrap();
    store::providers::roles::grant_to_group(&transaction, group, role)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

async fn roles_of(plane: &Plane, user: &str) -> Vec<String> {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    store::providers::roles::effective_roles(&transaction, user)
        .await
        .unwrap()
        .into_iter()
        .map(|role| role.role_id)
        .collect()
}

/// Age the one standing exception past its end, the way the clock would.
async fn lapsed_exception(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let aged = transaction
        .execute(
            "UPDATE sod_exceptions SET valid_until = now() - interval '1 hour'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(aged, 1, "one exception to age");
    transaction.commit().await.unwrap();
}

/// The separation holds at every granting door, refuses in words, excuses
/// exactly the combination an exception covers, and shows what stands.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn duties_separate_at_every_door_and_an_excuse_covers_exactly() {
    let plane = Plane::with_actions(&[
        AdminAction::IgaRead,
        AdminAction::IgaWrite,
        AdminAction::RoleWrite,
        AdminAction::GroupWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    for role in ["payer", "approver", "auditor", "bystander", "clerk"] {
        planted_role(&plane, role).await;
    }
    planted_group_holding(&plane, "approvers", "approver").await;
    let subject = support::SUBJECT;

    // The rule door refuses what could not separate anything.
    for (body, why) in [
        (json!({ "roles": ["payer"] }), "one role"),
        (json!({ "roles": ["payer", "payer"] }), "a doubled role"),
        (
            json!({ "roles": ["payer", "approver"], "min_conflicting": 1 }),
            "a threshold of one",
        ),
        (
            json!({ "roles": ["payer", "approver"], "min_conflicting": 3 }),
            "a threshold past the set",
        ),
        (json!({ "roles": ["payer", "ghost"] }), "an unknown role"),
    ] {
        let (status, told) = asked(
            &plane,
            Method::PUT,
            &format!("/admin/realms/{REALM}/iga/sod/rules/payments"),
            &bearer,
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{why}: {told}");
    }
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/iga/sod/rules/payments"),
        &bearer,
        Some(json!({
            "roles": ["payer", "approver", "auditor"],
            "min_conflicting": 2,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    // Below the threshold, grants land; the completing grant is refused in
    // words at each of the three doors, and nothing of it remains.
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/roles/payer/holders/{subject}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/roles/approver/holders/{subject}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let said = told["message"].as_str().unwrap_or_default().to_owned()
        + told["detail"].as_str().unwrap_or_default();
    assert!(
        said.contains("payments") && said.contains("payer") && said.contains("approver"),
        "the refusal names the rule and the pair: {told}"
    );
    assert!(
        !roles_of(&plane, subject).await.contains(&"approver".into()),
        "the refused grant landed anyway"
    );

    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/groups/approvers/members/{subject}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the group door reached the same pair"
    );
    assert!(
        !roles_of(&plane, subject).await.contains(&"approver".into()),
        "the refused membership granted through the side"
    );

    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/grants"),
        &bearer,
        Some(json!({
            "user_id": subject,
            "role_id": "approver",
            "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the timed door is a door like the others"
    );

    // A role the rule does not name passes.
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/roles/bystander/holders/{subject}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The exception door refuses what could not excuse: no justification,
    // fewer roles than the threshold, roles the rule does not separate.
    for (body, why) in [
        (
            json!({ "covered_roles": ["payer", "approver"], "valid_until":
                (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339() }),
            "no justification",
        ),
        (
            json!({ "covered_roles": ["payer"], "justification": "audit season",
                "valid_until": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339() }),
            "fewer than the threshold",
        ),
        (
            json!({ "covered_roles": ["payer", "bystander"], "justification": "audit season",
                "valid_until": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339() }),
            "a role outside the rule",
        ),
        (
            json!({ "covered_roles": ["payer", "approver"], "justification": "audit season",
                "valid_until": (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339() }),
            "an end already passed",
        ),
    ] {
        let (status, told) = asked(
            &plane,
            Method::PUT,
            &format!("/admin/realms/{REALM}/iga/sod/rules/payments/exceptions/{subject}"),
            &bearer,
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{why}: {told}");
    }

    // The excused pair lands; the set that grew past the excuse does not.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/iga/sod/rules/payments/exceptions/{subject}"),
        &bearer,
        Some(json!({
            "covered_roles": ["payer", "approver"],
            "justification": "audit season, two hats for a week",
            "valid_until": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/roles/approver/holders/{subject}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the excused pair still refused"
    );
    assert!(roles_of(&plane, subject).await.contains(&"approver".into()));
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/roles/auditor/holders/{subject}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the excuse covered two roles, not three"
    );

    // The standing, excused pair is visible, marked.
    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/iga/sod/violations"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let violations = told.as_array().expect("a list");
    assert_eq!(violations.len(), 1, "{told}");
    assert_eq!(violations[0]["rule_id"], "payments");
    assert_eq!(violations[0]["excused"], true, "{told}");

    // Lapsed, the excuse excuses nothing: while the pair stands uncovered,
    // no further grant lands, and the register says so.
    lapsed_exception(&plane).await;
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/roles/clerk/holders/{subject}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "hands already toxic take nothing more until excused or cleaned"
    );
    let (_, told) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/iga/sod/violations"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(told[0]["excused"], false, "{told}");

    // A disabled rule weighs nothing, and what it let through stands in the
    // register once the rule wakes: the detective's find.
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/iga/sod/rules/payments"),
        &bearer,
        Some(json!({
            "roles": ["payer", "approver", "auditor"],
            "min_conflicting": 2,
            "enabled": false,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/roles/auditor/holders/{subject}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a sleeping rule stopped a grant"
    );
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/iga/sod/rules/payments"),
        &bearer,
        Some(json!({
            "roles": ["payer", "approver", "auditor"],
            "min_conflicting": 2,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, told) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/iga/sod/violations"),
        &bearer,
        None,
    )
    .await;
    let held = told[0]["roles"].as_array().expect("the held set");
    assert_eq!(held.len(), 3, "{told}");

    // Taking back is never weighed, and with the rule gone the doors open.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/roles/auditor/holders/{subject}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/iga/sod/rules/payments"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/roles/auditor/holders/{subject}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "no rule, nothing weighs");
}
