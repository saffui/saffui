#[allow(unused_imports)]
use super::support;

use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;
use store::tenancy::TenantContext;
use super::support::Plane;

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

async fn walked(plane: &Plane) {
    server::jobs::deliver_every_realm(
        &plane.pool(),
        &plane.tenancy(),
        &support::sealing(),
        &support::origin(),
        1,
    )
    .await;
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

/// Give the person an attribute, so the composed rules have something to
/// read, and nudge the outbox so the walker converges them.
async fn attributed(plane: &Plane, bearer: &str, pairs: &[(&str, &str)]) {
    let attributes: serde_json::Map<String, Value> = pairs
        .iter()
        .map(|(named, value)| ((*named).to_owned(), json!(value)))
        .collect();
    let (status, told) = asked(
        plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/users/{}", support::SUBJECT),
        bearer,
        Some(json!({
            "user_name": support::SUBJECT,
            "enabled": true,
            "email": support::SUBJECT_EMAIL,
            "attributes": attributes,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
}

/// Time-bound access ends by the clock, and a composed predicate grants by
/// every term: the contractor clause holds a role back, the timed grant
/// falls at its end, and the ledger tells both stories.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn access_ends_by_the_clock_and_grants_by_the_terms() {
    let plane = Plane::with_actions(&[
        AdminAction::IgaRead,
        AdminAction::IgaWrite,
        AdminAction::UserRead,
        AdminAction::UserWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    for role in ["builders", "vault-access"] {
        planted_role(&plane, role).await;
    }

    // The composed rule: engineers who are not contractors build.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/iga/rules/builders"),
        &bearer,
        Some(json!({
            "when_expr": "department=eng && employment!=contractor",
            "roles": ["builders"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    // A rule carrying both shapes is refused: the expression is the whole
    // condition.
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/iga/rules/confused"),
        &bearer,
        Some(json!({
            "when_attribute": "department",
            "when_value": "eng",
            "when_expr": "department=eng",
            "roles": ["builders"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // As a contractor, the clause holds the role back; as staff, it grants.
    attributed(
        &plane,
        &bearer,
        &[("department", "eng"), ("employment", "contractor")],
    )
    .await;
    walked(&plane).await;
    assert!(
        !roles_of(&plane, support::SUBJECT)
            .await
            .contains(&"builders".to_owned()),
        "a contractor built anyway"
    );
    attributed(
        &plane,
        &bearer,
        &[("department", "eng"), ("employment", "staff")],
    )
    .await;
    walked(&plane).await;
    assert!(
        roles_of(&plane, support::SUBJECT)
            .await
            .contains(&"builders".to_owned()),
        "staff was not equipped"
    );

    // The timed grant: vault access until a breath ago, so the next pass
    // takes it back; and the ledger told both stories meanwhile.
    let soon = (chrono::Utc::now() + chrono::Duration::seconds(2)).to_rfc3339();
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/grants"),
        &bearer,
        Some(json!({
            "user_id": support::SUBJECT,
            "role_id": "vault-access",
            "expires_at": soon,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    assert!(
        roles_of(&plane, support::SUBJECT)
            .await
            .contains(&"vault-access".to_owned()),
        "the timed grant did not grant"
    );
    let (_, ledger) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/iga/grants/{}", support::SUBJECT),
        &bearer,
        None,
    )
    .await;
    let entries = ledger.as_array().expect("a ledger");
    assert!(
        entries
            .iter()
            .any(|held| held["role_id"] == "vault-access" && held["expires_at"].is_string()),
        "{ledger}"
    );
    assert!(
        entries
            .iter()
            .any(|held| held["role_id"] == "builders" && held["rule_id"] == "builders"),
        "{ledger}"
    );

    // An end without a date is refused: the end is the point.
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/grants"),
        &bearer,
        Some(json!({ "user_id": support::SUBJECT, "role_id": "vault-access" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Past the end, a converge takes the vault back and leaves the rule-born
    // role standing.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/converge"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let after = roles_of(&plane, support::SUBJECT).await;
    assert!(
        !after.contains(&"vault-access".to_owned()),
        "the clock ran out and nothing happened: {after:?}"
    );
    assert!(
        after.contains(&"builders".to_owned()),
        "the rule-born role went with it: {after:?}"
    );
}
