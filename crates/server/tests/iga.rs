mod support;

use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;
use support::Plane;

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
        egress: config::serving::Egress::Anywhere,
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

async fn planted_role(plane: &Plane, role_id: &str) {
    use store::tenancy::TenantContext;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let role = models::entities::authz::RoleMutationModel {
        name: role_id.into(),
        description: String::new(),
        display_name: String::new(),
        client_id: None,
        admin_actions: None,
    }
    .into_model(
        role_id.into(),
        REALM.into(),
        models::auditable::AuditableModel::from_creator(support::TENANT.into(), "root".into()),
    );
    store::providers::roles::create(&transaction, &role)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

async fn roles_of(plane: &Plane, user_id: &str) -> Vec<String> {
    use store::tenancy::TenantContext;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    store::providers::roles::effective_roles(&transaction, user_id)
        .await
        .unwrap()
        .into_iter()
        .map(|role| role.role_id)
        .collect()
}

async fn walked(plane: &Plane) {
    server::jobs::deliver_every_realm(&plane.pool(), &plane.tenancy(), &support::sealing(), 1)
        .await;
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_whole_working_life_converges_by_itself() {
    let plane = Plane::with_actions(&[
        AdminAction::IgaRead,
        AdminAction::IgaWrite,
        AdminAction::UserRead,
        AdminAction::UserWrite,
        AdminAction::ScimRead,
        AdminAction::ScimWrite,
        AdminAction::RoleRead,
        AdminAction::RoleWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    for role in ["staff", "engineers", "hr-readers", "hand-picked"] {
        planted_role(&plane, role).await;
    }

    // The rules: everybody is staff; a department carries its own role. A
    // rule naming an unknown role is refused at the plane.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/iga/rules/ghost-role"),
        &bearer,
        Some(json!({ "when_attribute": "*", "roles": ["nobody-has-this"] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    for (rule, body) in [
        (
            "everyone",
            json!({ "when_attribute": "*", "roles": ["staff"] }),
        ),
        (
            "eng",
            json!({ "when_attribute": "department", "when_value": "engineering", "roles": ["engineers"] }),
        ),
        (
            "hr",
            json!({ "when_attribute": "department", "when_value": "hr", "roles": ["hr-readers"] }),
        ),
    ] {
        let (status, told) = asked(
            &plane,
            Method::PUT,
            &format!("/admin/realms/{REALM}/iga/rules/{rule}"),
            &bearer,
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{told}");
    }

    // The joiner arrives by the SCIM door, department and all.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/realms/{REALM}/scim/v2/Users"),
        &bearer,
        Some(json!({
            "schemas": [services::scim::USER_SCHEMA],
            "userName": "grace",
            "active": true,
            "emails": [{ "value": "grace@example.test", "primary": true }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    // Her department lands as an attribute the way HR would set it.
    {
        use models::entities::attributes::AttributeValue;
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let mut person = store::providers::users::load(&transaction, "grace")
            .await
            .unwrap()
            .expect("grace");
        person
            .attributes
            .get_or_insert_with(Default::default)
            .insert(
                "department".into(),
                AttributeValue::Str("engineering".into()),
            );
        store::providers::users::update(&transaction, &person)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }
    walked(&plane).await;
    let held = roles_of(&plane, "grace").await;
    assert!(held.contains(&"staff".to_string()), "{held:?}");
    assert!(held.contains(&"engineers".to_string()), "{held:?}");

    // A hand-picked role rides along and belongs to no rule.
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::roles::grant_to_user(&transaction, "grace", "hand-picked")
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }

    // The mover: HR flips her department; the engine swaps the role and
    // leaves the hand-picked one alone.
    {
        use models::entities::attributes::AttributeValue;
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let mut person = store::providers::users::load(&transaction, "grace")
            .await
            .unwrap()
            .expect("grace");
        person
            .attributes
            .get_or_insert_with(Default::default)
            .insert("department".into(), AttributeValue::Str("hr".into()));
        store::providers::users::update(&transaction, &person)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }
    walked(&plane).await;
    let held = roles_of(&plane, "grace").await;
    assert!(held.contains(&"hr-readers".to_string()), "{held:?}");
    assert!(
        !held.contains(&"engineers".to_string()),
        "the old grant stayed: {held:?}"
    );
    assert!(
        held.contains(&"hand-picked".to_string()),
        "the manual grant was touched: {held:?}"
    );

    // The leaver: HR deactivates her through SCIM; the governed grants go,
    // the sessions close, the hand-picked role stays for the audit trail.
    let (_, found) = asked(
        &plane,
        Method::GET,
        &format!("/realms/{REALM}/scim/v2/Users?filter=userName%20eq%20%22grace%22"),
        &bearer,
        None,
    )
    .await;
    let scim_id = found["Resources"][0]["id"]
        .as_str()
        .expect("an id")
        .to_owned();
    let (status, _) = asked(
        &plane,
        Method::PATCH,
        &format!("/realms/{REALM}/scim/v2/Users/{scim_id}"),
        &bearer,
        Some(json!({
            "schemas": [services::scim::PATCH_SCHEMA],
            "Operations": [{ "op": "replace", "path": "active", "value": false }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    walked(&plane).await;
    let held = roles_of(&plane, "grace").await;
    assert!(!held.contains(&"staff".to_string()), "{held:?}");
    assert!(!held.contains(&"hr-readers".to_string()), "{held:?}");
    assert!(held.contains(&"hand-picked".to_string()), "{held:?}");

    // The return: reactivated, she is re-equipped by one pass.
    let (status, _) = asked(
        &plane,
        Method::PATCH,
        &format!("/realms/{REALM}/scim/v2/Users/{scim_id}"),
        &bearer,
        Some(json!({
            "schemas": [services::scim::PATCH_SCHEMA],
            "Operations": [{ "op": "replace", "path": "active", "value": true }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    walked(&plane).await;
    let held = roles_of(&plane, "grace").await;
    assert!(
        held.contains(&"staff".to_string()) && held.contains(&"hr-readers".to_string()),
        "{held:?}"
    );

    // A rule written after the fact reaches everybody through the realm
    // convergence, ada included.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/converge"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let held = roles_of(&plane, support::SUBJECT).await;
    assert!(
        held.contains(&"staff".to_string()),
        "the backfill missed ada: {held:?}"
    );
}
