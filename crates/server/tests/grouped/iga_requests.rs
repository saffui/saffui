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

/// A second administrator, so a decision can come from other eyes: the
/// planted world holds one admin and four eyes need two.
async fn planted_admin(plane: &Plane, named: &str) -> String {
    use models::auditable::AuditableModel;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let person = models::entities::user::UserModel {
        user_id: named.into(),
        realm_id: REALM.into(),
        user_name: named.into(),
        enabled: true,
        email: format!("{named}@example.test"),
        email_verified: None,
        phone_number: None,
        phone_number_verified: None,
        required_actions: None,
        not_before: None,
        user_storage: None,
        attributes: None,
        is_service_account: None,
        service_account_client_link: None,
        metadata: AuditableModel::from_creator(support::TENANT.into(), "root".into()),
    };
    store::providers::users::create(&transaction, &person)
        .await
        .unwrap();
    store::providers::roles::grant_to_user(&transaction, named, "admins")
        .await
        .unwrap();
    store::providers::sessions::open(
        &transaction,
        &models::sessions::records::UserSessionModel {
            browser_state: None,
            tenant: support::TENANT.into(),
            session_id: format!("{named}-session"),
            realm_id: REALM.into(),
            user_id: named.into(),
            login_username: named.into(),
            broker_session_id: None,
            broker_user_id: None,
            auth_method: None,
            ip_address: None,
            user_agent: None,
            started_at: chrono::Utc::now().timestamp(),
            auth_time: None,
            loa: None,
            expiration: None,
            state: models::sessions::records::UserSessionState::LoggedIn,
            remember_me: None,
            last_session_refresh: None,
            is_offline: None,
            notes: None,
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();

    let mut claims = support::claims();
    claims.set_subject(named);
    claims
        .set_claim("sid", Some(json!(format!("{named}-session"))))
        .unwrap();
    plane.token(&claims)
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

async fn state_of(plane: &Plane, bearer: &str, request_id: &str) -> String {
    let (_, held) = asked(
        plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/iga/requests"),
        bearer,
        None,
    )
    .await;
    held.as_array()
        .expect("a list")
        .iter()
        .find(|row| row["request_id"] == request_id)
        .map(|row| row["state"].as_str().unwrap_or_default().to_owned())
        .expect("the request in the list")
}

fn said(told: &Value) -> String {
    told["message"].as_str().unwrap_or_default().to_owned()
        + told["detail"].as_str().unwrap_or_default()
}

/// Asking is not taking: a request is decided by other eyes, the grant is
/// issued by the governed path and weighed like any other, and a loser's
/// second decision stops at the transition.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_request_needs_a_second_pair_of_eyes() {
    let plane = Plane::with_actions(&[AdminAction::IgaRead, AdminAction::IgaWrite]).await;
    let asker = plane.token(&support::claims());
    let approver = planted_admin(&plane, "grace").await;
    for role in ["vault", "payer"] {
        planted_role(&plane, role).await;
    }
    let subject = support::SUBJECT;

    // The lodge door refuses what could not be decided.
    for (body, why) in [
        (
            json!({ "user_id": subject, "role_id": "vault" }),
            "no reason",
        ),
        (
            json!({ "user_id": "nobody", "role_id": "vault", "reason": "ops" }),
            "an unknown person",
        ),
        (
            json!({ "user_id": subject, "role_id": "ghost", "reason": "ops" }),
            "an unknown role",
        ),
        (
            json!({ "user_id": subject, "role_id": "vault", "reason": "ops",
                "expires_at": "2020-01-01T00:00:00Z" }),
            "an end already passed",
        ),
    ] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &format!("/admin/realms/{REALM}/iga/requests"),
            &asker,
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{why}: {told}");
    }

    // Lodged, and the asker's own approval is refused in the four-eyes
    // words while the request stays pending.
    let until = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests"),
        &asker,
        Some(json!({
            "user_id": subject,
            "role_id": "vault",
            "reason": "quarter close needs the vault",
            "expires_at": until,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let vault_request = told["request_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    assert_eq!(told["state"], "pending");

    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests/{vault_request}/approve"),
        &asker,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(said(&told).contains("four eyes"), "{told}");
    assert_eq!(state_of(&plane, &asker, &vault_request).await, "pending");

    // Other eyes grant it; the grant rides the governed path with the end
    // the request carried, and a second decision stops at the transition.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests/{vault_request}/approve"),
        &approver,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["state"], "granted");
    assert_eq!(told["decided_by"], "grace");
    assert!(roles_of(&plane, subject).await.contains(&"vault".into()));
    let (_, ledger) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/iga/grants/{subject}"),
        &asker,
        None,
    )
    .await;
    assert!(
        ledger
            .as_array()
            .expect("a ledger")
            .iter()
            .any(|held| held["role_id"] == "vault" && held["expires_at"].is_string()),
        "the granted request left no governed trace: {ledger}"
    );

    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests/{vault_request}/approve"),
        &approver,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(said(&told).contains("already decided"), "{told}");

    // A denial says why, or says nothing.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests"),
        &asker,
        Some(json!({ "user_id": subject, "role_id": "payer", "reason": "backup payer" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let payer_request = told["request_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests/{payer_request}/deny"),
        &approver,
        Some(json!({})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a wordless denial"
    );
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests/{payer_request}/deny"),
        &approver,
        Some(json!({ "reason": "one payer is enough" })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(state_of(&plane, &asker, &payer_request).await, "denied");
    assert!(
        !roles_of(&plane, subject).await.contains(&"payer".into()),
        "a denial granted"
    );

    // Withdrawing is the asker's own act and nobody else's.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests"),
        &asker,
        Some(json!({ "user_id": subject, "role_id": "payer", "reason": "asking again" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let withdrawn_request = told["request_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests/{withdrawn_request}/withdraw"),
        &approver,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "not the asker");
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests/{withdrawn_request}/withdraw"),
        &asker,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        state_of(&plane, &asker, &withdrawn_request).await,
        "withdrawn"
    );

    // A separation written between the asking and the deciding: the
    // approval weighs the world as it stands, refuses in the rule's words,
    // and the fallen transaction leaves the request pending. A fresh ask
    // for the same pair is refused at the lodge door with the same face.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests"),
        &asker,
        Some(json!({ "user_id": subject, "role_id": "payer", "reason": "third time" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let toxic_request = told["request_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/iga/sod/rules/treasury"),
        &asker,
        Some(json!({ "roles": ["vault", "payer"], "min_conflicting": 2 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests/{toxic_request}/approve"),
        &approver,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(said(&told).contains("treasury"), "{told}");
    assert_eq!(
        state_of(&plane, &asker, &toxic_request).await,
        "pending",
        "the fallen approval decided anyway"
    );
    assert!(
        !roles_of(&plane, subject).await.contains(&"payer".into()),
        "the refused approval granted anyway"
    );

    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/requests"),
        &asker,
        Some(json!({ "user_id": subject, "role_id": "payer", "reason": "fourth time" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        said(&told).contains("treasury"),
        "the lodge door wears a different face: {told}"
    );
}
