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

/// The report is read as the bytes it was hashed as, never as a value to
/// render again: re-rendering would test that two renderers agree.
async fn read_bytes(plane: &Plane, path: &str, bearer: &str) -> (StatusCode, Vec<u8>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let asking = test::TestRequest::default()
        .method(Method::GET)
        .uri(path)
        .insert_header(("authorization", format!("Bearer {bearer}")));
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    (status, test::read_body(response).await.to_vec())
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

async fn planted_group(plane: &Plane, group: &str, confers: &str) {
    use models::auditable::AuditableModel;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    store::providers::roles::create_group(
        &transaction,
        &models::entities::authz::GroupModel {
            group_id: group.into(),
            realm_id: REALM.into(),
            name: group.into(),
            display_name: String::new(),
            description: String::new(),
            is_default: false,
            parent_id: None,
            metadata: AuditableModel::from_creator(support::TENANT.into(), "root".into()),
        },
    )
    .await
    .unwrap();
    store::providers::roles::grant_to_group(&transaction, group, confers)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

async fn planted_person(plane: &Plane, named: &str, roles: &[&str], groups: &[&str]) {
    use models::auditable::AuditableModel;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    store::providers::users::create(
        &transaction,
        &models::entities::user::UserModel {
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
        },
    )
    .await
    .unwrap();
    for role in roles {
        store::providers::roles::grant_to_user(&transaction, named, role)
            .await
            .unwrap();
    }
    for group in groups {
        store::providers::roles::add_to_group(&transaction, named, group)
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();
}

/// A second administrator, to prove a caller who is not the campaign's
/// reviewer decides nothing.
async fn planted_admin_token(plane: &Plane, named: &str) -> String {
    planted_person(plane, named, &["admins"], &[]).await;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
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

/// Widen what a group confers after its membership was certified, which is
/// the drift a certification must not cover.
async fn group_gains(plane: &Plane, group: &str, role: &str) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    store::providers::roles::grant_to_group(&transaction, group, role)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

async fn chain_holds(plane: &Plane) -> bool {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    store::audit::verify(&transaction, support::sealing().provider.digest())
        .await
        .expect("a chain to read")
        .holds()
}

fn said(told: &Value) -> String {
    told["message"].as_str().unwrap_or_default().to_owned()
        + told["detail"].as_str().unwrap_or_default()
}

fn item_of<'a>(items: &'a [Value], kind: &str, reference: &str) -> &'a Value {
    items
        .iter()
        .find(|item| item["edge_kind"] == kind && item["edge_ref"] == reference)
        .unwrap_or_else(|| panic!("an item for {kind} {reference} among {items:?}"))
}

/// A campaign freezes what stands, the reviewer judges that picture, and
/// the close pulls what nobody stood behind, keeps what was certified on a
/// picture that still holds, and seals a report the chain vouches for.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_review_judges_a_frozen_picture_and_closes_on_a_signed_one() {
    let plane = Plane::with_actions(&[
        AdminAction::IgaRead,
        AdminAction::IgaWrite,
        AdminAction::RoleWrite,
    ])
    .await;
    let reviewer = plane.token(&support::claims());
    let stranger = planted_admin_token(&plane, "hopper").await;
    for role in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"] {
        planted_role(&plane, role).await;
    }
    planted_group(&plane, "crew", "alpha").await;
    planted_person(
        &plane,
        "grace",
        &["beta", "delta", "epsilon", "zeta"],
        &["crew"],
    )
    .await;

    // One governed grant, so an edge that knows where it came from is under
    // review beside the hand-made ones.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/grants"),
        &reviewer,
        Some(json!({
            "user_id": "grace",
            "role_id": "gamma",
            "expires_at": (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339(),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");

    // The opening door refuses what could not be reviewed.
    for (body, why) in [
        (json!({ "reviewer_id": support::SUBJECT }), "no name"),
        (json!({ "name": "Q3" }), "no reviewer"),
        (
            json!({ "name": "Q3", "reviewer_id": "nobody" }),
            "an unknown reviewer",
        ),
        (
            json!({ "name": "Q3", "reviewer_id": support::SUBJECT, "scope_kind": "everything" }),
            "an unknown scope",
        ),
        (
            json!({ "name": "Q3", "reviewer_id": support::SUBJECT, "scope_kind": "role" }),
            "a role scope naming no role",
        ),
        (
            json!({ "name": "Q3", "reviewer_id": support::SUBJECT, "scope_kind": "role",
                "scope_ref": "ghost" }),
            "a role that is not there",
        ),
    ] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &format!("/admin/realms/{REALM}/iga/campaigns"),
            &reviewer,
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{why}: {told}");
    }

    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/campaigns"),
        &reviewer,
        Some(json!({
            "name": "Third quarter",
            "scope_kind": "realm",
            "reviewer_id": support::SUBJECT,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let campaign = told["campaign_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    assert_eq!(told["state"], "draft");

    // A draft holds no picture yet.
    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/iga/campaigns/{campaign}/items"),
        &reviewer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(told.as_array().expect("a list").is_empty(), "{told}");

    // Activation freezes it, once: the reviewer's own edges are left out
    // and counted rather than left for them to wave through.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/campaigns/{campaign}/activate"),
        &reviewer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["frozen"], 7, "{told}");
    assert_eq!(
        told["excluded"], 1,
        "the reviewer's own role was reviewable"
    );

    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/campaigns/{campaign}/activate"),
        &reviewer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a second snapshot was taken"
    );

    let (_, told) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/iga/campaigns/{campaign}/items"),
        &reviewer,
        None,
    )
    .await;
    let all = told.as_array().expect("a list").clone();
    assert!(
        all.iter()
            .all(|item| item["subject_id"] != support::SUBJECT),
        "the reviewer is under their own review: {told}"
    );
    let mine: Vec<Value> = all
        .iter()
        .filter(|item| item["subject_id"] == "grace")
        .cloned()
        .collect();
    assert_eq!(mine.len(), 6, "{told}");
    // The governed grant is a grant, not a plain role: that is the edge a
    // revocation would pull, and it carries where it came from.
    let gamma = item_of(&mine, "grant", "gamma");
    assert_eq!(gamma["frozen"]["kind"], "grant");
    assert!(gamma["frozen"]["until"].is_string(), "{gamma}");
    assert_eq!(item_of(&mine, "role", "beta")["frozen"]["kind"], "role");
    assert_eq!(
        item_of(&mine, "group", "crew")["frozen"]["confers"],
        json!(["alpha"])
    );

    // Only the campaign's reviewer decides, only with words where words are
    // owed, and only within the campaign the path names.
    let beta = item_of(&mine, "role", "beta")["item_id"]
        .as_str()
        .expect("an item")
        .to_owned();
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/campaigns/{campaign}/items/{beta}/decide"),
        &stranger,
        Some(json!({ "decision": "certify" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(said(&told).contains("reviewer"), "{told}");

    for (body, why) in [
        (json!({ "decision": "shrug" }), "a decision nobody defined"),
        (
            json!({ "decision": "revoke" }),
            "a revocation without words",
        ),
        (
            json!({ "decision": "abstain" }),
            "an abstention without words",
        ),
    ] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &format!("/admin/realms/{REALM}/iga/campaigns/{campaign}/items/{beta}/decide"),
            &reviewer,
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{why}: {told}");
    }
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/campaigns/elsewhere/items/{beta}/decide"),
        &reviewer,
        Some(json!({ "decision": "certify" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "an item of another campaign");

    // The trail keeps every decision and the last one written stands.
    let decide = |item: String, body: Value| {
        let campaign = campaign.clone();
        let reviewer = reviewer.clone();
        let plane = &plane;
        async move {
            let (status, told) = asked(
                plane,
                Method::POST,
                &format!("/admin/realms/{REALM}/iga/campaigns/{campaign}/items/{item}/decide"),
                &reviewer,
                Some(body),
            )
            .await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
        }
    };
    decide(
        beta.clone(),
        json!({ "decision": "revoke", "justification": "first thought" }),
    )
    .await;
    decide(beta.clone(), json!({ "decision": "certify" })).await;

    let crew = item_of(&mine, "group", "crew")["item_id"]
        .as_str()
        .expect("an item")
        .to_owned();
    decide(crew.clone(), json!({ "decision": "certify" })).await;

    let gamma_item = gamma["item_id"].as_str().expect("an item").to_owned();
    decide(
        gamma_item,
        json!({ "decision": "revoke", "justification": "the quarter is over" }),
    )
    .await;

    let epsilon = item_of(&mine, "role", "epsilon")["item_id"]
        .as_str()
        .expect("an item")
        .to_owned();
    decide(
        epsilon,
        json!({ "decision": "abstain", "justification": "not my call" }),
    )
    .await;

    let delta = item_of(&mine, "role", "delta")["item_id"]
        .as_str()
        .expect("an item")
        .to_owned();
    decide(
        delta,
        json!({ "decision": "revoke", "justification": "gone by Friday" }),
    )
    .await;

    // Two things move under the frozen picture before the close reaches it:
    // an edge is pulled by another hand, and a certified group widens.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/roles/delta/holders/grace"),
        &reviewer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    group_gains(&plane, "crew", "zeta").await;

    // The close: certified stays, drift is named rather than attested to,
    // and everything else goes.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/iga/campaigns/{campaign}/close"),
        &reviewer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["certified"], 1, "{told}");
    assert_eq!(told["drifted"], 1, "the widened group was attested to");
    assert_eq!(told["already_removed"], 1, "{told}");
    assert_eq!(
        told["revoked"], 4,
        "the revoked, the abstained, the undecided, and the stranger's own"
    );
    let digest = told["report_digest"].as_str().expect("a digest").to_owned();
    assert!(told["anchored_at"].as_i64().expect("a sequence") > 0);

    let after = roles_of(&plane, "grace").await;
    assert!(after.contains(&"beta".to_owned()), "{after:?}");
    assert!(
        after.contains(&"alpha".to_owned()),
        "a drifted certification pulled the membership: {after:?}"
    );
    for gone in ["gamma", "epsilon"] {
        assert!(
            !after.contains(&gone.to_owned()),
            "{gone} stands: {after:?}"
        );
    }
    assert!(
        !roles_of(&plane, "hopper").await.contains(&"admins".into()),
        "nobody stood behind it and it stands"
    );
    assert!(
        roles_of(&plane, support::SUBJECT)
            .await
            .contains(&"admins".to_owned()),
        "the excluded reviewer was pulled by their own campaign"
    );

    // The report is reproducible: the bytes served are the bytes hashed,
    // and the chain carries that digest.
    let (status, rendered) = read_bytes(
        &plane,
        &format!("/admin/realms/{REALM}/iga/campaigns/{campaign}/report"),
        &reviewer,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let recomputed: String = support::sealing()
        .provider
        .digest()
        .hash(crypto::provider::HashAlg::Sha256, &rendered)
        .expect("a digest")
        .iter()
        .map(|held| format!("{held:02x}"))
        .collect();
    assert_eq!(recomputed, digest, "the report does not hash to its digest");
    assert!(
        chain_holds(&plane).await,
        "the chain broke under the anchor"
    );

    let report: Value = serde_json::from_slice(&rendered).expect("a report");
    assert_eq!(report["schema"], "saffui.recert.report/1");
    assert_eq!(report["items"].as_array().expect("items").len(), 7);
    let crew_line = report["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|line| line["edge_ref"] == "crew")
        .expect("the crew line");
    assert_eq!(crew_line["resolution"], "drifted");
    assert_eq!(
        crew_line["frozen"]["confers"],
        json!(["alpha"]),
        "the report tells what was reviewed, not what stands now"
    );
    let gamma_line = report["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|line| line["edge_ref"] == "gamma")
        .expect("the gamma line");
    assert!(
        gamma_line["justification_hash"].is_string()
            && !rendered
                .windows(19)
                .any(|window| window == b"the quarter is over"),
        "the reasoning rode into the report instead of being bound to it"
    );

    // A closed campaign is closed: nothing decides, nothing closes twice.
    for (method, path) in [
        (
            Method::POST,
            format!("/admin/realms/{REALM}/iga/campaigns/{campaign}/close"),
        ),
        (
            Method::POST,
            format!("/admin/realms/{REALM}/iga/campaigns/{campaign}/items/{crew}/decide"),
        ),
    ] {
        let (status, told) = asked(
            &plane,
            method,
            &path,
            &reviewer,
            Some(json!({ "decision": "certify" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{path}: {told}");
    }
}
