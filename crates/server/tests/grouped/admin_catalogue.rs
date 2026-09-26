#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};

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
    let told = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, told)
}

/// The decision log forgets only when told, and only up to the named
/// instant.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_decision_log_forgets_only_when_told() {
    use models::entities::authz::{AuthzDecisionRecord, Decision, ReportedDecision};
    let plane = Plane::with_actions(&[
        AdminAction::AuthzDecisionRead,
        AdminAction::AuthzDecisionWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    {
        use store::tenancy::TenantContext;
        let transaction = plane
            .scoped(&TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::authorization::authz_policies::record(
            &transaction,
            &AuthzDecisionRecord {
                decision_id: "remembered".to_owned(),
                tenant: support::TENANT.to_owned(),
                realm_id: REALM.to_owned(),
                subject_type: "user".to_owned(),
                subject_id: "ada".to_owned(),
                resource_kind: "resource".to_owned(),
                resource_ref: Some("doc".to_owned()),
                action: "read".to_owned(),
                reported: ReportedDecision::Permit,
                computed: Decision::Permit,
                detail: json!({}),
                duration_us: 10,
                trace_id: None,
                occurred_at_millis: None,
            },
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }

    let decisions = format!("/admin/realms/{REALM}/authz/decisions");
    let (status, told) = asked(&plane, Method::GET, &decisions, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert!(!told.as_array().expect("a log").is_empty());

    // No bound, no forgetting: everything must be asked for in so many words.
    let (status, _) = asked(&plane, Method::DELETE, &decisions, &bearer, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A cut before the record leaves it standing.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{decisions}?before=2000-01-01T00:00:00Z"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["removed"], 0);

    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{decisions}?before=2100-01-01T00:00:00Z"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["removed"], 1);
    let (_, told) = asked(&plane, Method::GET, &decisions, &bearer, None).await;
    assert!(told.as_array().expect("a log").is_empty(), "{told}");
}

/// The last three families split like all the others, and the feature
/// registry answers what the build carries.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_last_capabilities_split_where_they_should() {
    let plane = Plane::with_actions(&[
        AdminAction::RebacRead,
        AdminAction::AuthzDecisionRead,
        AdminAction::FeatureRead,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    let (status, told) = asked(&plane, Method::GET, "/admin/features", &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let listed = told.as_array().expect("a registry");
    assert_eq!(listed.len(), commons::feature::Feature::ALL.len(), "{told}");
    assert!(
        listed.iter().any(|held| held["slug"] == "pq-hybrid"
            && held["compiled"].is_boolean()
            && held["enabled"].is_boolean()),
        "{told}"
    );

    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/rebac/schema"),
        &bearer,
        Some(json!({ "source": "definition user {}" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/authz/decisions?before=2100-01-01T00:00:00Z"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
