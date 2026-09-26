#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;

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
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// The relation store is experimental, so a process that says nothing does
/// not run it: its doors refuse, a relationship is walked for nobody even
/// over tuples already written, a user-managed resource is not shared, and a
/// realm cannot open it from underneath. A share is still taken back.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_relation_store_runs_only_where_the_process_asked_for_it() {
    assert!(
        !server::api::config::features().is_enabled(commons::feature::Feature::RebacStore),
        "this binary's process runs the relation store unasked"
    );
    let plane = Plane::with_actions(&[
        AdminAction::FeatureRead,
        AdminAction::FeatureWrite,
        AdminAction::UmaRead,
        AdminAction::UmaWrite,
        AdminAction::RebacRead,
        AdminAction::RebacWrite,
        AdminAction::AuthzDecisionWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    let (status, listed) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/features"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let store = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["slug"] == "rebac-store")
        .expect("the relation store is listed");
    assert_eq!(
        (&store["standing"], &store["in_process"], &store["enabled"]),
        (&json!("off"), &json!(false), &json!(false)),
        "{store}"
    );

    for (method, leaf) in [(Method::GET, "schema"), (Method::GET, "tuples")] {
        let (status, told) = asked(
            &plane,
            method,
            &format!("/admin/realms/{REALM}/rebac/{leaf}"),
            &bearer,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{leaf} answers: {told}");
    }

    // Tuples written straight to the store, as they would stand from before
    // the store was closed: no question walks them.
    {
        let transaction = plane
            .scoped(&TenantContext::new(support::TENANT, REALM))
            .await;
        services::authorization::rebac::publish(
            &transaction,
            "definition user {}\n\ndefinition invoice {\n    relation viewer: user\n}\n",
            Some("root"),
        )
        .await
        .expect("a schema");
        services::authorization::rebac::relate(
            &transaction,
            "invoice",
            "i-1",
            "viewer",
            &store::providers::authorization::rebac::Subject {
                subject_type: "user".to_owned(),
                subject_id: support::SUBJECT.to_owned(),
                subject_relation: String::new(),
            },
            Some("root"),
        )
        .await
        .expect("a tuple");
        transaction.commit().await.expect("committed");
    }
    let (status, verdict) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/authz/evaluate"),
        &bearer,
        Some(json!({
            "subject": support::SUBJECT,
            "question": {
                "kind": "relationship",
                "object_type": "invoice",
                "object_id": "i-1",
                "relation": "viewer",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verdict}");
    assert_eq!(
        (&verdict["reported"], &verdict["computed"]),
        (&json!("deny"), &json!("indeterminate")),
        "{verdict}"
    );
    assert_eq!(
        verdict["detail"]["reasons"][0]["reason"], "relation-store-closed",
        "{verdict}"
    );
    assert!(
        verdict.get("walk").is_none(),
        "walked for the trace: {verdict}"
    );

    let base = format!(
        "/admin/realms/{REALM}/authz/servers/{}",
        support::CONFIDENTIAL
    );
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({
            "enforcement_mode": "enforcing",
            "decision_strategy": "unanimous",
            "user_managed_access": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let (_, made) = asked(
        &plane,
        Method::POST,
        &format!("{base}/resources"),
        &bearer,
        Some(json!({
            "name": "shared", "display_name": "shared", "description": "",
            "resource_uris": [], "resource_type": "invoice",
            "resource_owner": support::SUBJECT, "user_managed_access": true,
        })),
    )
    .await;
    let invoice = made["resource_id"].as_str().expect("an id").to_owned();
    let shares = format!("{base}/resources/{invoice}/shares");
    let with =
        json!({ "relation": "viewer", "subject_type": "user", "subject_id": support::SUBJECT });
    let (status, told) = asked(&plane, Method::POST, &shares, &bearer, Some(with.clone())).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told.to_string().contains("relation store"),
        "refused in other words: {told}"
    );
    let (status, told) = asked(&plane, Method::DELETE, &shares, &bearer, Some(with)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "taking back waited: {told}");

    let wish = format!("/admin/realms/{REALM}/features/rebac-store");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &wish,
        &bearer,
        Some(json!({ "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told.to_string().contains("cannot open"),
        "refused in other words: {told}"
    );
    for kept in [json!(false), Value::Null] {
        let (status, told) = asked(
            &plane,
            Method::PUT,
            &wish,
            &bearer,
            Some(json!({ "enabled": kept })),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{kept}: {told}");
    }
}
