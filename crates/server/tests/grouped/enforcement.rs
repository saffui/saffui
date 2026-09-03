
#[allow(unused_imports)]
use super::support;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use server::api::config::{Plane as Mounted, register};
use server::middleware::admin_policy::AdminPolicy;
use store::tenancy::TenantContext;
use super::support::{AUDIENCE, PARTY, Plane, REALM, SCOPE, claims};

fn policy() -> AdminPolicy {
    AdminPolicy {
        audiences: vec![AUDIENCE.to_owned()],
        parties: vec![PARTY.to_owned()],
        scope: SCOPE.to_owned(),
    }
}

/// Ask, and get back what the caller is told.
async fn ask(plane: &Plane, bearer: &str, body: serde_json::Value) -> (StatusCode, String) {
    let mounted = Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: policy(),
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    };
    let app = test::init_service(App::new().configure(register(&mounted))).await;

    let request = test::TestRequest::post()
        .uri("/authz/decision")
        .insert_header(("authorization", format!("Bearer {bearer}")))
        .set_json(body)
        .to_request();

    let response = test::call_service(&app, request).await;
    let status = response.status();
    let body = String::from_utf8(test::read_body(response).await.to_vec()).unwrap_or_default();
    (status, body)
}

/// A realm with a relationship schema and one edge to the caller.
async fn plant_relationship(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new("acme", REALM))
        .await;

    services::rebac::publish(
        &transaction,
        "definition user {}
         definition document {
             relation owner: user
             permission view = owner
         }",
        Some("root"),
    )
    .await
    .unwrap();

    services::rebac::relate(
        &transaction,
        "document",
        "doc",
        "owner",
        &store::providers::rebac::Subject {
            subject_type: "user".into(),
            subject_id: support::SUBJECT.into(),
            subject_relation: String::new(),
        },
        Some("root"),
    )
    .await
    .unwrap();

    transaction.commit().await.unwrap();
}

/// The whole chain over a socket: a token, a caller established, an engine
/// walked, an answer given and a record written.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_question_over_the_wire_reaches_an_engine_and_is_recorded() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;
    plant_relationship(&plane).await;
    let bearer = plane.token(&claims());

    let (status, body) = ask(
        &plane,
        &bearer,
        serde_json::json!({
            "kind": "relationship",
            "object_type": "document",
            "object_id": "doc",
            "relation": "view",
            "action": "view",
            "decision_id": "d-1"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("permit"), "{body}");

    // And the record survived the request, which is what committing is for.
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new("acme", REALM))
        .await;
    let written = store::providers::authz_policies::recent(&transaction, 10)
        .await
        .unwrap();
    assert_eq!(
        written.len(),
        1,
        "the decision was answered and not recorded"
    );
    assert_eq!(written[0].decision_id, "d-1");
    assert_eq!(written[0].subject_id, support::SUBJECT);
    assert_eq!(written[0].resource_kind, "relationship");
}

/// An object the caller has no edge to.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_caller_with_no_edge_is_told_no() {
    let plane = Plane::with_actions(&[]).await;
    plant_relationship(&plane).await;
    let bearer = plane.token(&claims());

    let (status, body) = ask(
        &plane,
        &bearer,
        serde_json::json!({
            "kind": "relationship",
            "object_type": "document",
            "object_id": "somebody-elses",
            "relation": "view",
            "action": "view",
            "decision_id": "d-2"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("deny"), "{body}");
}

/// An application may ask about itself. Without that, any token holder in the
/// realm harvests another application's decisions, and one left in a permissive
/// rollout answers yes to all of them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_caller_may_not_ask_about_an_application_its_token_is_not_for() {
    let plane = Plane::with_actions(&[]).await;
    plant_relationship(&plane).await;
    let bearer = plane.token(&claims());

    let (status, _) = ask(
        &plane,
        &bearer,
        serde_json::json!({
            "kind": "permission",
            "server": "some-other-app",
            "resource": "doc",
            "scope": "read",
            "action": "read",
            "decision_id": "d-3"
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a token asked about an application it was not issued for"
    );
}

/// The gate is the same one the admin plane uses, so everything it refuses is
/// refused here: no token at all, and a token this realm will not have.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_enforcement_scope_is_guarded() {
    let plane = Plane::with_actions(&[]).await;
    plant_relationship(&plane).await;

    let mounted = Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: policy(),
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    };
    let app = test::init_service(App::new().configure(register(&mounted))).await;
    let request = test::TestRequest::post()
        .uri("/authz/decision")
        .set_json(serde_json::json!({
            "kind": "relationship",
            "object_type": "document",
            "object_id": "doc",
            "relation": "view",
            "action": "view",
            "decision_id": "d-4"
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, request).await.status(),
        StatusCode::UNAUTHORIZED,
        "the enforcement scope answered a request carrying no token"
    );

    let mut expired = claims();
    expired.set_expires_at(&(std::time::SystemTime::now() - std::time::Duration::from_secs(1)));
    let (status, _) = ask(
        &plane,
        &plane.token(&expired),
        serde_json::json!({
            "kind": "relationship",
            "object_type": "document",
            "object_id": "doc",
            "relation": "view",
            "action": "view",
            "decision_id": "d-5"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
