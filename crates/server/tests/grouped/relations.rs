#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use crate::admin_authz::asked;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};

const REALM: &str = support::REALM;

/// The relation store is experimental and off unless the process runs it, so
/// every case in this binary turns it on before anything reads what the
/// process runs: the first call decides for the whole binary.
pub(crate) fn relations_running() {
    server::api::config::install_features(
        commons::feature::FeatureSet::resolve("+rebac-store", |_| false)
            .expect("a set that resolves"),
    );
    assert!(
        server::api::config::features().is_enabled(commons::feature::Feature::RebacStore),
        "the process does not run the relation store"
    );
}

async fn evaluate(plane: &Plane, bearer: &str, invoice: &str) -> Value {
    let (status, verdict) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/authz/evaluate"),
        bearer,
        Some(json!({
            "subject": support::SUBJECT,
            "question": {
                "kind": "relationship",
                "object_type": "invoice",
                "object_id": invoice,
                "relation": "viewer",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verdict}");
    verdict
}

/// A realm that closes the relation store closes all of it: its doors, the
/// walk behind every relationship question, the trace a simulation shows, and
/// the sharing that rides it. Taking a share back does not wait for the store
/// to reopen, and reopening walks what is left.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_that_closes_the_relation_store_closes_all_of_it() {
    relations_running();
    let plane = Plane::with_actions(&[
        AdminAction::FeatureWrite,
        AdminAction::UmaRead,
        AdminAction::UmaWrite,
        AdminAction::RebacRead,
        AdminAction::RebacWrite,
        AdminAction::AuthzDecisionWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
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
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/rebac/schema"),
        &bearer,
        Some(json!({
            "source": "definition user {}\n\ndefinition invoice {\n    relation viewer: user\n}\n"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
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
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    assert_eq!(
        evaluate(&plane, &bearer, &invoice).await["computed"],
        "permit"
    );

    let wish = format!("/admin/realms/{REALM}/features/rebac-store");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &wish,
        &bearer,
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    let verdict = evaluate(&plane, &bearer, &invoice).await;
    assert_eq!(verdict["reported"], "deny", "{verdict}");
    assert_eq!(verdict["computed"], "indeterminate", "{verdict}");
    assert_eq!(
        verdict["detail"]["reasons"][0]["reason"], "relation-store-closed",
        "{verdict}"
    );
    assert!(
        verdict.get("walk").is_none(),
        "a closed store was walked for the trace: {verdict}"
    );
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/rebac/schema"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the store's door stayed open"
    );
    let (status, told) = asked(&plane, Method::POST, &shares, &bearer, Some(with.clone())).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told.to_string().contains("does not run"),
        "refused in other words: {told}"
    );
    let (status, told) = asked(&plane, Method::DELETE, &shares, &bearer, Some(with.clone())).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "taking back waited: {told}");

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &wish,
        &bearer,
        Some(json!({ "enabled": null })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    assert_ne!(
        evaluate(&plane, &bearer, &invoice).await["computed"],
        "permit",
        "the share taken back while the store was closed came back with it"
    );
    let (status, told) = asked(&plane, Method::POST, &shares, &bearer, Some(with)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    assert_eq!(
        evaluate(&plane, &bearer, &invoice).await["computed"],
        "permit",
        "the reopened store does not walk"
    );
}
