//! A question to the point of decision, on Postgres: a database that cannot
//! answer while the relations are walked makes the question one to ask
//! again, never a refusal.

use std::time::Duration;

use pgcore::pool::PoolSettings;
use saffui_core::authz::capability::Capability;
use saffui_core::authz::decide::{DecisionRequest, decide};
use saffui_core::authz::relations::schema::compile_schema;
use saffui_core::authz::relations::{StoredSchema, list_admitted_relations};
use saffui_core::oidc::errors::OAuthError;
use saffui_core::testkit::fixtures::{create_administrator, create_realm, create_service_client};
use serde_json::Map;

mod support;

#[tokio::test]
async fn a_walk_the_database_cannot_answer_is_to_be_asked_again() {
    // A read waits for a lock as long as the pool waits for a connection.
    let short_pool = PoolSettings {
        wait_timeout: Duration::from_secs(1),
        ..PoolSettings::default()
    };
    let (app, database) = support::wire_on_postgres(short_pool).await;
    let scope = create_realm(&app, "acme").await;
    let secret = create_service_client(&app, scope, "billing", &[]).await;
    let subject_token =
        create_administrator(&app, "acme", scope, "auditor", &[Capability::AuditRead]).await;
    let source = "definition client {}\ndefinition document {\n  relation reader: client\n}";
    let compiled = compile_schema(source).expect("a schema");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let stored = StoredSchema {
        source: source.to_owned(),
        compiled: serde_json::to_value(&compiled).expect("a compiled form"),
        written_at: app.now(),
    };
    work.write_relation_schema(&stored, &list_admitted_relations(&compiled))
        .await
        .expect("a schema");
    work.insert_relation_guard("document", "billing", app.now())
        .await
        .expect("a guard");
    work.commit().await.expect("a commit");

    // Only the relations are out of reach: the client, the token, the
    // schema and its guard are read as always.
    let operator = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    operator
        .batch_execute("BEGIN; LOCK TABLE relation_tuples IN ACCESS EXCLUSIVE MODE")
        .await
        .expect("the relations held");
    let attributes = Map::new();
    let asked = decide(
        &app,
        "acme",
        Some("billing"),
        Some(secret),
        DecisionRequest {
            subject_token: Some(&subject_token),
            action: "reader",
            resource_type: "document",
            resource_id: Some("q3"),
            attributes: &attributes,
        },
    )
    .await;
    operator
        .batch_execute("ROLLBACK")
        .await
        .expect("the relations let go");

    assert_eq!(
        asked
            .map(|decision| decision.decision)
            .map_err(|failure| failure.error),
        Err(OAuthError::TemporarilyUnavailable),
        "busy, not a refusal of the subject"
    );
}
