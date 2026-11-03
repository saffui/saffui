//! The audit chain on Postgres, verified with the digest the binary links:
//! the database hashes each link, and the verification hashes it again.

use pgcore::APP_ROLE;
use saffui_core::app::App;
use saffui_core::audit::EventKind;
use saffui_core::audit::append::record_event;
use saffui_core::audit::verify::{ChainBreak, ChainVerdict, verify_chain};
use saffui_core::tenancy::RealmScope;
use saffui_core::testkit::contract::check_audit_contract;
use serde_json::json;
use tokio_postgres::error::SqlState;

#[path = "support/product.rs"]
mod product;

use product::{connect_as, create_realm, scope_statement, wire_on_postgres};

const OWNER: &str = "saffui_owner";

#[tokio::test]
async fn postgres_passes_the_audit_contract() {
    let (app, _database) = wire_on_postgres().await;

    check_audit_contract(&app).await;
}

async fn append_event(app: &App, scope: RealmScope, payload: serde_json::Value) {
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    record_event(app, work.as_mut(), EventKind::RealmCreated, payload)
        .await
        .expect("an event");
    work.commit().await.expect("a commit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writers_at_once_leave_one_chain_that_verifies_whole_while_they_write() {
    const WRITERS: i64 = 8;
    const EVENTS_EACH: i64 = 12;
    let (app, _database) = wire_on_postgres().await;
    let scope = create_realm(&app, "busy").await;

    let mut writers = Vec::new();
    for writer in 0..WRITERS {
        let app = app.clone();
        writers.push(tokio::spawn(async move {
            for event in 0..EVENTS_EACH {
                append_event(&app, scope, json!({ "writer": writer, "event": event })).await;
            }
        }));
    }
    // Verified while the writers write: each verification reads one chain.
    let mut verdicts = Vec::new();
    while writers.iter().any(|writer| !writer.is_finished()) {
        verdicts.push(verify_chain(&app, scope).await);
    }
    for writer in writers {
        writer.await.expect("a writer that finished");
    }

    assert!(
        !verdicts.is_empty(),
        "the verification ran while they wrote"
    );
    assert!(
        verdicts
            .iter()
            .all(|verdict| matches!(verdict, Ok(ChainVerdict::Intact { .. }))),
        "{verdicts:?}"
    );
    // Then the whole chain: its creation and its first key, then every
    // append, no gap, no fork.
    assert_eq!(
        verify_chain(&app, scope).await,
        Ok(ChainVerdict::Intact {
            events: 2 + WRITERS * EVENTS_EACH
        })
    );
}

#[tokio::test]
async fn an_envelope_changed_behind_the_product_is_found_by_the_verification() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "tampered").await;
    append_event(&app, scope, json!({ "amount": 10 })).await;
    append_event(&app, scope, json!({ "amount": 20 })).await;

    connect_as(&database, OWNER)
        .await
        .batch_execute(&format!(
            "BEGIN; {};
             UPDATE audit_events
             SET envelope = convert_to(replace(convert_from(envelope, 'UTF8'), '\"amount\":10', '\"amount\":99'), 'UTF8')
             WHERE seq = 3;
             COMMIT;",
            scope_statement(scope)
        ))
        .await
        .expect("a hand in the database");

    assert_eq!(
        verify_chain(&app, scope).await,
        Ok(ChainVerdict::Broken {
            at_seq: 3,
            reason: ChainBreak::Altered
        })
    );
}

#[tokio::test]
async fn an_event_removed_behind_the_product_is_found_by_the_verification() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "pruned").await;
    append_event(&app, scope, json!({ "round": 1 })).await;
    append_event(&app, scope, json!({ "round": 2 })).await;

    connect_as(&database, OWNER)
        .await
        .batch_execute(&format!(
            "BEGIN; {}; DELETE FROM audit_events WHERE seq = 3; COMMIT;",
            scope_statement(scope)
        ))
        .await
        .expect("a hand in the database");

    assert_eq!(
        verify_chain(&app, scope).await,
        Ok(ChainVerdict::Broken {
            at_seq: 4,
            reason: ChainBreak::Gap
        })
    );
}

#[tokio::test]
async fn the_serving_role_writes_the_chain_through_the_function_and_no_other_way() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "guarded").await;
    let session = connect_as(&database, APP_ROLE).await;

    for statement in [
        "INSERT INTO audit_events (tenant_id, realm_id, seq, prev_hash, hash, envelope)
         SELECT tenant_id, realm_id, seq + 1, hash, hash, envelope FROM audit_events",
        "UPDATE audit_events SET envelope = envelope",
        "DELETE FROM audit_events",
        "UPDATE audit_chain_heads SET seq = 0",
        "DELETE FROM audit_chain_heads",
    ] {
        session
            .batch_execute(&format!("BEGIN; {}", scope_statement(scope)))
            .await
            .expect("a scoped transaction");
        let refused = session.batch_execute(statement).await.expect_err(statement);
        assert_eq!(
            refused.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{statement}"
        );
        session.batch_execute("ROLLBACK").await.expect("a rollback");
    }
}

#[tokio::test]
async fn an_event_is_not_appended_without_a_scope() {
    let (app, database) = wire_on_postgres().await;
    create_realm(&app, "scoped").await;
    let session = connect_as(&database, APP_ROLE).await;

    let refused = session
        .query(
            "SELECT * FROM saffui_append_audit_event(convert_to('{\"id\":\"00000000-0000-0000-0000-000000000001\"}', 'UTF8'))",
            &[],
        )
        .await
        .expect_err("an append outside any scope");

    assert_eq!(refused.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
}

#[tokio::test]
async fn a_realm_with_a_history_is_not_deleted_with_it() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "kept").await;

    let refused = connect_as(&database, pgcore::MAINTENANCE_ROLE)
        .await
        .execute(
            "DELETE FROM realms WHERE realm_id = $1",
            &[&scope.realm().as_uuid()],
        )
        .await
        .expect_err("a realm whose chain has events");

    assert_eq!(refused.code(), Some(&SqlState::FOREIGN_KEY_VIOLATION));
    assert_eq!(
        verify_chain(&app, scope).await,
        Ok(ChainVerdict::Intact { events: 2 })
    );
}
