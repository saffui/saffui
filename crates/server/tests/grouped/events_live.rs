#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use models::entities::authz::AdminAction;
use serde_json::json;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;

/// The live feed hears what the store commits, and only that: an emission
/// inside a transaction says nothing until the commit speaks it, a rolled
/// back one never speaks, and what arrives is the summary, never the
/// payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_feed_speaks_at_commit_and_never_before() {
    let plane = Plane::with_actions(&[AdminAction::EventRead]).await;
    let feed = server::live::listen(support::owner());
    let mut watching = feed.subscribe();
    // The LISTEN has to stand before the emission, or the notify lands on
    // nobody; a moment is what the connection needs.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::outbox::emit(
            &transaction,
            store::providers::outbox::SESSION_REVOKED,
            "ada",
            &json!({ "session": "s-1", "held_back": "the payload stays home" }),
        )
        .await
        .unwrap();

        // Not yet: the transaction is open, so nothing happened.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(400), watching.recv())
                .await
                .is_err(),
            "the feed spoke before the commit"
        );
        transaction.commit().await.unwrap();
    }

    let told = tokio::time::timeout(std::time::Duration::from_secs(5), watching.recv())
        .await
        .expect("the feed said nothing after the commit")
        .expect("the feed closed");
    assert_eq!(told.kind, "session.revoked");
    assert_eq!(told.realm, REALM);
    assert_eq!(told.tenant, support::TENANT);
    assert_eq!(told.user_id, "ada");
    assert!(told.event_id > 0);
    assert!(
        chrono::DateTime::parse_from_rfc3339(&told.occurred_at).is_ok(),
        "occurred_at does not parse: {}",
        told.occurred_at
    );

    // Rolled back is never spoken.
    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::outbox::emit(
            &transaction,
            store::providers::outbox::USER_UPDATED,
            "ada",
            &json!({}),
        )
        .await
        .unwrap();
        drop(transaction);
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(600), watching.recv())
            .await
            .is_err(),
        "a rolled back emission was spoken"
    );
}
