mod support;

use crypto::provider::openssl::hashing::OpenSslDigest;
use store::audit;
use store::error::StoreError;
use store::tenancy::TenantContext;
use support::Fixture;

fn digest() -> OpenSslDigest {
    OpenSslDigest
}

fn entry(kind: &str, actor: &str) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "actor": actor,
        "occurred_at": 1_700_000_000.0,
        "detail": {"realm": "main"},
    })
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn entries_chain_and_the_chain_verifies() {
    let fixture = Fixture::with_user().await;
    let digest = digest();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(
        audit::start(&transaction, &digest, "acme", "main")
            .await
            .unwrap()
    );
    assert!(
        !audit::start(&transaction, &digest, "acme", "main")
            .await
            .unwrap(),
        "a second chain was opened for one realm"
    );

    let first = audit::append(&transaction, &entry("realm.created", "root"))
        .await
        .unwrap();
    let second = audit::append(&transaction, &entry("user.created", "root"))
        .await
        .unwrap();
    assert_eq!(first.seq, 1);
    assert_eq!(second.seq, 2);
    assert_ne!(first.hash, second.hash);

    // Each entry names the one before it.
    let prev: Vec<u8> = transaction
        .query_one("SELECT prev_hash FROM audit_events WHERE seq = 2", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(prev, first.hash);

    let verified = audit::verify(&transaction, &digest).await.unwrap();
    assert!(
        verified.holds(),
        "the chain broke at {:?}",
        verified.broken_at
    );
    assert_eq!(verified.entries, 2);
}

/// The cross check: what the database hashed is what this side recomputes.
///
/// The canonical form has one owner, and this is what says so out loud. If the
/// two ever disagree, every verification fails at entry one rather than
/// silently accepting a chain nobody can recheck.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn both_sides_hash_the_same_bytes() {
    let fixture = Fixture::with_user().await;
    let digest = digest();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    audit::start(&transaction, &digest, "acme", "main")
        .await
        .unwrap();

    // Keys deliberately out of order and a unicode value, since the canonical
    // form is exactly what decides whether these hash the same on both sides.
    let awkward = serde_json::json!({
        "occurred_at": 1_700_000_000.0,
        "kind": "realm.updated",
        "zulu": "é\"\\ /",
        "actor": "root",
        "alpha": [1, 2, {"b": null, "a": true}],
    });
    let appended = audit::append(&transaction, &awkward).await.unwrap();

    let verified = audit::verify(&transaction, &digest).await.unwrap();
    assert!(
        verified.holds(),
        "the two sides hashed different bytes, breaking at {:?}",
        verified.broken_at
    );
    assert_eq!(verified.entries, 1);
    assert_eq!(appended.seq, 1);
}

/// Changing one entry breaks it and every entry after it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_altered_entry_is_found_where_it_was_altered() {
    let fixture = Fixture::with_user().await;
    let digest = digest();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    audit::start(&transaction, &digest, "acme", "main")
        .await
        .unwrap();
    for kind in ["a", "b", "c"] {
        audit::append(&transaction, &entry(kind, "root"))
            .await
            .unwrap();
    }

    transaction.commit().await.unwrap();
    drop(connection);

    // The application role is refused this outright, which is the first line of
    // defence. The chain is the second, for whoever is not refused.
    fixture
        .owner()
        .await
        .execute(
            "UPDATE audit_events SET envelope = jsonb_set(envelope, '{actor}', '\"mallory\"') \
             WHERE seq = 2",
            &[],
        )
        .await
        .unwrap();

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    let verified = audit::verify(&transaction, &digest).await.unwrap();
    assert_eq!(
        verified.broken_at,
        Some(2),
        "an altered entry was not found, or was found in the wrong place"
    );
}

/// Removing an entry leaves every remaining link agreeing with itself.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_removed_entry_is_a_gap_and_not_an_ordering_detail() {
    let fixture = Fixture::with_user().await;
    let digest = digest();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    audit::start(&transaction, &digest, "acme", "main")
        .await
        .unwrap();
    for kind in ["a", "b", "c"] {
        audit::append(&transaction, &entry(kind, "root"))
            .await
            .unwrap();
    }

    transaction.commit().await.unwrap();
    drop(connection);

    fixture
        .owner()
        .await
        .execute("DELETE FROM audit_events WHERE seq = 2", &[])
        .await
        .unwrap();

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    let verified = audit::verify(&transaction, &digest).await.unwrap();
    assert_eq!(verified.broken_at, Some(3), "a removed entry left no trace");
}

/// Truncating the end is the one removal every remaining link survives, which
/// is why the head is checked against the last entry.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn entries_removed_from_the_end_are_found_by_the_head() {
    let fixture = Fixture::with_user().await;
    let digest = digest();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    audit::start(&transaction, &digest, "acme", "main")
        .await
        .unwrap();
    for kind in ["a", "b", "c"] {
        audit::append(&transaction, &entry(kind, "root"))
            .await
            .unwrap();
    }

    transaction.commit().await.unwrap();
    drop(connection);

    fixture
        .owner()
        .await
        .execute("DELETE FROM audit_events WHERE seq = 3", &[])
        .await
        .unwrap();

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    let verified = audit::verify(&transaction, &digest).await.unwrap();
    assert_eq!(
        verified.broken_at,
        Some(2),
        "the chain was truncated and every remaining link still agreed"
    );
}

/// The queryable columns come from the envelope, so they cannot disagree with
/// what was hashed.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_readable_columns_are_the_envelope() {
    let fixture = Fixture::with_user().await;
    let digest = digest();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    audit::start(&transaction, &digest, "acme", "main")
        .await
        .unwrap();
    audit::append(&transaction, &entry("user.deleted", "ada"))
        .await
        .unwrap();

    let row = transaction
        .query_one(
            "SELECT kind, actor, extract(epoch FROM occurred_at)::bigint AS at \
             FROM audit_events WHERE seq = 1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>("kind"), "user.deleted");
    assert_eq!(row.get::<_, String>("actor"), "ada");
    assert_eq!(row.get::<_, i64>("at"), 1_700_000_000);

    // And they cannot be written to.
    assert!(
        transaction
            .execute(
                "UPDATE audit_events SET kind = 'something.else' WHERE seq = 1",
                &[]
            )
            .await
            .is_err(),
        "a generated column was written"
    );
}

/// An anchor names the head it was published for.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_anchor_records_the_head_it_published() {
    let fixture = Fixture::with_user().await;
    let digest = digest();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    audit::start(&transaction, &digest, "acme", "main")
        .await
        .unwrap();
    let second = {
        audit::append(&transaction, &entry("a", "root"))
            .await
            .unwrap();
        audit::append(&transaction, &entry("b", "root"))
            .await
            .unwrap()
    };

    let anchored = audit::anchor(&transaction, "a-public-log", "receipt-1")
        .await
        .unwrap();
    assert_eq!(anchored.seq, second.seq);
    assert_eq!(anchored.hash, second.hash);

    let stored: (i64, Vec<u8>, String) = {
        let row = transaction
            .query_one("SELECT seq, head_hash, witness FROM audit_anchors", &[])
            .await
            .unwrap();
        (row.get(0), row.get(1), row.get(2))
    };
    assert_eq!(stored.0, second.seq);
    assert_eq!(stored.1, second.hash);
    assert_eq!(stored.2, "a-public-log");
}

/// Appending without a chain says so rather than opening one.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn appending_to_a_realm_with_no_chain_is_refused() {
    let fixture = Fixture::with_user().await;
    let digest = digest();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(
        audit::append(&transaction, &entry("a", "root"))
            .await
            .is_err(),
        "an entry was written to a chain that does not exist"
    );
    drop(transaction);
    drop(connection);

    // Its own transaction: the refusal above aborted the one it was made in,
    // and every later statement there fails for that reason rather than its own.
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    assert!(matches!(
        audit::verify(&transaction, &digest).await,
        Err(StoreError::NoChain)
    ));
}

/// Two appends at once produce two entries, not a conflict.
///
/// This is what the head row is for. Without taking it for update, both would
/// read the same tail, both would claim the same sequence, and one would be
/// refused by the primary key. That refusal looks like a bug to whoever hits
/// it, and the entry it was carrying is simply lost.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn two_appends_at_once_are_serialised() {
    let fixture = Fixture::with_user().await;
    let digest = digest();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    audit::start(&transaction, &digest, "acme", "main")
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut first_connection = fixture.connection().await;
    // The second connection is left unscoped here and scoped inside its own
    // task, which is what lets the task own it while this one still holds the
    // first transaction open.
    let second_connection = fixture.connection().await;
    let first = fixture
        .scoped(&mut first_connection, &TenantContext::new("acme", "main"))
        .await;

    // The first append holds the head and does not commit, so the second one
    // genuinely overlaps it.
    let one = audit::append(&first, &entry("first", "root"))
        .await
        .unwrap();
    assert_eq!(one.seq, 1);

    // The second runs on its own task, so it can be waiting while this one
    // commits. What distinguishes the two designs is not that it waits, since
    // it waits either way: without the head taken for update it waits on the
    // primary key, having already claimed a sequence that is about to be
    // taken. It is the outcome after the wait that differs.
    let mut owned = second_connection;
    let waiting = tokio::spawn(async move {
        let transaction = owned.transaction().await.unwrap();
        for (setting, value) in [
            ("saffui.current_tenant", "acme"),
            ("saffui.current_realm", "main"),
        ] {
            transaction
                .execute("SELECT set_config($1, $2, true)", &[&setting, &value])
                .await
                .unwrap();
        }
        let outcome = transaction
            .query_one(
                "SELECT seq FROM audit_append($1)",
                &[&serde_json::json!({
                    "kind": "second",
                    "actor": "root",
                    "occurred_at": 1_700_000_000.0,
                })],
            )
            .await
            .map(|row| row.get::<_, i64>("seq"));
        if outcome.is_ok() {
            transaction.commit().await.unwrap();
        }
        outcome
    });

    // Long enough for the second to have reached the wait.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    first.commit().await.unwrap();
    drop(first_connection);

    let seq = tokio::time::timeout(std::time::Duration::from_secs(10), waiting)
        .await
        .expect("the second append never finished")
        .expect("the task panicked")
        .expect("the second append was refused instead of chaining onto the first");
    assert_eq!(seq, 2, "the second append did not chain onto the first");

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    assert!(audit::verify(&transaction, &digest).await.unwrap().holds());
}

/// An entry cannot name the chain it lands in.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_entry_cannot_choose_its_realm() {
    let fixture = Fixture::with_user().await;
    let digest = digest();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    audit::start(&transaction, &digest, "acme", "main")
        .await
        .unwrap();

    let claiming = serde_json::json!({
        "kind": "user.deleted",
        "actor": "mallory",
        "occurred_at": 1_700_000_000.0,
        "tenant": "globex",
        "realm_id": "elsewhere",
    });
    audit::append(&transaction, &claiming).await.unwrap();

    let (tenant, realm): (String, String) = {
        let row = transaction
            .query_one(
                "SELECT tenant, realm_id FROM audit_events WHERE seq = 1",
                &[],
            )
            .await
            .unwrap();
        (row.get(0), row.get(1))
    };
    assert_eq!(tenant, "acme", "an entry named the tenant it landed in");
    assert_eq!(realm, "main", "an entry named the realm it landed in");
}

/// The application reads the record and cannot touch it.
///
/// The chain is what catches whoever is not refused here; this is what refuses
/// almost everyone. Each attempt runs in its own transaction, since a refused
/// write aborts the one it was made in.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_application_cannot_write_the_record() {
    let fixture = Fixture::with_user().await;
    let digest = digest();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    audit::start(&transaction, &digest, "acme", "main")
        .await
        .unwrap();
    audit::append(&transaction, &entry("a", "root"))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let attempts = [
        (
            "UPDATE audit_events SET prev_hash = hash WHERE seq = 1",
            "an entry was altered",
        ),
        (
            "DELETE FROM audit_events WHERE seq = 1",
            "an entry was removed",
        ),
        (
            "INSERT INTO audit_events (tenant, realm_id, seq, envelope, prev_hash, hash) \
             VALUES ('acme', 'main', 99, '{\"kind\":\"forged\",\"occurred_at\":0}'::jsonb, \
                     sha256('a'), sha256('b'))",
            "an entry was written outside the function",
        ),
    ];

    for (statement, what) in attempts {
        let mut connection = fixture.connection().await;
        let transaction = fixture
            .scoped(&mut connection, &TenantContext::new("acme", "main"))
            .await;
        let refused = transaction.execute(statement, &[]).await.is_err();
        drop(transaction);
        drop(connection);
        assert!(refused, "{what}");
    }
}

/// Two realms do not start from the same value, so an entry cannot be lifted
/// from one chain into the other at the same position.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn each_realm_starts_from_its_own_genesis() {
    let fixture = Fixture::with_user().await;
    let digest = digest();

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    audit::start(&transaction, &digest, "acme", "main")
        .await
        .unwrap();
    let first: Vec<u8> = transaction
        .query_one("SELECT head_hash FROM audit_chain_heads", &[])
        .await
        .unwrap()
        .get(0);
    transaction.commit().await.unwrap();
    drop(connection);

    // A second realm of the same tenant, planted for this.
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::tenant_wide("acme"))
        .await;
    let realm = models::entities::realm::RealmCreateModel {
        name: "other".into(),
        display_name: "Other".into(),
        enabled: true,
    }
    .into_model(
        "other".into(),
        models::auditable::AuditableModel::from_creator("acme".into(), "root".into()),
    );
    store::providers::realms::create(&transaction, &realm)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    audit::start(&transaction, &digest, "acme", "other")
        .await
        .unwrap();
    let second: Vec<u8> = transaction
        .query_one("SELECT head_hash FROM audit_chain_heads", &[])
        .await
        .unwrap()
        .get(0);

    assert_ne!(
        first, second,
        "two realms began from the same value, so an entry of one fits the other"
    );
}

/// Another realm's chain is not this realm's.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_chain_is_not_visible_from_another_realm() {
    let fixture = Fixture::with_user().await;
    let digest = digest();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    audit::start(&transaction, &digest, "acme", "main")
        .await
        .unwrap();
    audit::append(&transaction, &entry("a", "root"))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    assert!(
        matches!(
            audit::verify(&transaction, &digest).await,
            Err(StoreError::NoChain)
        ),
        "another realm read this realm's chain"
    );
    let seen: i64 = transaction
        .query_one("SELECT count(*) FROM audit_events", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(seen, 0, "another realm read this realm's entries");
}
