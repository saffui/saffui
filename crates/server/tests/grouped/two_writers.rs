//! What two instances would do to one database, driven as concurrent
//! writers: the chain must not fork, a claim must not double, a sweep must
//! not double-count. The guards under test live in the database, so
//! concurrent tasks on independent connections exercise exactly what a
//! second node would.

#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use store::tenancy::TenantContext;

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, support::REALM)
}

/// Appends racing from many connections land on one linear chain: every
/// sequence exactly once, every link verifying, no two entries chained
/// onto the same predecessor.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_chain_does_not_fork_under_racing_writers() {
    let plane = Plane::with_actions(&[]).await;
    let sealing = support::sealing();
    {
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
        store::audit::start(
            &transaction,
            sealing.provider.digest(),
            support::TENANT,
            support::REALM,
        )
        .await
        .expect("a chain");
        transaction.commit().await.expect("the chain kept");
    }
    let before: i64 = {
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
        transaction
            .query_one("SELECT count(*) FROM audit_events", &[])
            .await
            .expect("a count")
            .get(0)
    };

    let mut racing = Vec::new();
    for writer in 0..12 {
        let pool = plane.pool();
        let tenancy = plane.tenancy();
        racing.push(tokio::spawn(async move {
            for entry in 0..6 {
                let mut connection = pool.get().await.expect("a connection");
                let transaction = tenancy
                    .transaction(&mut connection, &within())
                    .await
                    .expect("a scope");
                store::audit::append(
                    &transaction,
                    &serde_json::json!({
                        "kind": "two-writers",
                        "occurred_at": chrono::Utc::now().timestamp(),
                        "writer": writer,
                        "entry": entry,
                    }),
                )
                .await
                .expect("an append");
                transaction.commit().await.expect("the append kept");
            }
        }));
    }
    for task in racing {
        task.await.expect("a writer finished");
    }

    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let after: i64 = transaction
        .query_one("SELECT count(*) FROM audit_events", &[])
        .await
        .expect("a count")
        .get(0);
    assert_eq!(after - before, 72, "an append went missing or doubled");

    // One linear chain: sequences contiguous and unique, and nobody chained
    // onto a predecessor somebody else already extended.
    let row = transaction
        .query_one(
            "SELECT count(DISTINCT seq) AS distinct_seq, max(seq) AS top FROM audit_events",
            &[],
        )
        .await
        .expect("the shape");
    assert_eq!(
        row.get::<_, i64>("distinct_seq"),
        after,
        "two entries share a sequence"
    );
    assert_eq!(row.get::<_, i64>("top"), after, "the sequence has holes");
    let forks: i64 = transaction
        .query_one(
            "SELECT count(*) FROM ( \
                 SELECT prev_hash FROM audit_events GROUP BY prev_hash HAVING count(*) > 1 \
             ) forked",
            &[],
        )
        .await
        .expect("the fork census")
        .get(0);
    assert_eq!(forks, 0, "two entries chained onto the same predecessor");

    let verified = store::audit::verify(&transaction, sealing.provider.digest())
        .await
        .expect("a verification");
    assert!(
        verified.holds(),
        "the chain broke at {:?}",
        verified.broken_at
    );
    assert_eq!(verified.entries as i64, after);
}

/// Two open claims see disjoint work, and a claim that rolls back frees its
/// rows at once: what a crashed pump costs is a retry, never a double send.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn two_outbox_claims_are_disjoint_and_a_crash_frees_its_claim() {
    let plane = Plane::with_actions(&[]).await;
    let now = chrono::Utc::now();
    {
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
        // Only this test's events count: the planted world emits its own.
        transaction
            .execute("DELETE FROM event_outbox", &[])
            .await
            .expect("a clean outbox");
        for n in 0..30 {
            store::providers::outbox::emit(
                &transaction,
                "two-writers-test",
                support::SUBJECT,
                &serde_json::json!({ "n": n }),
            )
            .await
            .expect("an emission");
        }
        transaction.commit().await.expect("the seed kept");
    }

    // Both claims open at once, the second while the first still holds its
    // rows: SKIP LOCKED hands it the rest, never the same rows again.
    let mut first_connection = plane.connection().await;
    let first = plane.scoped(&mut first_connection, &within()).await;
    let mut second_connection = plane.connection().await;
    let second = plane.scoped(&mut second_connection, &within()).await;

    let first_claim = store::providers::outbox::due(&first, 20, 60, now)
        .await
        .expect("the first claim");
    let second_claim = store::providers::outbox::due(&second, 20, 60, now)
        .await
        .expect("the second claim");
    assert_eq!(first_claim.len(), 20, "the first pump was short-changed");
    assert_eq!(
        second_claim.len(),
        10,
        "the second pump did not get exactly the rest"
    );
    let mut seen = std::collections::HashSet::new();
    for event in first_claim.iter().chain(second_claim.iter()) {
        assert!(
            seen.insert(event.event_id),
            "event {} was claimed twice",
            event.event_id
        );
    }

    // The first pump crashes mid-work: its transaction rolls back, and its
    // claim frees with it. The second delivers what it holds.
    for event in &second_claim {
        store::providers::outbox::delivered(&second, event.event_id)
            .await
            .expect("a delivery mark");
    }
    drop(first);
    drop(first_connection);
    second.commit().await.expect("the deliveries kept");

    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let refreed = store::providers::outbox::due(&transaction, 30, 60, now)
        .await
        .expect("the after-crash claim");
    assert_eq!(
        refreed.len(),
        20,
        "the crashed pump's claim did not free, or a delivered row came back"
    );
    let crashed: std::collections::HashSet<i64> =
        first_claim.iter().map(|event| event.event_id).collect();
    for event in &refreed {
        assert!(
            crashed.contains(&event.event_id),
            "a delivered event {} was handed out again",
            event.event_id
        );
    }
}

/// Two sweepers race one realm: the realm lock hands the pass to one of
/// them, and between them exactly the expired rows go, counted once.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn two_sweepers_take_exactly_what_expired() {
    let plane = Plane::with_actions(&[]).await;
    {
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
        for n in 0..40 {
            transaction
                .execute(
                    "INSERT INTO one_time_tokens \
                         (tenant, realm_id, user_id, purpose, token_hash, bound_to, \
                          expires_at, created_at) \
                     SELECT current_setting('saffui.current_tenant', true), \
                            current_setting('saffui.current_realm', true), \
                            $1, $2, decode(repeat('ab', 32), 'hex'), NULL, \
                            now() - interval '1 minute', now() - interval '10 minutes'",
                    &[&support::SUBJECT, &format!("two-writers-{n}")],
                )
                .await
                .expect("a stale token");
        }
        transaction.commit().await.expect("the seed kept");
    }

    let (pool, tenancy) = (plane.pool(), plane.tenancy());
    let (one, other) = tokio::join!(
        server::jobs::sweep_every_realm(&pool, &tenancy),
        server::jobs::sweep_every_realm(&pool, &tenancy),
    );
    let taken = one.map_or(0, |swept| swept.one_time_tokens)
        + other.map_or(0, |swept| swept.one_time_tokens);
    assert_eq!(
        taken, 40,
        "the two sweepers together took other than what expired"
    );

    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let left: i64 = transaction
        .query_one(
            "SELECT count(*) FROM one_time_tokens WHERE purpose LIKE 'two-writers-%'",
            &[],
        )
        .await
        .expect("a count")
        .get(0);
    assert_eq!(left, 0, "an expired token survived both sweepers");
}
