#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use server::jobs::sweep_every_realm;
use store::tenancy::{Tenancy, TenantContext};

/// A revocation that has already outlived the token it was for. It holds
/// nothing but the realm, so a realm with no client and no user can still be
/// given something to sweep.
async fn plant_expired_revocation(plane: &Plane, realm: &str, token_id: &str) {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, realm))
        .await;
    transaction
        .execute(
            "INSERT INTO revoked_tokens (tenant, realm_id, token_id, expires_at) \
             VALUES ($1, $2, $3, now() - interval '1 minute')",
            &[&support::TENANT, &realm, &token_id],
        )
        .await
        .expect("a revocation to sweep");
    transaction.commit().await.expect("the revocation kept");
}

async fn revocations_left(plane: &Plane, realm: &str) -> i64 {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, realm))
        .await;
    transaction
        .query_one("SELECT count(*) FROM revoked_tokens", &[])
        .await
        .expect("a count")
        .get(0)
}

/// A pass visits every realm, not the one that happened to come first.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_pass_sweeps_every_realm() {
    let plane = Plane::with_actions(&[]).await;
    plane.plant_realm("second").await;
    plant_expired_revocation(&plane, support::REALM, "sweep-1").await;
    plant_expired_revocation(&plane, "second", "sweep-2").await;

    let swept = sweep_every_realm(&plane.tenancy())
        .await
        .expect("the realms were listed");
    assert_eq!(swept.revocations, 2, "a realm was left behind: {swept:?}");
    assert_eq!(revocations_left(&plane, support::REALM).await, 0);
    assert_eq!(revocations_left(&plane, "second").await, 0);

    // Nothing left to take, and the pass says so rather than failing.
    let swept = sweep_every_realm(&plane.tenancy())
        .await
        .expect("the realms were listed");
    assert_eq!(swept.total(), 0, "{swept:?}");
}

/// A realm already being swept is left to whoever holds it. Without the lock
/// both nodes run the same deletes, and the second pays for rows that are gone.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_another_node_is_sweeping_is_left_alone() {
    let plane = Plane::with_actions(&[]).await;
    plant_expired_revocation(&plane, support::REALM, "sweep-held").await;

    let held = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    let taken: bool = held
        .query_one(
            "SELECT pg_try_advisory_xact_lock($1, hashtext($2))",
            &[
                &(0x5746_4545_u32 as i32),
                &format!("{}:{}", support::TENANT, support::REALM),
            ],
        )
        .await
        .expect("the lock")
        .get(0);
    assert!(taken, "the lock was already held before the test took it");

    let swept = sweep_every_realm(&plane.tenancy())
        .await
        .expect("the realms were listed");
    assert_eq!(swept.total(), 0, "a held realm was swept anyway: {swept:?}");

    held.commit().await.expect("the lock released");

    let swept = sweep_every_realm(&plane.tenancy())
        .await
        .expect("the realms were listed");
    assert_eq!(
        swept.revocations, 1,
        "the released realm was not swept: {swept:?}"
    );
}

/// A realm pinned elsewhere belongs to the nodes there. A sweep that ignored
/// the pin would delete residency-bound rows from a node that may not read
/// them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_pinned_elsewhere_is_not_swept_here() {
    let plane = Plane::with_actions(&[]).await;
    plant_expired_revocation(&plane, support::REALM, "sweep-pinned").await;
    plane.pin_tenant("here").await;

    let swept = sweep_every_realm(&Tenancy::in_region(plane.pool(), "somewhere-else"))
        .await
        .expect("the realms were listed");
    assert_eq!(swept.total(), 0, "{swept:?}");
    assert_eq!(revocations_left(&plane, support::REALM).await, 1);
}

/// A client grant that ran out under a login still standing is taken away,
/// the one still running is not, and an offline grant still running keeps
/// holding its expired login exactly as before: what ends early goes early,
/// and nothing the sweep takes reaches past its own expiration.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_grant_that_ran_out_goes_before_its_login_does() {
    let plane = Plane::with_actions(&[]).await;
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    let plant_login = |id: &'static str, alive: bool| {
        let transaction = &transaction;
        async move {
            transaction
                .execute(
                    &format!(
                        "INSERT INTO user_sessions \
                             (tenant, realm_id, session_id, user_id, login_username, \
                              started_at, state, expiration) \
                         SELECT current_setting('saffui.current_tenant', true), \
                                current_setting('saffui.current_realm', true), \
                                $1, $2, $2, extract(epoch from now())::bigint - 600, 'logged-in', \
                                extract(epoch from now())::bigint {}",
                        if alive { "+ 3600" } else { "- 60" }
                    ),
                    &[&id, &support::SUBJECT],
                )
                .await
                .expect("a login planted");
        }
    };
    let plant_grant = |session: &'static str,
                       login: &'static str,
                       client: &'static str,
                       alive: bool,
                       offline: bool| {
        let transaction = &transaction;
        async move {
            transaction
                .execute(
                    &format!(
                        "INSERT INTO client_sessions \
                             (tenant, realm_id, session_id, user_session_id, user_id, client_id, \
                              started_at, expiration, offline) \
                         SELECT current_setting('saffui.current_tenant', true), \
                                current_setting('saffui.current_realm', true), \
                                $1, $2, $3, $4, extract(epoch from now())::bigint - 600, \
                                extract(epoch from now())::bigint {}, $5",
                        if alive { "+ 3600" } else { "- 60" }
                    ),
                    &[&session, &login, &support::SUBJECT, &client, &offline],
                )
                .await
                .expect("a grant planted");
        }
    };
    plant_login("sweep-live-login", true).await;
    plant_grant(
        "sweep-ended-grant",
        "sweep-live-login",
        support::CONFIDENTIAL,
        false,
        false,
    )
    .await;
    plant_grant(
        "sweep-live-grant",
        "sweep-live-login",
        support::PARTY,
        true,
        false,
    )
    .await;
    // The one login that outlives itself: expired, held by an offline grant
    // still running, the §11 retention the sweep must keep honouring.
    plant_login("sweep-held-login", false).await;
    plant_grant(
        "sweep-offline-grant",
        "sweep-held-login",
        support::CONFIDENTIAL,
        true,
        true,
    )
    .await;
    transaction.commit().await.expect("the seed kept");

    let swept = sweep_every_realm(&plane.tenancy())
        .await
        .expect("the realms were listed");
    assert_eq!(
        swept.client_sessions, 1,
        "other than the ended grant was taken: {swept:?}"
    );

    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    let left: Vec<String> = transaction
        .query(
            "SELECT session_id FROM client_sessions WHERE session_id LIKE 'sweep-%' \
             UNION ALL \
             SELECT session_id FROM user_sessions WHERE session_id LIKE 'sweep-%' \
             ORDER BY session_id",
            &[],
        )
        .await
        .expect("a census")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        left,
        vec![
            "sweep-held-login".to_owned(),
            "sweep-live-grant".to_owned(),
            "sweep-live-login".to_owned(),
            "sweep-offline-grant".to_owned(),
        ],
        "the sweep took other than the ended grant"
    );
}

/// A delivered event leaves once it is older than the replay window. A younger
/// one stays, and so do a dead and a pending one of the same age.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_delivered_event_leaves_when_its_replay_window_closes() {
    let plane = Plane::with_actions(&[]).await;
    let kept = services::realm::housekeeping::DELIVERED_EVENTS_KEPT_DAYS;
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    // Only this test's events count: the planted world emits its own.
    transaction
        .execute("DELETE FROM event_outbox", &[])
        .await
        .expect("a clean outbox");
    for (kind, state, days) in [
        ("sweep-old-delivered", "delivered", kept + 1),
        ("sweep-young-delivered", "delivered", kept - 1),
        ("sweep-old-dead", "dead", kept + 1),
        ("sweep-old-pending", "pending", kept + 1),
    ] {
        store::providers::outbox::emit(
            &transaction,
            kind,
            support::SUBJECT,
            &serde_json::json!({}),
        )
        .await
        .expect("an emission");
        // Aged on the database's clock, the one that stamped the event.
        transaction
            .execute(
                &format!(
                    "UPDATE event_outbox SET state = '{state}', \
                     occurred_at = now() - make_interval(days => {days}) WHERE kind = $1"
                ),
                &[&kind],
            )
            .await
            .expect("an event aged");
    }
    transaction.commit().await.expect("the seed kept");

    let swept = sweep_every_realm(&plane.tenancy())
        .await
        .expect("the realms were listed");

    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    let left: Vec<String> = transaction
        .query("SELECT kind FROM event_outbox ORDER BY kind", &[])
        .await
        .expect("a census")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        left,
        vec![
            "sweep-old-dead".to_owned(),
            "sweep-old-pending".to_owned(),
            "sweep-young-delivered".to_owned(),
        ],
        "the sweep took other than the delivered event past the window"
    );
    assert_eq!(swept.delivered_events, 1, "{swept:?}");
}

/// A brokered login the upstream never answered leaves its state behind: the
/// sweep takes it once it has run out, and one still waiting stays.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_broker_login_state_that_ran_out_is_taken_away() {
    let plane = Plane::with_actions(&[]).await;
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    // Ends stamped from the host's clock, as opening a brokered login does.
    let now = chrono::Utc::now();
    for (state_hash, expires_at) in [
        ("sweep-ran-out", now - chrono::Duration::minutes(1)),
        ("sweep-still-waiting", now + chrono::Duration::hours(1)),
    ] {
        transaction
            .execute(
                "INSERT INTO broker_login_states \
                     (tenant, realm_id, state_hash, provider_alias, auth_session, \
                      code_verifier, nonce, expires_at) \
                 VALUES ($1, $2, $3, 'upstream', 'an-auth-session', 'a-verifier', 'a-nonce', $4)",
                &[&support::TENANT, &support::REALM, &state_hash, &expires_at],
            )
            .await
            .expect("a login state planted");
    }
    transaction.commit().await.expect("the states kept");

    let swept = sweep_every_realm(&plane.tenancy())
        .await
        .expect("the realms were listed");

    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    let left: Vec<String> = transaction
        .query(
            "SELECT state_hash FROM broker_login_states ORDER BY state_hash",
            &[],
        )
        .await
        .expect("a census")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        left,
        vec!["sweep-still-waiting".to_owned()],
        "the sweep took other than the state that ran out"
    );
    assert_eq!(swept.broker_login_states, 1, "{swept:?}");
}

/// A SAML request no provider answered leaves its row behind: the sweep takes an
/// authentication request and a logout request once they ran out, and leaves the
/// ones still waiting.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn saml_requests_that_ran_out_are_taken_away() {
    let plane = Plane::with_actions(&[]).await;
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    let now = chrono::Utc::now();
    for (table, kept, request_id, expires_at) in [
        (
            "saml_login_requests",
            "auth_session",
            "_ran-out",
            now - chrono::Duration::minutes(1),
        ),
        (
            "saml_login_requests",
            "auth_session",
            "_still-waiting",
            now + chrono::Duration::hours(1),
        ),
        (
            "saml_logout_requests",
            "resume_to",
            "_ran-out",
            now - chrono::Duration::minutes(1),
        ),
        (
            "saml_logout_requests",
            "resume_to",
            "_still-waiting",
            now + chrono::Duration::hours(1),
        ),
    ] {
        let statement = format!(
            "INSERT INTO {table} (tenant, realm_id, request_id, provider_alias, {kept}, expires_at) \
             VALUES ($1, $2, $3, 'upstream', 'a-value', $4)"
        );
        transaction
            .execute(
                statement.as_str(),
                &[&support::TENANT, &support::REALM, &request_id, &expires_at],
            )
            .await
            .expect("a request planted");
    }
    transaction.commit().await.expect("the requests kept");

    let swept = sweep_every_realm(&plane.tenancy())
        .await
        .expect("the realms were listed");

    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    for table in ["saml_login_requests", "saml_logout_requests"] {
        let census = format!("SELECT request_id FROM {table} ORDER BY request_id");
        let left: Vec<String> = transaction
            .query(census.as_str(), &[])
            .await
            .expect("a census")
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(left, vec!["_still-waiting".to_owned()], "{table}");
    }
    assert_eq!(swept.saml_login_requests, 1, "{swept:?}");
    assert_eq!(swept.saml_logout_requests, 1, "{swept:?}");
}

/// A pass over several realms reports what each of them gave up: a stale text
/// counter and a spent anchor in two realms are two of each, not none.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_pass_counts_the_text_counters_and_anchors_of_every_realm() {
    let plane = Plane::with_actions(&[]).await;
    plane.plant_realm("second").await;
    let now = chrono::Utc::now();
    for realm in [support::REALM, "second"] {
        let transaction = plane
            .scoped(&TenantContext::new(support::TENANT, realm))
            .await;
        transaction
            .execute(
                "INSERT INTO sms_velocity (tenant, realm_id, recipient, hour, sent) \
                 VALUES ($1, $2, '+22890000000', $3, 1)",
                &[&support::TENANT, &realm, &(now - chrono::Duration::days(3))],
            )
            .await
            .expect("a stale text counter");
        transaction
            .execute(
                "INSERT INTO ussd_sessions \
                     (tenant, realm_id, session_id, user_id, anchored, expires_at) \
                 VALUES ($1, $2, 'sweep-anchor', $3, $4, $5)",
                &[
                    &support::TENANT,
                    &realm,
                    &support::SUBJECT,
                    &b"a-digest".as_slice(),
                    &(now - chrono::Duration::minutes(1)),
                ],
            )
            .await
            .expect("a spent anchor");
        transaction.commit().await.expect("the seed kept");
    }

    let swept = sweep_every_realm(&plane.tenancy())
        .await
        .expect("the realms were listed");
    assert_eq!(
        (swept.sms_counters, swept.ussd_anchors),
        (2, 2),
        "a realm's text counters or anchors went uncounted: {swept:?}"
    );
}

/// A minute of failures from an address goes once its realm's own window no
/// longer reaches it, and not before: twenty minutes is stale under a window
/// of fifteen and still counted under one of an hour.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_pass_drops_the_minutes_no_window_reaches_any_more() {
    let plane = Plane::with_actions(&[]).await;
    plane.plant_realm("second").await;
    let now = chrono::Utc::now().timestamp();
    let minute = |ago: i64| (now - ago) - (now - ago).rem_euclid(60);
    for (realm, window) in [(support::REALM, 900), ("second", 3600)] {
        let transaction = plane
            .scoped(&TenantContext::new(support::TENANT, realm))
            .await;
        transaction
            .execute(
                "UPDATE realms SET source_window_seconds = $1 WHERE realm_id = $2",
                &[&window, &realm],
            )
            .await
            .expect("the window");
        for ago in [60, 20 * 60, 2 * 3600] {
            transaction
                .execute(
                    "INSERT INTO source_failures \
                         (tenant, realm_id, source, named, minute, failures) \
                     VALUES ($1, $2, '203.0.113.7', '', $3, 1)",
                    &[&support::TENANT, &realm, &minute(ago)],
                )
                .await
                .expect("a counted minute");
        }
        transaction.commit().await.expect("the seed kept");
    }

    let swept = sweep_every_realm(&plane.tenancy())
        .await
        .expect("the realms were listed");
    assert_eq!(swept.source_failures, 3, "{swept:?}");
    for (realm, kept) in [(support::REALM, 1), ("second", 2)] {
        let transaction = plane
            .scoped(&TenantContext::new(support::TENANT, realm))
            .await;
        let left: i64 = transaction
            .query_one("SELECT COUNT(*) FROM source_failures", &[])
            .await
            .expect("the counts")
            .get(0);
        assert_eq!(left, kept, "{realm} kept the wrong minutes");
    }
}
