#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use server::jobs::sweep_every_realm;
use store::tenancy::{Tenancy, TenantContext};

/// A revocation that has already outlived the token it was for. It holds
/// nothing but the realm, so a realm with no client and no user can still be
/// given something to sweep.
async fn plant_expired_revocation(plane: &Plane, realm: &str, token_id: &str) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, realm))
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
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, realm))
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

    let swept = sweep_every_realm(&plane.pool(), &plane.tenancy())
        .await
        .expect("the realms were listed");
    assert_eq!(swept.revocations, 2, "a realm was left behind: {swept:?}");
    assert_eq!(revocations_left(&plane, support::REALM).await, 0);
    assert_eq!(revocations_left(&plane, "second").await, 0);

    // Nothing left to take, and the pass says so rather than failing.
    let swept = sweep_every_realm(&plane.pool(), &plane.tenancy())
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

    let mut connection = plane.connection().await;
    let held = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
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

    let swept = sweep_every_realm(&plane.pool(), &plane.tenancy())
        .await
        .expect("the realms were listed");
    assert_eq!(swept.total(), 0, "a held realm was swept anyway: {swept:?}");

    held.commit().await.expect("the lock released");
    drop(connection);

    let swept = sweep_every_realm(&plane.pool(), &plane.tenancy())
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

    let swept = sweep_every_realm(&plane.pool(), &Tenancy::in_region("somewhere-else"))
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
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
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

    let swept = sweep_every_realm(&plane.pool(), &plane.tenancy())
        .await
        .expect("the realms were listed");
    assert_eq!(
        swept.client_sessions, 1,
        "other than the ended grant was taken: {swept:?}"
    );

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
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
