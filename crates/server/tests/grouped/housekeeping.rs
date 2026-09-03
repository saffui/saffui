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
