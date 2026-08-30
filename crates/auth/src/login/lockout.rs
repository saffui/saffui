//! The realm's answer to a hammered credential.
//!
//! One count per person, shared by every door that verifies a password, so
//! an attacker cannot pick the entrance that does not count.

use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::realm::RealmModel;
use store::error::StoreResult;
use store::providers::login as login_store;

/// When this person's lockout ends, or nothing when they are not locked.
///
/// Asked before anything is verified, and without counting: an answer that
/// is never looked at cannot be wrong, and extending the lock on every
/// attempt would let anybody hold somebody else's account shut
/// indefinitely.
pub async fn until(
    transaction: &Transaction<'_>,
    realm: &RealmModel,
    user_id: &str,
    now: DateTime<Utc>,
) -> StoreResult<Option<i64>> {
    if !realm.brute_force.protected {
        return Ok(None);
    }
    let held = login_store::failures(transaction, user_id).await?;
    Ok(held
        .filter(|record| record.is_locked_at(now.timestamp()))
        .map(|record| record.failed_login_not_before))
}

/// Count one failure, and lock when the count says to.
pub async fn count(
    transaction: &Transaction<'_>,
    realm: &RealmModel,
    user_id: &str,
    from: Option<&str>,
    now: DateTime<Utc>,
) -> StoreResult<()> {
    if !realm.brute_force.protected {
        return Ok(());
    }
    let policy = realm.brute_force;
    // The window is worked out from the count this failure will make, which
    // is what the row already holds plus one.
    let standing = login_store::failures(transaction, user_id)
        .await?
        .map_or(0, |record| record.num_failures);
    login_store::record_failure(
        transaction,
        user_id,
        now.timestamp(),
        from,
        i64::from(policy.max_failures),
        policy.lockout_for(standing + 1),
        i64::from(policy.reset_seconds),
    )
    .await?;
    Ok(())
}

/// Forget what was counted. A login that succeeded says the person is the
/// person, so what was counted against them was noise.
pub async fn clear(transaction: &Transaction<'_>, user_id: &str) -> StoreResult<()> {
    login_store::clear_failures(transaction, user_id).await?;
    Ok(())
}
