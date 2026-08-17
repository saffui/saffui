//! The single use, short lived things a login hands out: the code in a message,
//! the link in a mail, a reset token.
//!
//! Only the digest is stored. The value travels in a message or a URL and lands
//! in inboxes, browser history and proxy logs, so reading this table yields
//! nothing that can be presented.

use crypto::provider::{DigestProvider, HashAlg};
use deadpool_postgres::Transaction;

use crate::error::{StoreError, StoreResult};

/// Who a token belongs to, and what it is for.
///
/// Grouped rather than passed as four strings in a row, where any two can be
/// swapped and still compile.
#[derive(Debug, Clone, Copy)]
pub struct Owner<'a> {
    pub tenant: &'a str,
    pub realm_id: &'a str,
    pub user_id: &'a str,
    pub purpose: Purpose<'a>,
}

/// What a token is for. Free text rather than a catalogue: a deployment adds a
/// purpose by minting one, and refusing an unknown one would fail a login over a
/// flow this build merely has no name for.
pub type Purpose<'a> = &'a str;

/// Mint a token for a user and a purpose.
///
/// Replaces whatever was there. One row per user and purpose bounds how many are
/// live at once, and means a link requested twice only honours the newer, which
/// is the alternative to a mailbox full of working links.
///
/// The digest comes through the provider. A digest computed some other way is
/// one this deployment did not choose, and the whole value of storing one is
/// that it is the one the verifier will compute.
pub async fn mint(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    owner: Owner<'_>,
    raw_token: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> StoreResult<()> {
    let (tenant, realm_id, user_id, purpose) =
        (owner.tenant, owner.realm_id, owner.user_id, owner.purpose);
    let hash = digest
        .hash(HashAlg::Sha256, raw_token.as_bytes())
        .map_err(|_| StoreError::Backend)?;

    transaction
        .execute(
            "INSERT INTO one_time_tokens (tenant, realm_id, user_id, purpose, token_hash, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (tenant, realm_id, user_id, purpose) DO UPDATE \
             SET token_hash = EXCLUDED.token_hash, \
                 expires_at = EXCLUDED.expires_at, \
                 created_at = now()",
            &[&tenant, &realm_id, &user_id, &purpose, &hash, &expires_at],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Spend a token, if it is the one that was minted and has not expired.
///
/// Consumed in the same statement that checks it. Reading it and then deleting
/// it is a window in which two presentations both find it valid, which for a
/// link in a mail is the difference between single use and single use most of
/// the time.
///
/// An expired token is refused and removed either way, so a stale row does not
/// sit there being compared against.
pub async fn spend(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    user_id: &str,
    purpose: Purpose<'_>,
    presented: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> StoreResult<bool> {
    let hash = digest
        .hash(HashAlg::Sha256, presented.as_bytes())
        .map_err(|_| StoreError::Backend)?;

    let spent = transaction
        .execute(
            "DELETE FROM one_time_tokens \
             WHERE user_id = $1 AND purpose = $2 AND token_hash = $3 AND expires_at > $4",
            &[&user_id, &purpose, &hash, &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(spent > 0)
}

/// Whether a token is outstanding for this user and purpose.
///
/// Says nothing about its value, which is the point: a caller deciding whether
/// to send another one needs to know there is a live one, not what it is.
pub async fn outstanding(
    transaction: &Transaction<'_>,
    user_id: &str,
    purpose: Purpose<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> StoreResult<bool> {
    let found: i64 = transaction
        .query_one(
            "SELECT count(*) FROM one_time_tokens \
             WHERE user_id = $1 AND purpose = $2 AND expires_at > $3",
            &[&user_id, &purpose, &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0);
    Ok(found > 0)
}

/// Drop everything that has expired, and say how many.
///
/// Scoped like everything else, so a sweep clears this realm's and reports on
/// this realm's.
pub async fn drop_expired(
    transaction: &Transaction<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM one_time_tokens WHERE expires_at <= $1",
            &[&now],
        )
        .await
        .map_err(|_| StoreError::Backend)
}
