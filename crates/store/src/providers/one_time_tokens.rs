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
    // The login this token finishes, when it finishes one. A token that binds
    // to nothing is spendable from any browser.
    bound_to: Option<&str>,
    expires_at: chrono::DateTime<chrono::Utc>,
    // Stamped from the caller's clock, not the database's. The cooldown is
    // read back and compared against the caller's, and a window measured
    // across two clocks is one that means nothing when they disagree.
    now: chrono::DateTime<chrono::Utc>,
) -> StoreResult<()> {
    let (tenant, realm_id, user_id, purpose) =
        (owner.tenant, owner.realm_id, owner.user_id, owner.purpose);
    let hash = digest
        .hash(HashAlg::Sha256, raw_token.as_bytes())
        .map_err(|_| StoreError::Backend)?;

    transaction
        .execute(
            "INSERT INTO one_time_tokens \
                 (tenant, realm_id, user_id, purpose, token_hash, bound_to, \
                  expires_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (tenant, realm_id, user_id, purpose) DO UPDATE \
             SET token_hash = EXCLUDED.token_hash, \
                 bound_to = EXCLUDED.bound_to, \
                 expires_at = EXCLUDED.expires_at, \
                 created_at = EXCLUDED.created_at",
            &[
                &tenant,
                &realm_id,
                &user_id,
                &purpose,
                &hash,
                &bound_to,
                &expires_at,
                &now,
            ],
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
    // The login presenting it. A token bound to another is not spendable here,
    // whoever holds it.
    bound_to: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> StoreResult<Spent> {
    let hash = digest
        .hash(HashAlg::Sha256, presented.as_bytes())
        .map_err(|_| StoreError::Backend)?;

    let spent = transaction
        .execute(
            "DELETE FROM one_time_tokens \
             WHERE user_id = $1 AND purpose = $2 AND token_hash = $3 AND expires_at > $4 \
               AND bound_to IS NOT DISTINCT FROM $5",
            &[&user_id, &purpose, &hash, &now, &bound_to],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    if spent > 0 {
        return Ok(Spent::Yes);
    }

    // Only on the miss, so the common path is still one statement. The row is
    // read and not removed: a link opened in the wrong browser must survive to
    // be used in the right one.
    let elsewhere = transaction
        .query_opt(
            "SELECT 1 FROM one_time_tokens \
             WHERE user_id = $1 AND purpose = $2 AND token_hash = $3 AND expires_at > $4",
            &[&user_id, &purpose, &hash, &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(match elsewhere {
        Some(_) => Spent::ElsewhereBound,
        None => Spent::Unknown,
    })
}

/// What came of presenting a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spent {
    Yes,
    /// Live and this person's, and made for another login. Told apart from an
    /// unknown one because it is the ordinary way a mailed link is followed:
    /// the mail was opened somewhere other than where the login began.
    ElsewhereBound,
    /// Unknown, already spent, or expired. One answer, because telling them
    /// apart says which links once existed.
    Unknown,
}

/// When the live token for this user and purpose was minted, if there is one.
///
/// What a caller deciding whether to send another needs: not its value, and not
/// merely that one exists, but how long ago the last one went out.
pub async fn minted_at(
    transaction: &Transaction<'_>,
    user_id: &str,
    purpose: Purpose<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> StoreResult<Option<chrono::DateTime<chrono::Utc>>> {
    Ok(transaction
        .query_opt(
            "SELECT created_at FROM one_time_tokens \
             WHERE user_id = $1 AND purpose = $2 AND expires_at > $3",
            &[&user_id, &purpose, &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| row.get(0)))
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
