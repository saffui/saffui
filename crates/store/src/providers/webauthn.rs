use deadpool_postgres::Transaction;
use serde_json::Value;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

/// One enrolled authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledCredential {
    /// The raw identifier the authenticator returns, which a login presents and
    /// an allow list names.
    pub credential_id: Vec<u8>,
    pub user_id: String,
    pub label: String,
    /// Public key, transports and flags, as serialised.
    pub passkey: Value,
    pub sign_count: i64,
    /// Stamped by the store on enrolment; whatever a caller sets is ignored.
    pub enrolled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Enrol one.
pub async fn enrol(
    transaction: &Transaction<'_>,
    credential: &EnrolledCredential,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO webauthn_credentials \
                 (tenant, realm_id, credential_id, user_id, label, passkey, sign_count) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5",
            &[
                &credential.credential_id,
                &credential.user_id,
                &credential.label,
                &credential.passkey,
                &credential.sign_count,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The one a login is presenting.
pub async fn by_id(
    transaction: &Transaction<'_>,
    credential_id: &[u8],
) -> StoreResult<Option<EnrolledCredential>> {
    Ok(transaction
        .query_opt(
            "SELECT credential_id, user_id, label, passkey, sign_count, enrolled_at, \
                    last_used_at \
             FROM webauthn_credentials WHERE credential_id = $1",
            &[&credential_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// What a user may present, oldest enrolment first so a list reads as a history.
///
/// The identifier breaks ties, because two keys enrolled in one transaction
/// carry the same instant: `now()` is the transaction's, not the statement's.
pub async fn of_user(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<Vec<EnrolledCredential>> {
    Ok(transaction
        .query(
            "SELECT credential_id, user_id, label, passkey, sign_count, enrolled_at, \
                    last_used_at \
             FROM webauthn_credentials WHERE user_id = $1 \
             ORDER BY enrolled_at ASC, credential_id ASC",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read)
        .collect())
}

/// Record a use, and refuse a counter that did not advance.
///
/// An authenticator's counter only goes up. One that repeats or goes backwards
/// is the signature of a clone being used beside the original, which is the one
/// thing this counter exists to reveal. A counter of zero is exempt: it is what
/// an authenticator that keeps no counter reports every time.
pub async fn record_use(
    transaction: &Transaction<'_>,
    credential_id: &[u8],
    sign_count: i64,
) -> StoreResult<bool> {
    let advanced = transaction
        .execute(
            "UPDATE webauthn_credentials \
             SET sign_count = $2, last_used_at = now() \
             WHERE credential_id = $1 AND ($2 > sign_count OR $2 = 0)",
            &[&credential_id, &sign_count],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(advanced > 0)
}

/// Revoke one of this user's keys, and say whether there was one to revoke.
///
/// The user is part of the question, not a nicety: a caller naming a user and
/// an identifier must not reach past that user, however it learned the name.
pub async fn revoke(
    transaction: &Transaction<'_>,
    user_id: &str,
    credential_id: &[u8],
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM webauthn_credentials WHERE user_id = $1 AND credential_id = $2",
            &[&user_id, &credential_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

fn read(row: Row) -> EnrolledCredential {
    EnrolledCredential {
        credential_id: row.get("credential_id"),
        user_id: row.get("user_id"),
        label: row.get("label"),
        passkey: row.get("passkey"),
        sign_count: row.get("sign_count"),
        enrolled_at: row.get("enrolled_at"),
        last_used_at: row.get("last_used_at"),
    }
}
