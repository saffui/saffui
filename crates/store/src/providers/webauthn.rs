use crate::tenancy::UnitOfWork;
use models::entities::credentials::{AuthenticatorAttachment, CredentialChange};
use serde_json::Value;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

/// A key's type in a credential change: the word the flows and the admin
/// listing already use for a passkey.
pub const CREDENTIAL_TYPE: &str = "webauthn";

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
    /// Where the browser said the key lives, when it said.
    pub attachment: Option<AuthenticatorAttachment>,
    /// The authenticator model the key named at enrolment, when it named one.
    pub aaguid: Option<String>,
    /// The attestation format the key answered its enrolment with.
    pub attestation_format: Option<String>,
    /// Stamped by the store on enrolment; whatever a caller sets is ignored.
    pub enrolled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Enrol one, and say so.
pub async fn enrol(transaction: &UnitOfWork, credential: &EnrolledCredential) -> StoreResult<()> {
    let written = transaction
        .execute(
            "INSERT INTO webauthn_credentials \
                 (tenant, realm_id, credential_id, user_id, label, passkey, sign_count, \
                  attachment, aaguid, attestation_format) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5, $6, \
                    $7::text::uuid, $8",
            &[
                &credential.credential_id,
                &credential.user_id,
                &credential.label,
                &credential.passkey,
                &credential.sign_count,
                &credential.attachment,
                &credential.aaguid,
                &credential.attestation_format,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    if written > 0 {
        announce_key_change(
            transaction,
            &credential.user_id,
            CredentialChange::Create,
            credential.attachment,
            &credential.passkey,
        )
        .await?;
    }
    Ok(())
}

/// The one a login is presenting.
pub async fn by_id(
    transaction: &UnitOfWork,
    credential_id: &[u8],
) -> StoreResult<Option<EnrolledCredential>> {
    Ok(transaction
        .query_opt(
            "SELECT credential_id, user_id, label, passkey, sign_count, attachment, \
                    aaguid::text AS aaguid, attestation_format, enrolled_at, last_used_at \
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
    transaction: &UnitOfWork,
    user_id: &str,
) -> StoreResult<Vec<EnrolledCredential>> {
    Ok(transaction
        .query(
            "SELECT credential_id, user_id, label, passkey, sign_count, attachment, \
                    aaguid::text AS aaguid, attestation_format, enrolled_at, last_used_at \
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
    transaction: &UnitOfWork,
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

/// Revoke one of this user's keys at an administrator's hand, and say whether
/// there was one to revoke.
///
/// The user is part of the question, not a nicety: a caller naming a user and
/// an identifier must not reach past that user, however it learned the name.
/// Only a key that was there is announced as gone.
pub async fn revoke(
    transaction: &UnitOfWork,
    user_id: &str,
    credential_id: &[u8],
) -> StoreResult<bool> {
    remove_key(
        transaction,
        user_id,
        credential_id,
        CredentialChange::Revoke,
    )
    .await
}

/// Delete one of this user's keys at their own hand. It reaches exactly as far
/// as [`revoke`]; only what a receiver is told differs.
pub async fn delete(
    transaction: &UnitOfWork,
    user_id: &str,
    credential_id: &[u8],
) -> StoreResult<bool> {
    remove_key(
        transaction,
        user_id,
        credential_id,
        CredentialChange::Delete,
    )
    .await
}

async fn remove_key(
    transaction: &UnitOfWork,
    user_id: &str,
    credential_id: &[u8],
    change: CredentialChange,
) -> StoreResult<bool> {
    let removed = transaction
        .query_opt(
            "DELETE FROM webauthn_credentials WHERE user_id = $1 AND credential_id = $2 \
             RETURNING attachment, passkey",
            &[&user_id, &credential_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let Some(row) = removed else {
        return Ok(false);
    };
    announce_key_change(
        transaction,
        user_id,
        change,
        row.get("attachment"),
        &row.get::<_, Value>("passkey"),
    )
    .await?;
    Ok(true)
}

/// Announce a change to this person's keys, in the transaction that made it.
///
/// A receiver is told what it takes to name the key in its own words: where the
/// browser said the key lives, and the backup flag the stored key keeps, the
/// only hint left for a key enrolled before attachments were recorded.
async fn announce_key_change(
    transaction: &UnitOfWork,
    user_id: &str,
    change: CredentialChange,
    attachment: Option<AuthenticatorAttachment>,
    passkey: &Value,
) -> StoreResult<()> {
    super::outbox::emit(
        transaction,
        super::outbox::CREDENTIAL_CHANGED,
        user_id,
        &serde_json::json!({
            "credential_type": CREDENTIAL_TYPE,
            "change_type": change,
            "attachment": attachment,
            "backup_eligible": passkey["cred"]["backup_eligible"].as_bool(),
        }),
    )
    .await
}

fn read(row: Row) -> EnrolledCredential {
    EnrolledCredential {
        credential_id: row.get("credential_id"),
        user_id: row.get("user_id"),
        label: row.get("label"),
        passkey: row.get("passkey"),
        sign_count: row.get("sign_count"),
        attachment: row.get("attachment"),
        aaguid: row.get("aaguid"),
        attestation_format: row.get("attestation_format"),
        enrolled_at: row.get("enrolled_at"),
        last_used_at: row.get("last_used_at"),
    }
}
