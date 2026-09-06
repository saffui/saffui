use chrono::{DateTime, Utc};
use crypto::envelope::Envelope;
use deadpool_postgres::Transaction;
use secrecy::{ExposeSecret, SecretBox};

use crate::error::{StoreError, StoreResult};
use crate::keyring::RealmKeyring;

const PURPOSE: &str = "ussd";
const ID: &str = "secret";

/// Write the secret the realm's USSD gateway presents, replacing whatever
/// was there.
pub async fn keep_secret(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    secret: &SecretBox<String>,
) -> StoreResult<()> {
    let sealed = ring
        .seal(envelope, PURPOSE, ID, secret.expose_secret().as_bytes())
        .await?;
    transaction
        .execute(
            "INSERT INTO realm_ussd (tenant, realm_id, sealed_secret, sealed_version) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2 \
             ON CONFLICT (tenant, realm_id) DO UPDATE \
             SET sealed_secret = EXCLUDED.sealed_secret, \
                 sealed_version = EXCLUDED.sealed_version, \
                 updated_at = now()",
            &[&sealed, &(ring.active_version() as i32)],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The secret, opened, or nothing where the realm takes no USSD.
pub async fn load_secret(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> StoreResult<Option<SecretBox<String>>> {
    let Some(row) = transaction
        .query_opt("SELECT sealed_secret FROM realm_ussd LIMIT 1", &[])
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };
    let sealed: Vec<u8> = row.get(0);
    let opened = ring.open(envelope, PURPOSE, ID, &sealed).await?;
    let secret =
        String::from_utf8(opened.expose_secret().clone()).map_err(|_| StoreError::Backend)?;
    Ok(Some(SecretBox::new(Box::new(secret))))
}

/// Forget the gateway, and say whether there was one to forget.
pub async fn forget_secret(transaction: &Transaction<'_>) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM realm_ussd", &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Anchor what this gateway session was shown, replacing whatever it was
/// shown before: one screen, one pending answer.
pub async fn anchor(
    transaction: &Transaction<'_>,
    session_id: &str,
    user_id: &str,
    anchored: &[u8],
    expires_at: DateTime<Utc>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO ussd_sessions (tenant, realm_id, session_id, user_id, anchored, \
                                        expires_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4 \
             ON CONFLICT (tenant, realm_id, session_id) DO UPDATE \
             SET user_id = EXCLUDED.user_id, \
                 anchored = EXCLUDED.anchored, \
                 expires_at = EXCLUDED.expires_at",
            &[&session_id, &user_id, &anchored, &expires_at],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Take the anchor and hand back what the screen showed, once: an answer
/// spends its screen the way a code spends its token.
pub async fn take_anchor(
    transaction: &Transaction<'_>,
    session_id: &str,
    now: DateTime<Utc>,
) -> StoreResult<Option<(String, Vec<u8>)>> {
    Ok(transaction
        .query_opt(
            "DELETE FROM ussd_sessions \
             WHERE tenant = current_setting('saffui.current_tenant', true) \
               AND realm_id = current_setting('saffui.current_realm', true) \
               AND session_id = $1 AND expires_at > $2 \
             RETURNING user_id, anchored",
            &[&session_id, &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| (row.get(0), row.get(1))))
}

/// Drop anchors nothing will answer any more, and say how many.
pub async fn drop_expired_anchors(
    transaction: &Transaction<'_>,
    now: DateTime<Utc>,
) -> StoreResult<u64> {
    transaction
        .execute("DELETE FROM ussd_sessions WHERE expires_at <= $1", &[&now])
        .await
        .map_err(|_| StoreError::Backend)
}
