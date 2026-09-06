use crypto::envelope::Envelope;
use deadpool_postgres::Transaction;
use models::entities::sms::SmsSettings;
use secrecy::{ExposeSecret, SecretBox};

use crate::error::{StoreError, StoreResult};
use crate::keyring::RealmKeyring;

const PURPOSE: &str = "sms";
const ID: &str = "token";

const COLUMNS: &str = "url, sender, sealed_token, sealed_version";

/// Write a realm's settings, replacing whatever was there.
pub async fn keep(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    settings: &SmsSettings,
) -> StoreResult<()> {
    let (sealed, version) = match &settings.token {
        None => (None, None),
        Some(held) => (
            Some(
                ring.seal(envelope, PURPOSE, ID, held.expose_secret().as_bytes())
                    .await?,
            ),
            Some(ring.active_version() as i32),
        ),
    };

    transaction
        .execute(
            "INSERT INTO realm_sms \
                 (tenant, realm_id, url, sender, sealed_token, sealed_version) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4 \
             ON CONFLICT (tenant, realm_id) DO UPDATE \
             SET url = EXCLUDED.url, \
                 sender = EXCLUDED.sender, \
                 sealed_token = EXCLUDED.sealed_token, \
                 sealed_version = EXCLUDED.sealed_version, \
                 updated_at = now()",
            &[&settings.url, &settings.sender, &sealed, &version],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// A realm's settings, token opened.
pub async fn load(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> StoreResult<Option<SmsSettings>> {
    let statement = format!("SELECT {COLUMNS} FROM realm_sms LIMIT 1");
    let Some(row) = transaction
        .query_opt(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };

    let token = match row.get::<_, Option<Vec<u8>>>("sealed_token") {
        Some(sealed) => {
            let opened = ring.open(envelope, PURPOSE, ID, &sealed).await?;
            let token = String::from_utf8(opened.expose_secret().clone())
                .map_err(|_| StoreError::Backend)?;
            Some(SecretBox::new(Box::new(token)))
        }
        None => None,
    };

    Ok(Some(SmsSettings {
        url: row.get("url"),
        sender: row.get("sender"),
        token,
    }))
}

/// Forget how a realm sends SMS, and say whether there was anything to forget.
pub async fn forget(transaction: &Transaction<'_>) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM realm_sms", &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}
