use crate::tenancy::UnitOfWork;
use crypto::envelope::Envelope;
use models::entities::whatsapp::WhatsAppSettings;
use secrecy::{ExposeSecret, SecretBox};

use crate::error::{StoreError, StoreResult};
use crate::keyring::RealmKeyring;

const PURPOSE: &str = "whatsapp";
const ID: &str = "token";

/// Write a realm's settings, replacing whatever was there.
pub async fn keep(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
    settings: &WhatsAppSettings,
) -> StoreResult<()> {
    let sealed = ring
        .seal(
            envelope,
            PURPOSE,
            ID,
            settings.token.expose_secret().as_bytes(),
        )
        .await?;
    let version = ring.active_version() as i32;

    transaction
        .execute(
            "INSERT INTO realm_whatsapp \
                 (tenant, realm_id, phone_number_id, template, languages, \
                  sealed_token, sealed_version) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5 \
             ON CONFLICT (tenant, realm_id) DO UPDATE \
             SET phone_number_id = EXCLUDED.phone_number_id, \
                 template = EXCLUDED.template, \
                 languages = EXCLUDED.languages, \
                 sealed_token = EXCLUDED.sealed_token, \
                 sealed_version = EXCLUDED.sealed_version, \
                 updated_at = now()",
            &[
                &settings.phone_number_id,
                &settings.template,
                &settings.languages,
                &sealed,
                &version,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// A realm's settings, token opened.
pub async fn load(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> StoreResult<Option<WhatsAppSettings>> {
    let Some(row) = transaction
        .query_opt(
            "SELECT phone_number_id, template, languages, sealed_token \
             FROM realm_whatsapp LIMIT 1",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };

    let sealed: Vec<u8> = row.get("sealed_token");
    let opened = ring.open(envelope, PURPOSE, ID, &sealed).await?;
    let token =
        String::from_utf8(opened.expose_secret().clone()).map_err(|_| StoreError::Backend)?;

    Ok(Some(WhatsAppSettings {
        phone_number_id: row.get("phone_number_id"),
        template: row.get("template"),
        languages: row.get("languages"),
        token: SecretBox::new(Box::new(token)),
    }))
}

/// Forget how a realm sends over WhatsApp, and say whether there was anything
/// to forget.
pub async fn forget(transaction: &UnitOfWork) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM realm_whatsapp", &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}
