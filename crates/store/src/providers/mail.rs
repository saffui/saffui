use crypto::envelope::Envelope;
use deadpool_postgres::Transaction;
use models::entities::mail::{MailCredentials, MailSettings};
use secrecy::{ExposeSecret, SecretBox};

use crate::error::{StoreError, StoreResult};
use crate::keyring::RealmKeyring;

const PURPOSE: &str = "mail";
const ID: &str = "password";

const COLUMNS: &str = "host, port, from_address, from_name, reply_to, implicit_tls, \
                       username, sealed_password, sealed_version";

/// Write a realm's settings, replacing whatever was there.
pub async fn keep(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    settings: &MailSettings,
) -> StoreResult<()> {
    let (username, sealed, version) = match &settings.credentials {
        None => (None, None, None),
        Some(held) => (
            Some(held.username.as_str()),
            Some(
                ring.seal(
                    envelope,
                    PURPOSE,
                    ID,
                    held.password.expose_secret().as_bytes(),
                )
                .await?,
            ),
            Some(ring.active_version() as i32),
        ),
    };

    transaction
        .execute(
            "INSERT INTO realm_mail \
                 (tenant, realm_id, host, port, from_address, from_name, reply_to, \
                  implicit_tls, username, sealed_password, sealed_version) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8, $9 \
             ON CONFLICT (tenant, realm_id) DO UPDATE \
             SET host = EXCLUDED.host, \
                 port = EXCLUDED.port, \
                 from_address = EXCLUDED.from_address, \
                 from_name = EXCLUDED.from_name, \
                 reply_to = EXCLUDED.reply_to, \
                 implicit_tls = EXCLUDED.implicit_tls, \
                 username = EXCLUDED.username, \
                 sealed_password = EXCLUDED.sealed_password, \
                 sealed_version = EXCLUDED.sealed_version, \
                 updated_at = now()",
            &[
                &settings.host,
                &i32::from(settings.port),
                &settings.from_address,
                &settings.from_name,
                &settings.reply_to,
                &settings.implicit_tls,
                &username,
                &sealed,
                &version,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// A realm's settings, password opened.
pub async fn load(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> StoreResult<Option<MailSettings>> {
    let statement = format!("SELECT {COLUMNS} FROM realm_mail LIMIT 1");
    let Some(row) = transaction
        .query_opt(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };

    let credentials = match (
        row.get::<_, Option<String>>("username"),
        row.get::<_, Option<Vec<u8>>>("sealed_password"),
    ) {
        (Some(username), Some(sealed)) => {
            let opened = ring.open(envelope, PURPOSE, ID, &sealed).await?;
            let password = String::from_utf8(opened.expose_secret().clone())
                .map_err(|_| StoreError::Backend)?;
            Some(MailCredentials {
                username,
                password: SecretBox::new(Box::new(password)),
            })
        }
        _ => None,
    };

    Ok(Some(MailSettings {
        host: row.get("host"),
        port: u16::try_from(row.get::<_, i32>("port")).map_err(|_| StoreError::Backend)?,
        from_address: row.get("from_address"),
        from_name: row.get("from_name"),
        reply_to: row.get("reply_to"),
        implicit_tls: row.get("implicit_tls"),
        credentials,
    }))
}

/// Forget how a realm sends mail, and say whether there was anything to forget.
pub async fn forget(transaction: &Transaction<'_>) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM realm_mail", &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}
