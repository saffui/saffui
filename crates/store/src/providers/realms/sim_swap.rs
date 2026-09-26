use crate::tenancy::UnitOfWork;
use crypto::envelope::Envelope;
use models::entities::sim_swap::{SimSwapKey, SimSwapSettings};
use secrecy::{ExposeSecret, SecretBox};

use crate::error::{StoreError, StoreResult};
use crate::keyring::RealmKeyring;

const PURPOSE: &str = "sim-swap";
const ID: &str = "key";

/// Write a realm's settings, replacing whatever was there.
pub async fn keep(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
    settings: &SimSwapSettings,
) -> StoreResult<()> {
    let sealed = ring
        .seal(
            envelope,
            PURPOSE,
            ID,
            settings.key.private_pem.expose_secret(),
        )
        .await?;
    let version = ring.active_version() as i32;

    transaction
        .execute(
            "INSERT INTO realm_sim_swap \
                 (tenant, realm_id, client_id, authorize_url, token_url, check_url, \
                  max_age_hours, when_unanswered, kid, sealed_key, sealed_version, public_jwk) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 \
             ON CONFLICT (tenant, realm_id) DO UPDATE \
             SET client_id = EXCLUDED.client_id, \
                 authorize_url = EXCLUDED.authorize_url, \
                 token_url = EXCLUDED.token_url, \
                 check_url = EXCLUDED.check_url, \
                 max_age_hours = EXCLUDED.max_age_hours, \
                 when_unanswered = EXCLUDED.when_unanswered, \
                 kid = EXCLUDED.kid, \
                 sealed_key = EXCLUDED.sealed_key, \
                 sealed_version = EXCLUDED.sealed_version, \
                 public_jwk = EXCLUDED.public_jwk, \
                 updated_at = now()",
            &[
                &settings.client_id,
                &settings.authorize_url,
                &settings.token_url,
                &settings.check_url,
                &settings.max_age_hours,
                &settings.when_unanswered.as_str(),
                &settings.key.kid,
                &sealed,
                &version,
                &settings.key.public_jwk,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// A realm's settings, key opened.
pub async fn load(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> StoreResult<Option<SimSwapSettings>> {
    let Some(row) = transaction
        .query_opt(
            "SELECT client_id, authorize_url, token_url, check_url, max_age_hours, \
                    when_unanswered, kid, sealed_key, public_jwk \
             FROM realm_sim_swap LIMIT 1",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };

    let sealed: Vec<u8> = row.get("sealed_key");
    let opened = ring.open(envelope, PURPOSE, ID, &sealed).await?;
    let when_unanswered = row
        .get::<_, String>("when_unanswered")
        .parse()
        .map_err(|_| StoreError::Backend)?;

    Ok(Some(SimSwapSettings {
        client_id: row.get("client_id"),
        authorize_url: row.get("authorize_url"),
        token_url: row.get("token_url"),
        check_url: row.get("check_url"),
        max_age_hours: row.get("max_age_hours"),
        when_unanswered,
        key: SimSwapKey {
            kid: row.get("kid"),
            private_pem: SecretBox::new(Box::new(opened.expose_secret().clone())),
            public_jwk: row.get("public_jwk"),
        },
    }))
}

/// The public half the carrier checks assertions with, read without opening
/// anything.
pub async fn public_key(transaction: &UnitOfWork) -> StoreResult<Option<serde_json::Value>> {
    Ok(transaction
        .query_opt("SELECT public_jwk FROM realm_sim_swap LIMIT 1", &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| row.get(0)))
}

/// Forget how a realm asks its carrier, key included, and say whether there
/// was anything to forget.
pub async fn forget(transaction: &UnitOfWork) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM realm_sim_swap", &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}
