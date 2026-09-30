use chrono::{DateTime, Utc};
use crypto::envelope::Envelope;
use secrecy::SecretBox;
use serde_json::Value;

use crate::error::{StoreError, StoreResult, refuse_broken_rule};
use crate::keyring::RealmKeyring;
use crate::tenancy::UnitOfWork;

const PURPOSE: &str = "wallet-identity";
const ID: &str = "digest-key";

/// How the realm knows people by a credential their wallet presents.
#[derive(Debug, Clone, PartialEq)]
pub struct WalletIdentity {
    /// The credential asked for, as one DCQL credential query.
    pub credential_query: Value,
    /// The issuer that vouches for identities.
    pub issuer: String,
    /// The claim that identifies, as a path of member names.
    pub identifier_path: Vec<String>,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

/// The realm's profile, when it keeps one. Its key stays sealed: saying how
/// the realm knows people needs none of it.
pub async fn load(transaction: &UnitOfWork) -> StoreResult<Option<WalletIdentity>> {
    let row = transaction
        .query_opt(
            "SELECT credential_query, issuer, identifier_path, updated_by, updated_at \
             FROM realm_wallet_identity",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let path: Value = row.get("identifier_path");
    let identifier_path = serde_json::from_value(path).map_err(|_| StoreError::Backend)?;
    Ok(Some(WalletIdentity {
        credential_query: row.get("credential_query"),
        issuer: row.get("issuer"),
        identifier_path,
        updated_by: row.get("updated_by"),
        updated_at: row.get("updated_at"),
    }))
}

/// Keep the realm's profile, with `drawn` sealed as its key the first time.
/// A profile already kept keeps the key it holds: every identity linked is a
/// digest under that key, and another key would leave each naming nobody.
pub async fn keep(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
    profile: &WalletIdentity,
    drawn: &[u8],
) -> StoreResult<()> {
    let path = serde_json::to_value(&profile.identifier_path).map_err(|_| StoreError::Backend)?;
    let sealed = ring.seal(envelope, PURPOSE, ID, drawn).await?;
    let version = ring.active_version() as i32;
    transaction
        .execute(
            "INSERT INTO realm_wallet_identity \
                 (tenant, realm_id, credential_query, issuer, identifier_path, \
                  sealed_digest_key, sealed_version, updated_by, updated_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7 \
             ON CONFLICT (tenant, realm_id) DO UPDATE SET \
                 credential_query = EXCLUDED.credential_query, \
                 issuer = EXCLUDED.issuer, \
                 identifier_path = EXCLUDED.identifier_path, \
                 updated_by = EXCLUDED.updated_by, \
                 updated_at = EXCLUDED.updated_at",
            &[
                &profile.credential_query,
                &profile.issuer,
                &path,
                &sealed,
                &version,
                &profile.updated_by,
                &profile.updated_at,
            ],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(())
}

/// The key the realm's identifiers are digested under, opened, when the realm
/// keeps a profile.
pub async fn open_digest_key(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> StoreResult<Option<SecretBox<Vec<u8>>>> {
    let row = transaction
        .query_opt("SELECT sealed_digest_key FROM realm_wallet_identity", &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let sealed: Vec<u8> = row.get("sealed_digest_key");
    Ok(Some(ring.open(envelope, PURPOSE, ID, &sealed).await?))
}
