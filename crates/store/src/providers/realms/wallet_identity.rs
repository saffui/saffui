use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::error::{StoreError, StoreResult, refuse_broken_rule};
use crate::tenancy::UnitOfWork;

/// How the realm knows people by a credential their wallet presents.
#[derive(Debug, Clone, PartialEq)]
pub struct WalletIdentity {
    /// The credential asked for, as one DCQL credential query.
    pub credential_query: Value,
    /// The issuer that vouches for identities.
    pub issuer: String,
    /// The claim that identifies, as a path of member names.
    pub identifier_path: Vec<String>,
    /// The HMAC key identifiers are kept under, sealed.
    pub digest_key: Vec<u8>,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

/// The realm's profile, when it keeps one.
pub async fn load(transaction: &UnitOfWork) -> StoreResult<Option<WalletIdentity>> {
    let row = transaction
        .query_opt(
            "SELECT credential_query, issuer, identifier_path, digest_key, updated_by, \
                    updated_at FROM realm_wallet_identity",
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
        digest_key: row.get("digest_key"),
        updated_by: row.get("updated_by"),
        updated_at: row.get("updated_at"),
    }))
}

/// Keep the realm's profile. A profile already kept keeps the key it holds,
/// whatever `profile` carries: every identity linked is a digest under that
/// key, and another key would leave each of them naming nobody.
pub async fn keep(transaction: &UnitOfWork, profile: &WalletIdentity) -> StoreResult<()> {
    let path = serde_json::to_value(&profile.identifier_path).map_err(|_| StoreError::Backend)?;
    transaction
        .execute(
            "INSERT INTO realm_wallet_identity \
                 (tenant, realm_id, credential_query, issuer, identifier_path, digest_key, \
                  updated_by, updated_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6 \
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
                &profile.digest_key,
                &profile.updated_by,
                &profile.updated_at,
            ],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(())
}
