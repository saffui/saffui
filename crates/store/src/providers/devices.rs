use chrono::{DateTime, Utc};
use crypto::provider::{DigestProvider, HashAlg};
use deadpool_postgres::Transaction;
use models::entities::device::DeviceCodeModel;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

const COLUMNS: &str = "tenant, realm_id, user_code, client_id, scope, state, \
                       user_id, session_id, auth_time, acr, org_id, org_name, \
                       interval_secs, last_polled_at, approved_at, expires_at, created_at";

fn digest_of(digest: &dyn DigestProvider, device_code: &str) -> StoreResult<Vec<u8>> {
    digest
        .hash(HashAlg::Sha256, device_code.as_bytes())
        .map_err(|_| StoreError::Backend)
}

pub async fn open(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    device_code: &str,
    request: &DeviceCodeModel,
) -> StoreResult<()> {
    let hash = digest_of(digest, device_code)?;
    transaction
        .execute(
            "INSERT INTO oidc_device_codes \
                 (tenant, realm_id, device_digest, user_code, client_id, scope, \
                  interval_secs, expires_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6",
            &[
                &hash,
                &request.user_code,
                &request.client_id,
                &request.scope,
                &request.interval_secs,
                &request.expires_at,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn load(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    device_code: &str,
) -> StoreResult<Option<DeviceCodeModel>> {
    let hash = digest_of(digest, device_code)?;
    let statement = format!("SELECT {COLUMNS} FROM oidc_device_codes WHERE device_digest = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&hash])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// The live row behind a short code, for the page a person types it into.
pub async fn pending_by_user_code(
    transaction: &Transaction<'_>,
    user_code: &str,
    now: DateTime<Utc>,
) -> StoreResult<Option<DeviceCodeModel>> {
    let statement = format!(
        "SELECT {COLUMNS} FROM oidc_device_codes \
         WHERE user_code = $1 AND state = 'pending' AND expires_at > $2"
    );
    Ok(transaction
        .query_opt(statement.as_str(), &[&user_code, &now])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// Stamp one poll and hand back the previous stamp, so the caller can tell a
/// too-eager device to slow down without a second read.
pub async fn touch_poll(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    device_code: &str,
    now: DateTime<Utc>,
) -> StoreResult<Option<Option<DateTime<Utc>>>> {
    let hash = digest_of(digest, device_code)?;
    Ok(transaction
        .query_opt(
            "UPDATE oidc_device_codes SET last_polled_at = $2 \
             WHERE device_digest = $1 \
             RETURNING (SELECT last_polled_at FROM oidc_device_codes \
                        WHERE device_digest = $1)",
            &[&hash, &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| row.get(0)))
}

/// Approve the pending row behind a short code, freezing who approved it and
/// what their login attested. The WHERE is the state machine: an expired,
/// decided or unknown code writes nothing.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact frozen at approval"
)]
pub async fn approve(
    transaction: &Transaction<'_>,
    user_code: &str,
    user_id: &str,
    session_id: &str,
    auth_time: i64,
    acr: Option<&str>,
    org_id: Option<&str>,
    org_name: Option<&str>,
    now: DateTime<Utc>,
) -> StoreResult<bool> {
    let touched = transaction
        .execute(
            "UPDATE oidc_device_codes \
             SET state = 'approved', user_id = $2, session_id = $3, auth_time = $4, \
                 acr = $5, org_id = $6, org_name = $7, approved_at = $8 \
             WHERE user_code = $1 AND state = 'pending' AND expires_at > $8",
            &[
                &user_code,
                &user_id,
                &session_id,
                &auth_time,
                &acr,
                &org_id,
                &org_name,
                &now,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(touched > 0)
}

/// Take an approved row off the table and hand it back: the one redemption,
/// by construction.
pub async fn spend(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    device_code: &str,
) -> StoreResult<Option<DeviceCodeModel>> {
    let hash = digest_of(digest, device_code)?;
    let statement = format!(
        "DELETE FROM oidc_device_codes \
         WHERE device_digest = $1 AND state = 'approved' \
         RETURNING {COLUMNS}"
    );
    Ok(transaction
        .query_opt(statement.as_str(), &[&hash])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

pub async fn drop_expired(transaction: &Transaction<'_>, now: DateTime<Utc>) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM oidc_device_codes WHERE expires_at <= $1",
            &[&now],
        )
        .await
        .map_err(|_| StoreError::Backend)
}

fn read(row: Row) -> DeviceCodeModel {
    DeviceCodeModel {
        tenant: row.get("tenant"),
        realm_id: row.get("realm_id"),
        user_code: row.get("user_code"),
        client_id: row.get("client_id"),
        scope: row.get("scope"),
        state: row.get("state"),
        user_id: row.get("user_id"),
        session_id: row.get("session_id"),
        auth_time: row.get("auth_time"),
        acr: row.get("acr"),
        org_id: row.get("org_id"),
        org_name: row.get("org_name"),
        interval_secs: row.get("interval_secs"),
        last_polled_at: row.get("last_polled_at"),
        approved_at: row.get("approved_at"),
        expires_at: row.get("expires_at"),
        created_at: row.get("created_at"),
    }
}
