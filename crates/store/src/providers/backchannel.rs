use chrono::{DateTime, Utc};
use crypto::provider::{DigestProvider, HashAlg};
use deadpool_postgres::Transaction;
use models::entities::backchannel::{BackchannelRequestModel, BackchannelState};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

const COLUMNS: &str = "tenant, realm_id, client_id, user_id, scope, binding_message, state, \
                       interval_secs, last_polled_at, approved_at, expires_at, created_at";

fn digest_of(digest: &dyn DigestProvider, auth_req_id: &str) -> StoreResult<Vec<u8>> {
    digest
        .hash(HashAlg::Sha256, auth_req_id.as_bytes())
        .map_err(|_| StoreError::Backend)
}

pub async fn open(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    auth_req_id: &str,
    request: &BackchannelRequestModel,
) -> StoreResult<()> {
    let hash = digest_of(digest, auth_req_id)?;
    transaction
        .execute(
            "INSERT INTO backchannel_requests \
                 (tenant, realm_id, request_digest, client_id, user_id, scope, \
                  binding_message, state, interval_secs, expires_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8",
            &[
                &hash,
                &request.client_id,
                &request.user_id,
                &request.scope,
                &request.binding_message,
                &request.state,
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
    auth_req_id: &str,
) -> StoreResult<Option<BackchannelRequestModel>> {
    let hash = digest_of(digest, auth_req_id)?;
    let statement = format!("SELECT {COLUMNS} FROM backchannel_requests WHERE request_digest = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&hash])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// Stamp one poll and hand back the previous stamp, so the caller can tell a
/// too-eager client to slow down without a second read.
pub async fn touch_poll(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    auth_req_id: &str,
    now: DateTime<Utc>,
) -> StoreResult<Option<Option<DateTime<Utc>>>> {
    let hash = digest_of(digest, auth_req_id)?;
    Ok(transaction
        .query_opt(
            "UPDATE backchannel_requests SET last_polled_at = $2 \
             WHERE request_digest = $1 \
             RETURNING (SELECT last_polled_at FROM backchannel_requests \
                        WHERE request_digest = $1)",
            &[&hash, &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| row.get(0)))
}

/// The pending requests somebody may decide on, oldest first.
pub async fn pending_for(
    transaction: &Transaction<'_>,
    user_id: &str,
    now: DateTime<Utc>,
) -> StoreResult<Vec<(Vec<u8>, BackchannelRequestModel)>> {
    let statement = format!(
        "SELECT request_digest, {COLUMNS} FROM backchannel_requests \
         WHERE user_id = $1 AND state = 'pending' AND expires_at > $2 \
         ORDER BY created_at ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[&user_id, &now])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| (row.get("request_digest"), read(row)))
        .collect())
}

/// Decide one pending request, by its digest, for exactly this person: the
/// WHERE is the authorization, so a decision for somebody else's request
/// writes nothing.
pub async fn decide(
    transaction: &Transaction<'_>,
    request_digest: &[u8],
    user_id: &str,
    approved: bool,
    now: DateTime<Utc>,
) -> StoreResult<bool> {
    let state = if approved {
        BackchannelState::Approved
    } else {
        BackchannelState::Denied
    };
    let landed = transaction
        .execute(
            "UPDATE backchannel_requests \
             SET state = $3, approved_at = CASE WHEN $4 THEN $5 ELSE NULL END \
             WHERE request_digest = $1 AND user_id = $2 \
               AND state = 'pending' AND expires_at > $5",
            &[&request_digest, &user_id, &state, &approved, &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(landed > 0)
}

/// Take an approved request off the table and hand it back: the one
/// collection, by construction.
pub async fn spend(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    auth_req_id: &str,
) -> StoreResult<Option<BackchannelRequestModel>> {
    let hash = digest_of(digest, auth_req_id)?;
    let statement = format!(
        "DELETE FROM backchannel_requests \
         WHERE request_digest = $1 AND state = 'approved' \
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
            "DELETE FROM backchannel_requests WHERE expires_at <= $1",
            &[&now],
        )
        .await
        .map_err(|_| StoreError::Backend)
}

fn read(row: Row) -> BackchannelRequestModel {
    BackchannelRequestModel {
        tenant: row.get("tenant"),
        realm_id: row.get("realm_id"),
        client_id: row.get("client_id"),
        user_id: row.get("user_id"),
        scope: row.get("scope"),
        binding_message: row.get("binding_message"),
        state: row.get("state"),
        interval_secs: row.get("interval_secs"),
        last_polled_at: row.get("last_polled_at"),
        approved_at: row.get("approved_at"),
        expires_at: row.get("expires_at"),
        created_at: row.get("created_at"),
    }
}
