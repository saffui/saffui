use chrono::{DateTime, Utc};
use serde_json::Value;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult, refuse_broken_rule};
use crate::tenancy::UnitOfWork;

/// A presentation request as the realm keeps it.
pub struct KeptRequest<'a> {
    pub request_id: &'a str,
    pub nonce: &'a str,
    pub response_kid: &'a str,
    /// The private half of the key the answer is encrypted to, sealed.
    pub response_key: &'a [u8],
    pub query: &'a Value,
    pub request_object: &'a str,
    /// The identifier the realm presented itself under in the request.
    pub client_id: &'a str,
    pub expires_at: DateTime<Utc>,
    pub created_by: &'a str,
    /// The login it was asked for, when a login asked rather than an
    /// administrator.
    pub for_login: Option<ForLogin<'a>>,
}

/// A request asked for a login: what it is for, the login, and the person that
/// login names. A sign-in names nobody until its answer does.
#[derive(Debug, Clone, Copy)]
pub struct ForLogin<'a> {
    pub purpose: &'a str,
    pub login_session: &'a str,
    pub user_id: Option<&'a str>,
}

pub async fn keep(transaction: &UnitOfWork, request: &KeptRequest<'_>) -> StoreResult<()> {
    let for_login = request.for_login;
    transaction
        .execute(
            "INSERT INTO presentation_requests \
                 (tenant, realm_id, request_id, nonce, response_kid, response_key, query, \
                  request_object, client_id, expires_at, created_by, purpose, login_session, \
                  user_id) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12",
            &[
                &request.request_id,
                &request.nonce,
                &request.response_kid,
                &request.response_key,
                request.query,
                &request.request_object,
                &request.client_id,
                &request.expires_at,
                &request.created_by,
                &for_login.map(|bound| bound.purpose),
                &for_login.map(|bound| bound.login_session),
                &for_login.and_then(|bound| bound.user_id),
            ],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(())
}

/// The signed request, while it waits for an answer and has not run out.
pub async fn pending_request_object(
    transaction: &UnitOfWork,
    request_id: &str,
    now: &DateTime<Utc>,
) -> StoreResult<Option<String>> {
    Ok(transaction
        .query_opt(
            "SELECT request_object FROM presentation_requests \
             WHERE request_id = $1 AND status = 'pending' AND expires_at > $2",
            &[&request_id, now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| row.get(0)))
}

/// A pending request, held for the one answer that settles it.
pub struct Answering {
    pub request_id: String,
    pub nonce: String,
    pub response_key: Vec<u8>,
    pub query: Value,
    /// What a login asked it for, when a login did.
    pub purpose: Option<String>,
    /// The identifier the request was asked under; absent on requests asked
    /// before it was kept, which were all asked under the realm's did:web.
    pub client_id: Option<String>,
}

/// Hold the pending request whose answer is encrypted to this key.
///
/// Locked until the transaction ends, so two answers to one request queue up
/// and the second finds it settled.
pub async fn claim_by_response_kid(
    transaction: &UnitOfWork,
    response_kid: &str,
    now: &DateTime<Utc>,
) -> StoreResult<Option<Answering>> {
    Ok(transaction
        .query_opt(
            "SELECT request_id, nonce, response_key, query, purpose, client_id \
             FROM presentation_requests \
             WHERE response_kid = $1 AND status = 'pending' AND expires_at > $2 \
             FOR UPDATE",
            &[&response_kid, now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_answering))
}

/// Hold the pending request a wallet names by its state, which is how a
/// refusal, sent in the clear, points at the request it refuses.
pub async fn claim_by_request_id(
    transaction: &UnitOfWork,
    request_id: &str,
    now: &DateTime<Utc>,
) -> StoreResult<Option<Answering>> {
    Ok(transaction
        .query_opt(
            "SELECT request_id, nonce, response_key, query, purpose, client_id \
             FROM presentation_requests \
             WHERE request_id = $1 AND status = 'pending' AND expires_at > $2 \
             FOR UPDATE",
            &[&request_id, now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_answering))
}

/// Settle a request, and say whether it was still pending. A sign-in's keeps
/// the digest of the code its browser redeems it with.
pub async fn settle(
    transaction: &UnitOfWork,
    request_id: &str,
    status: &str,
    outcome: &Value,
    response_code_digest: Option<&str>,
    at: &DateTime<Utc>,
) -> StoreResult<bool> {
    let settled = transaction
        .execute(
            "UPDATE presentation_requests \
             SET status = $2, outcome = $3, answered_at = $4, response_code_digest = $5 \
             WHERE request_id = $1 AND status = 'pending'",
            &[&request_id, &status, outcome, at, &response_code_digest],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(settled > 0)
}

/// Where a request stands, for whoever asked for it.
#[derive(Debug, Clone, PartialEq)]
pub struct Standing {
    pub request_id: String,
    pub status: String,
    pub outcome: Option<Value>,
    pub expires_at: DateTime<Utc>,
    pub answered_at: Option<DateTime<Utc>>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    /// When the browser that asked brought back the code its answer was
    /// handed: a sign-in's alone.
    pub redeemed_at: Option<DateTime<Utc>>,
}

/// Where a request an administrator asked for stands. One a login asked for
/// is that login's alone to read.
pub async fn standing(transaction: &UnitOfWork, request_id: &str) -> StoreResult<Option<Standing>> {
    Ok(transaction
        .query_opt(
            "SELECT request_id, status, outcome, expires_at, answered_at, created_by, created_at, \
                    redeemed_at \
             FROM presentation_requests WHERE request_id = $1 AND purpose IS NULL",
            &[&request_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_standing))
}

/// Where a request a login asked for stands, read by that login alone.
pub async fn standing_for_login(
    transaction: &UnitOfWork,
    request_id: &str,
    login_session: &str,
) -> StoreResult<Option<Standing>> {
    Ok(transaction
        .query_opt(
            "SELECT request_id, status, outcome, expires_at, answered_at, created_by, created_at, \
                    redeemed_at \
             FROM presentation_requests WHERE request_id = $1 AND login_session = $2",
            &[&request_id, &login_session],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_standing))
}

/// Spend the code a sign-in's answer was handed, brought back by the login that
/// asked, while its request has not run out. Once: a second presentation of
/// the same code finds it spent, and a code another login asked for is not
/// this one's to spend.
pub async fn redeem(
    transaction: &UnitOfWork,
    request_id: &str,
    login_session: &str,
    response_code_digest: &str,
    now: &DateTime<Utc>,
) -> StoreResult<Option<Standing>> {
    Ok(transaction
        .query_opt(
            "UPDATE presentation_requests SET redeemed_at = $4 \
             WHERE request_id = $1 AND login_session = $2 AND response_code_digest = $3 \
               AND redeemed_at IS NULL AND expires_at > $4 \
             RETURNING request_id, status, outcome, expires_at, answered_at, created_by, \
                       created_at, redeemed_at",
            &[&request_id, &login_session, &response_code_digest, now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_standing))
}

/// Take away the requests whose window closed before `before`, answered or not.
pub async fn drop_expired(transaction: &UnitOfWork, before: DateTime<Utc>) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM presentation_requests WHERE expires_at < $1",
            &[&before],
        )
        .await
        .map_err(|_| StoreError::Backend)
}

fn read_standing(row: Row) -> Standing {
    Standing {
        request_id: row.get("request_id"),
        status: row.get("status"),
        outcome: row.get("outcome"),
        expires_at: row.get("expires_at"),
        answered_at: row.get("answered_at"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
        redeemed_at: row.get("redeemed_at"),
    }
}

fn read_answering(row: Row) -> Answering {
    Answering {
        request_id: row.get("request_id"),
        nonce: row.get("nonce"),
        response_key: row.get("response_key"),
        query: row.get("query"),
        purpose: row.get("purpose"),
        client_id: row.get("client_id"),
    }
}
