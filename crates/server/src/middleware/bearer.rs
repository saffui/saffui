//! Reading a bearer, and turning it into a caller.
//!
//! What both planes do before they differ. Two paths that each verify a token
//! and then establish who it is are two places for one to skip a step nobody
//! notices missing.

use actix_web::dev::ServiceRequest;
use chrono::Utc;
use data_encoding::BASE64URL_NOPAD;
use store::providers::realm_keys;
use store::tenancy::resolve;

use crate::error::unauthenticated;

pub(crate) fn bearer(request: &ServiceRequest) -> Option<String> {
    let header = request.headers().get("authorization")?.to_str().ok()?;
    header
        .strip_prefix("Bearer ")
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
}

/// The issuer, read without verifying anything.
///
/// Reading an unverified payload to find the key is unavoidable: something has
/// to say which realm's keys to fetch, and which realm that is, is written in
/// the token. Nothing else is taken from it, and nothing read here survives
/// into the decision: the payload is read again, from scratch, once the
/// signature has checked out.
///
/// The segment is decoded here rather than through the JOSE layer because that
/// layer has no way to read a payload without checking it. Decoding as an
/// unsecured token refuses anything whose header is not `alg: none`, which is
/// every real token; asking it for no verifier is an error rather than a
/// permission to skip the check. So this reads the one field it needs and
/// treats the rest as what it is, unproven text.
pub(crate) fn unverified_issuer(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded = BASE64URL_NOPAD.decode(payload.as_bytes()).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    claims.get("iss")?.as_str().map(str::to_owned)
}

/// Verify the bearer and establish who it is, and stop there.
pub(crate) async fn admitted(
    gate: &crate::middleware::caller::Caller,
    request: &ServiceRequest,
) -> Result<services::context::Established, commons::http::ApiError> {
    let now = Utc::now();
    let bearer = bearer(request).ok_or_else(unauthenticated)?;
    let issuer = unverified_issuer(&bearer).ok_or_else(unauthenticated)?;

    let mut connection = gate.pool.get().await.map_err(|_| unauthenticated())?;
    let context = resolve::realm_by_id(&connection, &issuer)
        .await
        .map_err(|_| unauthenticated())?;
    let transaction = gate
        .tenancy
        .transaction(&mut connection, &context)
        .await
        .map_err(|_| unauthenticated())?;

    let keys = realm_keys::published(&transaction, models::entities::keys::KeyUse::Sig)
        .await
        .map_err(|_| unauthenticated())?;

    services::context::admit_bearer(&transaction, context, &keys, &bearer, now)
        .await
        .map_err(|_| unauthenticated())
}
