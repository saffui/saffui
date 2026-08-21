//! What `/authorize` mints, what `/token` spends, and what a realm refuses.

use deadpool_postgres::Transaction;
use models::entities::oidc::AuthorizationCode;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

/// Mint a code.
///
/// The caller hashes it and keeps the raw value for the client. Nothing here
/// ever sees the value that would be redeemed.
pub async fn mint_code(
    transaction: &Transaction<'_>,
    code: &AuthorizationCode,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO oidc_auth_codes \
                 (tenant, realm_id, code_hash, client_id, user_id, session_id, redirect_uri, \
                  scope, nonce, code_challenge, code_challenge_method, auth_time, acr, org_id, \
                  expires_at, claims) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14",
            &[
                &code.code_hash,
                &code.client_id,
                &code.user_id,
                &code.session_id,
                &code.redirect_uri,
                &code.scope,
                &code.nonce,
                &code.code_challenge,
                &code.code_challenge_method,
                &code.auth_time,
                &code.acr,
                &code.org_id,
                &expires_at,
                &code.claims,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Spend a code, once.
///
/// The row is removed and returned in one statement, so a code is spent by the
/// attempt rather than by the attempt succeeding. Two redemptions racing means
/// one of them finds nothing, which is the whole point: whatever happens after
/// this must not hand the code back.
///
/// An expired code is not returned, and is removed all the same. Leaving it
/// would let a caller that ignores the answer try again.
/// What presenting a code found.
#[derive(Debug)]
pub enum Redemption {
    /// Unspent until now. Spent by this call.
    Fresh(Box<AuthorizationCode>),
    /// Spent before, by whoever holds what it bought.
    Reused { issued_token_ids: Vec<String> },
    /// Never minted, or gone.
    Unknown,
}

/// Spend a code, or learn that it was spent.
///
/// Spent is a mark, not a deletion: a second presentation has to be told
/// apart from a code that never was, because the first wants the tokens it
/// bought revoked and the second has nothing to revoke.
pub async fn redeem_code(
    transaction: &Transaction<'_>,
    code_hash: &str,
) -> StoreResult<Redemption> {
    let fresh = transaction
        .query_opt(
            "UPDATE oidc_auth_codes SET redeemed_at = now() \
             WHERE code_hash = $1 AND redeemed_at IS NULL AND expires_at > now() \
             RETURNING tenant, realm_id, code_hash, client_id, user_id, session_id, \
                       redirect_uri, scope, nonce, code_challenge, code_challenge_method, \
                       auth_time, acr, org_id, expires_at, claims",
            &[&code_hash],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    if let Some(row) = fresh {
        return Ok(Redemption::Fresh(Box::new(read_code(row))));
    }
    Ok(transaction
        .query_opt(
            "SELECT issued_token_ids FROM oidc_auth_codes \
             WHERE code_hash = $1 AND redeemed_at IS NOT NULL",
            &[&code_hash],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map_or(Redemption::Unknown, |row| Redemption::Reused {
            issued_token_ids: row.get("issued_token_ids"),
        }))
}

/// What a redemption bought, so a later presentation can take it back.
pub async fn record_issued(
    transaction: &Transaction<'_>,
    code_hash: &str,
    token_ids: &[String],
) -> StoreResult<()> {
    transaction
        .execute(
            "UPDATE oidc_auth_codes SET issued_token_ids = $2 WHERE code_hash = $1",
            &[&code_hash, &token_ids],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// How long a spent code is remembered past its expiry, so a late replay can
/// still be answered with a revocation. The refresh token's default lifespan:
/// after that, what the code bought has expired on its own.
const SPENT_CODE_MEMORY: &str = "30 minutes";

/// Drop what nobody can spend any more: unspent codes past their expiry, and
/// spent ones once there is nothing left to revoke.
pub async fn drop_expired_codes(transaction: &Transaction<'_>) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM oidc_auth_codes \
             WHERE (redeemed_at IS NULL AND expires_at <= now()) \
                OR redeemed_at <= now() - ($1::text)::interval",
            &[&SPENT_CODE_MEMORY],
        )
        .await
        .map_err(|_| StoreError::Backend)
}

/// Refuse a token from now on.
///
/// Recording the same one twice is not an error: a revocation is a statement
/// about a token, and repeating it says the same thing.
pub async fn revoke(
    transaction: &Transaction<'_>,
    token_id: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
    reason: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO revoked_tokens (tenant, realm_id, token_id, expires_at, reason) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3 \
             ON CONFLICT DO NOTHING",
            &[&token_id, &expires_at, &reason],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Whether a presented token is refused.
///
/// A row past its own expiry answers no, because the token it names is refused
/// by its expiry already and a sweep that has not run yet must not change the
/// answer.
pub async fn is_revoked(transaction: &Transaction<'_>, token_id: &str) -> StoreResult<bool> {
    Ok(transaction
        .query_opt(
            "SELECT 1 FROM revoked_tokens WHERE token_id = $1 AND expires_at > now()",
            &[&token_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .is_some())
}

/// Forget the tokens that expired on their own.
pub async fn drop_expired_revocations(transaction: &Transaction<'_>) -> StoreResult<u64> {
    transaction
        .execute("DELETE FROM revoked_tokens WHERE expires_at <= now()", &[])
        .await
        .map_err(|_| StoreError::Backend)
}

/// Claim an assertion identifier for a client, or refuse it as already used.
///
/// The insertion is the check. Asking first and inserting after is two
/// statements, and two presentations of one assertion at the same moment both
/// find nothing and both proceed.
pub async fn claim_assertion(
    transaction: &Transaction<'_>,
    client_id: &str,
    jti_hash: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> StoreResult<bool> {
    let claimed = transaction
        .execute(
            "INSERT INTO client_assertion_jtis \
                 (tenant, realm_id, client_id, jti_hash, expires_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3 \
             ON CONFLICT DO NOTHING",
            &[&client_id, &jti_hash, &expires_at],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(claimed > 0)
}

/// Forget assertions whose own expiry now refuses them.
pub async fn drop_expired_assertions(transaction: &Transaction<'_>) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM client_assertion_jtis WHERE expires_at <= now()",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)
}

fn read_code(row: Row) -> AuthorizationCode {
    AuthorizationCode {
        code_hash: row.get("code_hash"),
        tenant: row.get("tenant"),
        realm_id: row.get("realm_id"),
        client_id: row.get("client_id"),
        user_id: row.get("user_id"),
        session_id: row.get("session_id"),
        redirect_uri: row.get("redirect_uri"),
        scope: row.get("scope"),
        nonce: row.get("nonce"),
        code_challenge: row.get("code_challenge"),
        code_challenge_method: row.get("code_challenge_method"),
        auth_time: row.get("auth_time"),
        acr: row.get("acr"),
        org_id: row.get("org_id"),
        org_name: None,
        claims: row.get("claims"),
    }
}
