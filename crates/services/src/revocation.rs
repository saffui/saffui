use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Transaction;
use models::entities::client::ClientModel;
use models::entities::keys::RealmSigningKeyView;
use serde_json::Value;
use store::providers::{oidc, sessions};

use crate::token;
use crate::token::issuance::Kind;

/// How long a withdrawal is kept when the token says nothing of its expiry.
const WITHDRAWN_FOR: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unrevokable {
    /// Issued to somebody else. §2.1: refused, and the client is told.
    #[error("the token was not issued to this client")]
    NotTheHolder,
    #[error("the store could not be written")]
    Unwritable,
}

/// Withdraw a token, and with it the client session it belongs to, which ends
/// every renewal descended from the same grant. Either kind of token, since
/// §2 asks that the other be invalidated too when possible, and here it is.
pub async fn revoke(
    transaction: &Transaction<'_>,
    keys: &[RealmSigningKeyView],
    caller: &ClientModel,
    token: &str,
    now: DateTime<Utc>,
) -> Result<(), Unrevokable> {
    // Signature only: an expired or already withdrawn token is revoked again
    // without complaint, and a client is told nothing about which it was.
    let Ok(payload) = token::verify_signature(keys, token) else {
        return Ok(());
    };
    let claim = |named: &str| {
        payload
            .claim(named)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    if claim("azp").as_deref() != Some(caller.client_id.as_str()) {
        return Err(Unrevokable::NotTheHolder);
    }
    let kind = claim("typ");
    if kind.as_deref() != Some(Kind::Access.claimed())
        && kind.as_deref() != Some(Kind::Refresh.claimed())
    {
        return Ok(());
    }

    if let Some(token_id) = payload.jwt_id() {
        let until = payload
            .expires_at()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(|| now + Duration::seconds(WITHDRAWN_FOR));
        oidc::revoke(transaction, token_id, until, "revoked by its client")
            .await
            .map_err(|_| Unrevokable::Unwritable)?;
    }
    if let Some(session) = claim("sid") {
        sessions::close_client_session_of(transaction, &session, &caller.client_id)
            .await
            .map_err(|_| Unrevokable::Unwritable)?;
    }
    Ok(())
}
