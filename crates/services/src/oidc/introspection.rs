use chrono::{DateTime, Utc};
use models::entities::client::ClientModel;
use models::entities::keys::RealmSigningKeyView;
use serde_json::{Map, Value, json};
use store::providers::protocol::sessions;
use store::tenancy::UnitOfWork;

use crate::token;
use crate::token::issuance::Kind;

/// What the caller is told.
#[derive(Debug, PartialEq, Eq)]
pub enum Told {
    Active(Map<String, Value>),
    Inactive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Untellable {
    /// Introspection turns a stolen token into its claims, so it is never for a
    /// client that cannot keep a secret.
    #[error("a public client may not introspect")]
    PublicCaller,
    #[error("the store could not be read")]
    Unreadable,
}

/// Say whether a token is live, and what it says when it is.
///
/// Any confidential client of the realm may ask about any token the realm
/// issued: a resource server is rarely the client a token was minted for.
pub async fn introspect(
    transaction: &UnitOfWork,
    keys: &[RealmSigningKeyView],
    caller: &ClientModel,
    token: &str,
    now: DateTime<Utc>,
) -> Result<Told, Untellable> {
    if caller.public_client == Some(true) {
        return Err(Untellable::PublicCaller);
    }
    let Ok(verified) =
        token::verify_presented(transaction, keys, token, token::Binding::Reported, now).await
    else {
        return Ok(Told::Inactive);
    };
    let kind = verified.claims.get("typ").and_then(Value::as_str);
    let party = verified.claims.get("azp").and_then(Value::as_str);
    let session = verified.claims.get("sid").and_then(Value::as_str);

    // A refresh token that was rotated out is dead however unexpired: only the
    // one the client session anchors on is current.
    if kind == Some(Kind::Refresh.claimed()) {
        let (Some(party), Some(session), Some(token_id)) =
            (party, session, verified.token_id.as_deref())
        else {
            return Ok(Told::Inactive);
        };
        let current = sessions::refresh_is_current(transaction, session, party, token_id)
            .await
            .map_err(|_| Untellable::Unreadable)?;
        if !current {
            return Ok(Told::Inactive);
        }
    } else if kind != Some(Kind::Access.claimed()) {
        // An identity token is a record, not a credential.
        return Ok(Told::Inactive);
    }

    let mut told = Map::new();
    told.insert("active".into(), json!(true));
    if let Some(party) = party {
        told.insert("client_id".into(), json!(party));
    }
    // RFC 9449 §6.2: an access token bound to a key is a DPoP token, and a
    // resource server reading `Bearer` would take it as one anybody may show.
    if kind == Some(Kind::Access.claimed()) {
        let bound_to_a_key = verified
            .claims
            .get("cnf")
            .is_some_and(|held| held.get("jkt").is_some());
        let named = if bound_to_a_key { "DPoP" } else { "Bearer" };
        told.insert("token_type".into(), json!(named));
    }
    // The binding travels whole, RFC 9449 §6.2 and RFC 8705 §3.2: this door
    // verifies a token for whoever asks and cannot demand its proof, so the
    // resource server holding the proof is the one that has to compare.
    for named in [
        "scope", "sub", "aud", "iss", "exp", "iat", "nbf", "jti", "sid", "act", "cap", "cnf",
    ] {
        if let Some(value) = verified.claims.get(named) {
            told.insert(named.into(), value.clone());
        }
    }
    Ok(Told::Active(told))
}
