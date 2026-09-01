use chrono::{DateTime, Utc};
use crypto::jose::jwk::{Jwk, JwkSet};
use crypto::jose::jwt;
use models::entities::client::ClientModel;
use serde_json::Value;

use crate::authorize::Requested;
use crate::token::verifier_for;

/// How far either side of now the object's own window may sit.
const SKEW: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unreadable {
    /// The client registered no algorithm, or no keys to verify against.
    #[error("this client did not register a request object")]
    Unregistered,
    #[error("the request object could not be read")]
    Malformed,
    #[error("the request object was signed by something else")]
    BadSignature,
    /// It states a window, and now is outside it.
    #[error("the request object is expired or not yet valid")]
    OutsideWindow,
    /// It names another issuer, another audience, or another client.
    #[error("the request object was not made for this")]
    Misbound,
}

impl Unreadable {
    /// What the client is told, from §6's own vocabulary.
    pub fn told(self) -> &'static str {
        match self {
            Unreadable::Unregistered => "request_not_supported",
            _ => "invalid_request_object",
        }
    }
}

/// What an object carried, owned so the merged request can borrow it.
pub struct Carried {
    map: serde_json::Map<String, Value>,
    /// `claims` is an object in here and a string in a query, so it is spelled
    /// back once rather than at every read.
    claims: Option<String>,
}

impl Carried {
    fn text(&self, named: &str) -> Option<&str> {
        self.map.get(named).and_then(Value::as_str)
    }

    /// The object over the query: what it signed wins, what it left out the
    /// query fills, and a parameter both state must agree (§6.1).
    pub fn over<'a>(&'a self, outer: &Requested<'a>) -> Result<Requested<'a>, Unreadable> {
        for named in ["response_type", "client_id"] {
            let stated = self.text(named);
            let asked = match named {
                "response_type" => outer.response_type,
                _ => outer.client_id,
            };
            if let (Some(stated), Some(asked)) = (stated, asked)
                && stated != asked
            {
                return Err(Unreadable::Misbound);
            }
        }
        Ok(Requested {
            response_type: self.text("response_type").or(outer.response_type),
            client_id: self.text("client_id").or(outer.client_id),
            redirect_uri: self.text("redirect_uri").or(outer.redirect_uri),
            scope: self.text("scope").or(outer.scope),
            state: self.text("state").or(outer.state),
            nonce: self.text("nonce").or(outer.nonce),
            code_challenge: self.text("code_challenge").or(outer.code_challenge),
            code_challenge_method: self
                .text("code_challenge_method")
                .or(outer.code_challenge_method),
            dpop_jkt: self.text("dpop_jkt").or(outer.dpop_jkt),
            // Neither travels inside an object: one is what carried it.
            request: None,
            request_uri: None,
            response_mode: self.text("response_mode").or(outer.response_mode),
            prompt: self.text("prompt").or(outer.prompt),
            max_age: self
                .map
                .get("max_age")
                .and_then(Value::as_i64)
                .or(outer.max_age),
            acr_values: self.text("acr_values").or(outer.acr_values),
            claims: self.claims.as_deref().or(outer.claims),
            organization: self.text("organization").or(outer.organization),
        })
    }
}

/// The parameters a signed request object carries, ready to merge.
pub fn read(
    client: &ClientModel,
    token: &str,
    issuer: &str,
    now: DateTime<Utc>,
) -> Result<Carried, Unreadable> {
    let algorithm = client
        .request_object_signing_alg
        .ok_or(Unreadable::Unregistered)?;
    let keys = client.jwks.as_ref().ok_or(Unreadable::Unregistered)?;
    let jwk = key_named(keys, token, algorithm)?;
    let verifier = verifier_for(algorithm, &jwk).ok_or(Unreadable::Unregistered)?;
    let payload = jwt::decode_with_verifier(token, &*verifier)
        .map_err(|_| Unreadable::BadSignature)?
        .0;

    let claim = |named: &str| payload.claim(named).and_then(Value::as_str);
    // §6.1: the object is made for this client, at this issuer. Enforced where
    // stated rather than required, since §6 leaves them optional and a client
    // that omits one has not thereby made an object for somebody else.
    if let Some(named) = claim("iss")
        && named != client.client_id
    {
        return Err(Unreadable::Misbound);
    }
    if let Some(named) = claim("aud")
        && named != issuer
    {
        return Err(Unreadable::Misbound);
    }
    if let Some(named) = claim("client_id")
        && named != client.client_id
    {
        return Err(Unreadable::Misbound);
    }
    let second = |named: &str| payload.claim(named).and_then(Value::as_i64);
    let instant = now.timestamp();
    if second("exp").is_some_and(|exp| instant > exp + SKEW)
        || second("nbf").is_some_and(|nbf| instant + SKEW < nbf)
    {
        return Err(Unreadable::OutsideWindow);
    }

    let map = payload.claims_set().clone();
    // §6.1 again: an object carrying another one is a chain nothing bounds.
    if map.contains_key("request") || map.contains_key("request_uri") {
        return Err(Unreadable::Malformed);
    }
    let claims = match map.get("claims") {
        None => None,
        Some(Value::String(spelled)) => Some(spelled.clone()),
        Some(other) => Some(serde_json::to_string(other).map_err(|_| Unreadable::Malformed)?),
    };
    Ok(Carried { map, claims })
}

/// The client's key the object's header names, or its only one of that
/// algorithm when the header names none.
pub(crate) fn key_named(
    keys: &Value,
    token: &str,
    algorithm: SignAlgOf,
) -> Result<Jwk, Unreadable> {
    let set = JwkSet::from_map(keys.as_object().cloned().ok_or(Unreadable::Unregistered)?)
        .map_err(|_| Unreadable::Unregistered)?;
    let header = jwt::decode_header(token).map_err(|_| Unreadable::Malformed)?;
    let named = header.claim("kid").and_then(Value::as_str);
    let wanted = algorithm.name();
    let mut usable = set.keys().into_iter().filter(|key| {
        key.algorithm().is_none_or(|stated| stated == wanted)
            && key.key_use().is_none_or(|held| held == "sig")
    });
    let found = match named {
        Some(kid) => usable.find(|key| key.key_id() == Some(kid)),
        None => usable.next(),
    };
    found.cloned().ok_or(Unreadable::BadSignature)
}

type SignAlgOf = crypto::provider::SignAlg;
