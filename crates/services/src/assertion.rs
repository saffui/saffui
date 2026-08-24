//! What a client signs to say it is itself: RFC 7523 §2.2 and OIDC Core §9.
//!
//! Two methods, one shape. `private_key_jwt` verifies against the keys the
//! client published; `client_secret_jwt` recomputes an HMAC over the secret
//! only this deployment and that client hold. The method decides which family
//! of algorithms is acceptable, so an assertion cannot be verified with a
//! published key as if it were a shared one.

use chrono::{DateTime, Utc};
use crypto::jose::jwk::{Jwk, JwkSet};
use crypto::jose::jws::{HS256, HS384, HS512, JwsVerifier};
use crypto::jose::jwt;
use crypto::provider::{CryptoProvider, HashAlg, SignAlg};
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use models::entities::client::ClientModel;
use secrecy::{ExposeSecret, SecretBox};
use serde_json::Value;
use store::providers::oidc;

use crate::token::verifier_for;

/// RFC 7521 §4.2: the only assertion type this endpoint reads.
pub const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// How far either side of now the assertion's own window may sit.
const SKEW: i64 = 60;

/// The longest window an assertion may claim. One that never expires is a
/// permanent credential, and the replay row for it would never be swept.
const LONGEST: i64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unverifiable {
    #[error("this client registered no way to verify an assertion")]
    Unregistered,
    #[error("the assertion could not be read")]
    Malformed,
    #[error("the assertion was signed by something else")]
    BadSignature,
    #[error("the assertion is expired, not yet valid, or claims too long a life")]
    OutsideWindow,
    #[error("the assertion was not made for this")]
    Misbound,
    #[error("this assertion has already been used")]
    Replayed,
    #[error("the store could not be read")]
    Unreadable,
}

/// Who an assertion says it is about, read before anything is verified.
///
/// Only ever used to find the client whose keys the signature is then checked
/// against, because §9 lets a request carry the assertion and no `client_id`.
pub fn subject_of(assertion: &str) -> Option<String> {
    let payload = assertion.split('.').nth(1)?;
    let bytes = BASE64URL_NOPAD.decode(payload.as_bytes()).ok()?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .get("sub")?
        .as_str()
        .map(str::to_owned)
}

/// Which HMAC algorithm, for a secret-signed assertion.
fn shared_verifier(algorithm: SignAlg, secret: &[u8]) -> Option<Box<dyn JwsVerifier>> {
    let named = match algorithm {
        SignAlg::Rs256 => HS256,
        SignAlg::Rs384 => HS384,
        SignAlg::Rs512 => HS512,
        _ => return None,
    };
    named
        .verifier_from_bytes(secret)
        .ok()
        .map(|verifier| Box::new(verifier) as Box<dyn JwsVerifier>)
}

/// The algorithm the header names, read as a member of the family this method
/// allows and refused as anything else.
fn algorithm_of(token: &str, shared: bool) -> Result<SignAlg, Unverifiable> {
    let header = jwt::decode_header(token).map_err(|_| Unverifiable::Malformed)?;
    let named = header
        .claim("alg")
        .and_then(Value::as_str)
        .ok_or(Unverifiable::Malformed)?;
    // The two families are read through one enum, so the name is mapped rather
    // than trusted: `HS256` never resolves to a key the client published, and
    // `RS256` never resolves to the shared secret.
    let wanted = match (shared, named) {
        (true, "HS256") | (false, "RS256") => SignAlg::Rs256,
        (true, "HS384") | (false, "RS384") => SignAlg::Rs384,
        (true, "HS512") | (false, "RS512") => SignAlg::Rs512,
        (false, "PS256") => SignAlg::Ps256,
        (false, "PS384") => SignAlg::Ps384,
        (false, "PS512") => SignAlg::Ps512,
        (false, "ES256") => SignAlg::Es256,
        (false, "ES384") => SignAlg::Es384,
        (false, "ES512") => SignAlg::Es512,
        (false, "EdDSA") => SignAlg::EdDsa,
        _ => return Err(Unverifiable::BadSignature),
    };
    Ok(wanted)
}

/// The client's key the header names, or its only one of that algorithm.
fn published_key(keys: &Value, token: &str, algorithm: SignAlg) -> Result<Jwk, Unverifiable> {
    let set = JwkSet::from_map(
        keys.as_object()
            .cloned()
            .ok_or(Unverifiable::Unregistered)?,
    )
    .map_err(|_| Unverifiable::Unregistered)?;
    let header = jwt::decode_header(token).map_err(|_| Unverifiable::Malformed)?;
    let named = header.claim("kid").and_then(Value::as_str);
    let wanted = algorithm.name();
    let mut usable = set.keys().into_iter().filter(|key| {
        key.algorithm().is_none_or(|stated| stated == wanted)
            && key.key_use().is_none_or(|held| held == "sig")
    });
    match named {
        Some(kid) => usable.find(|key| key.key_id() == Some(kid)),
        None => usable.next(),
    }
    .cloned()
    .ok_or(Unverifiable::BadSignature)
}

/// Verify an assertion, and spend it.
///
/// The spend is part of verifying, not a step after it: an assertion checked
/// and not recorded is one the next caller may present again.
pub async fn verify(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    client: &ClientModel,
    assertion: &str,
    audiences: &[String],
    secret: Option<&SecretBox<String>>,
    now: DateTime<Utc>,
) -> Result<(), Unverifiable> {
    let shared = secret.is_some();
    let algorithm = algorithm_of(assertion, shared)?;
    if let Some(registered) = client.token_endpoint_auth_signing_alg
        && registered != algorithm
    {
        return Err(Unverifiable::BadSignature);
    }

    let verifier = match secret {
        Some(secret) => shared_verifier(algorithm, secret.expose_secret().as_bytes())
            .ok_or(Unverifiable::BadSignature)?,
        None => {
            let keys = client.jwks.as_ref().ok_or(Unverifiable::Unregistered)?;
            let jwk = published_key(keys, assertion, algorithm)?;
            verifier_for(algorithm, &jwk).ok_or(Unverifiable::Unregistered)?
        }
    };
    let payload = jwt::decode_with_verifier(assertion, &*verifier)
        .map_err(|_| Unverifiable::BadSignature)?
        .0;

    let claim = |named: &str| payload.claim(named).and_then(Value::as_str);
    // §3: the client is both who made it and who it is about. Required, not
    // optional: an assertion that names nobody authenticates nobody.
    if claim("iss") != Some(client.client_id.as_str())
        || claim("sub") != Some(client.client_id.as_str())
    {
        return Err(Unverifiable::Misbound);
    }
    // §3 again: this server, by a name it answers to. An assertion made for
    // one provider is otherwise replayable at every other.
    let intended = match payload.claim("aud") {
        Some(Value::String(named)) => audiences.iter().any(|held| held == named),
        Some(Value::Array(named)) => named
            .iter()
            .filter_map(Value::as_str)
            .any(|named| audiences.iter().any(|held| held == named)),
        _ => false,
    };
    if !intended {
        return Err(Unverifiable::Misbound);
    }

    let second = |named: &str| payload.claim(named).and_then(Value::as_i64);
    let instant = now.timestamp();
    let expiry = second("exp").ok_or(Unverifiable::OutsideWindow)?;
    if instant > expiry + SKEW || expiry > instant + LONGEST + SKEW {
        return Err(Unverifiable::OutsideWindow);
    }
    if second("nbf").is_some_and(|nbf| instant + SKEW < nbf) {
        return Err(Unverifiable::OutsideWindow);
    }

    let jti = claim("jti").ok_or(Unverifiable::Malformed)?;
    let expires_at = DateTime::from_timestamp(expiry + SKEW, 0).ok_or(Unverifiable::Malformed)?;
    // Hashed rather than kept: an identifier a client chose is a value it
    // controls, and the row only has to answer whether one was seen.
    let digest = provider
        .digest()
        .hash(HashAlg::Sha256, jti.as_bytes())
        .map(|hashed| BASE64URL_NOPAD.encode(&hashed))
        .map_err(|_| Unverifiable::Unreadable)?;
    let fresh = oidc::claim_assertion(transaction, &client.client_id, &digest, expires_at)
        .await
        .map_err(|_| Unverifiable::Unreadable)?;
    fresh.then_some(()).ok_or(Unverifiable::Replayed)
}
