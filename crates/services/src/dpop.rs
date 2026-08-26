use chrono::{DateTime, Duration, Utc};
use crypto::jose::jwk::Jwk;
use crypto::jose::jwt;
use crypto::provider::{CryptoProvider, HashAlg, SignAlg};
use crypto::thumbprint::jwk_sha256_thumbprint;
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use serde_json::Value;
use store::providers::dpop;

use crate::token::verifier_for;

/// How far from now a proof's own instant may sit, RFC 9449 §11.1. Both ways:
/// a clock behind is as ordinary as a clock ahead, and a proof from the future
/// is not thereby an attack.
const WINDOW: i64 = 60;

/// The algorithms a proof may be signed at, for discovery to advertise.
///
/// Asymmetric only. A shared secret proves possession of something this server
/// holds too, which is not possession of anything the client alone has.
pub const SIGNING_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA",
];

/// Why a proof did not bind the request it came with.
///
/// One shape for nearly every one of them. What a caller learns is that the
/// proof was not accepted, never which of the checks it failed: told which, it
/// walks the list.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum Unproven {
    #[error("the proof does not bind this request")]
    Refused,
    /// Held apart because it is the one thing the caller can act on, by making
    /// a fresh proof rather than sending that one again.
    #[error("the proof was already spent")]
    Replayed,
    #[error("the store could not be read")]
    Unreadable,
}

/// What a proof binds, once it is proven.
#[derive(Debug, Clone)]
pub struct Proven {
    /// RFC 7638 thumbprint of the key the holder proved. This is what a token
    /// is bound to, and what a later request is measured against.
    pub thumbprint: String,
}

/// What the request being bound looks like.
#[derive(Debug, Clone, Copy)]
pub struct Bound<'a> {
    pub method: &'a str,
    /// The URL with no query and no fragment, RFC 9449 §4.2: a proof made for
    /// one query would otherwise not bind the same call made with another.
    pub url: &'a str,
    /// The access token this proof accompanies, where the request carries one.
    /// Absent at the token endpoint, where none has been handed out yet.
    pub access_token: Option<&'a str>,
}

/// Prove a DPoP proof against the request it arrived with, and spend it.
///
/// The spend is part of proving rather than a step after it: a proof checked
/// and not recorded is one the next caller may present again, which is the
/// replay this whole mechanism exists to stop.
pub async fn proven(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    proof: &str,
    bound: Bound<'_>,
    now: DateTime<Utc>,
) -> Result<Proven, Unproven> {
    let header = jwt::decode_header(proof).map_err(|_| Unproven::Refused)?;
    let named = |claim: &str| {
        header
            .claim(claim)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };

    // §4.2: this and nothing else, so a token of another kind cannot be handed
    // over as a proof.
    if named("typ").as_deref() != Some("dpop+jwt") {
        return Err(Unproven::Refused);
    }
    let algorithm = read_alg(named("alg").as_deref()).ok_or(Unproven::Refused)?;

    // §4.2: the key travels in the header and the proof is verified against
    // it. What makes that worth anything is the token naming its thumbprint:
    // a key alone proves possession of itself and nothing more.
    let key = header.claim("jwk").ok_or(Unproven::Refused)?;
    let jwk = Jwk::from_map(key.as_object().cloned().ok_or(Unproven::Refused)?)
        .map_err(|_| Unproven::Refused)?;
    // A private half here is a client publishing its own secret, and a server
    // that verified against it would accept whatever it was sent.
    if ["d", "p", "q", "dp", "dq", "qi", "k"]
        .iter()
        .any(|held| jwk.parameter(held).is_some())
    {
        return Err(Unproven::Refused);
    }

    let verifier = verifier_for(algorithm, &jwk).ok_or(Unproven::Refused)?;
    let payload = jwt::decode_with_verifier(proof, &*verifier)
        .map_err(|_| Unproven::Refused)?
        .0;
    let claim = |named: &str| payload.claim(named).and_then(Value::as_str);

    // §4.3: the method and the address this proof was made for, so one lifted
    // off a call does not bind another.
    if !claim("htm").is_some_and(|held| held.eq_ignore_ascii_case(bound.method))
        || claim("htu") != Some(bound.url)
    {
        return Err(Unproven::Refused);
    }

    let instant = payload
        .claim("iat")
        .and_then(Value::as_i64)
        .ok_or(Unproven::Refused)?;
    if (instant - now.timestamp()).abs() > WINDOW {
        return Err(Unproven::Refused);
    }

    // §4.3: on a request carrying an access token, the proof says which one.
    // Without it, a proof made for one token binds a request carrying another.
    if let Some(access) = bound.access_token {
        let hashed = digest(provider, access.as_bytes())?;
        if claim("ath") != Some(hashed.as_str()) {
            return Err(Unproven::Refused);
        }
    }

    // §11.1: accepted once. Recorded against the identifier its holder drew,
    // hashed, and kept only as long as `iat` would still be in its window.
    let jti = claim("jti").ok_or(Unproven::Refused)?;
    let spent = dpop::spend(
        transaction,
        &digest(provider, jti.as_bytes())?,
        now + Duration::seconds(WINDOW),
    )
    .await
    .map_err(|_| Unproven::Unreadable)?;
    if spent == dpop::Spent::Already {
        return Err(Unproven::Replayed);
    }

    // Taken after the signature is verified, never before: the thumbprint of a
    // key nobody proved holding is a key a token would be bound to for free.
    Ok(Proven {
        thumbprint: jwk_sha256_thumbprint(provider, &jwk).map_err(|_| Unproven::Refused)?,
    })
}

fn read_alg(named: Option<&str>) -> Option<SignAlg> {
    Some(match named? {
        "RS256" => SignAlg::Rs256,
        "RS384" => SignAlg::Rs384,
        "RS512" => SignAlg::Rs512,
        "PS256" => SignAlg::Ps256,
        "PS384" => SignAlg::Ps384,
        "PS512" => SignAlg::Ps512,
        "ES256" => SignAlg::Es256,
        "ES384" => SignAlg::Es384,
        "ES512" => SignAlg::Es512,
        "EdDSA" => SignAlg::EdDsa,
        _ => return None,
    })
}

fn digest(provider: &dyn CryptoProvider, over: &[u8]) -> Result<String, Unproven> {
    provider
        .digest()
        .hash(HashAlg::Sha256, over)
        .map(|held| BASE64URL_NOPAD.encode(&held))
        .map_err(|_| Unproven::Refused)
}
