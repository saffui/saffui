//! Selective disclosure for JSON Web Tokens, RFC 9901.
//!
//! The issuer signs digests where the claims a holder may withhold would
//! stand, and hands the holder each of those claims salted apart, as a
//! disclosure. A presentation carries the signed token, the disclosures the
//! holder chose, and, when the verifier asks for it, a key binding token signed
//! by the key the issuer named, over a digest of exactly what was presented.
//!
//! Only the compact serialization is read and written. The JSON one is optional
//! in the RFC and nothing this build talks to sends it.

mod conceal;
mod present;
mod verify;

#[cfg(test)]
mod tests;

pub use conceal::{Concealed, Concealment, Unconcealable, conceal_claims};
pub use present::{bind_presentation, select_disclosures};
pub use verify::{KeyBinding, Verified, VerifyingPolicy, read_issuer_header, verify_presentation};

use data_encoding::BASE64URL_NOPAD;

use crate::jose::{Map, Value};
use crate::provider::{CryptoProvider, HashAlg};

/// Why a presentation, or a part of one, was not accepted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("not an SD-JWT: a signed token, then disclosures, each followed by a tilde")]
    NotAnSdJwt,
    #[error("the issuer's signature does not verify under the key it was checked against")]
    IssuerSignature,
    #[error("the issuer's token is not of the type this verifier expects")]
    WrongType,
    #[error("the issuer's payload is not a JSON object")]
    UnreadablePayload,
    #[error("the digests are made with a hash this build does not accept: {0}")]
    UnknownHash(String),
    #[error("_sd_alg may only name the hash at the top of the payload")]
    MisplacedHashAlgorithm,
    #[error("a disclosure is not a salted claim or a salted array element")]
    MalformedDisclosure,
    #[error("a digest is carried where the RFC allows none, or in a shape it does not")]
    MalformedDigestCarrier,
    #[error("a disclosure names a claim no disclosure may name: {0}")]
    ForbiddenClaimName(String),
    #[error("a disclosed claim would overwrite one already present: {0}")]
    ClaimCollision(String),
    #[error("the same digest appears twice in the payload")]
    RepeatedDigest,
    #[error("the same disclosure was presented twice")]
    RepeatedDisclosure,
    #[error("a disclosure answers no digest the issuer signed")]
    UnreferencedDisclosure,
    #[error("a claim the verifier requires is missing: {0}")]
    MissingClaim(String),
    #[error("the issuer's token has expired")]
    Expired,
    #[error("the issuer's token is not valid yet")]
    NotYetValid,
    #[error("key binding is required and the presentation carries none")]
    KeyBindingMissing,
    #[error("the presentation carries key binding the verifier did not ask for")]
    KeyBindingUnexpected,
    #[error("key binding is required and the issuer named no holder key this build can use")]
    NoHolderKey,
    #[error("the key binding token is not signed by the holder key")]
    KeyBindingSignature,
    #[error("the key binding token is not typed kb+jwt")]
    KeyBindingType,
    #[error("the key binding token lacks a claim it must carry, or carries one in the wrong shape")]
    KeyBindingUnreadable,
    #[error("the key binding token was made outside the accepted window")]
    KeyBindingStale,
    #[error("the key binding token is meant for another verifier")]
    KeyBindingAudience,
    #[error("the key binding token answers another request")]
    KeyBindingNonce,
    #[error("the key binding token covers other disclosures than the ones presented")]
    KeyBindingHash,
    #[error("a digest could not be computed")]
    Unhashable,
    #[error("the key binding token could not be signed")]
    Unsigned,
}

/// One claim as the issuer salted it.
#[derive(Clone, Debug, PartialEq)]
pub struct Disclosure {
    /// The base64url string exactly as it travels; its digest covers these bytes.
    pub encoded: String,
    pub salt: String,
    /// Absent for an array element, which is disclosed by value alone.
    pub name: Option<String>,
    pub value: Value,
}

impl Disclosure {
    /// Read a disclosure: three members for a property, two for an array
    /// element, a string salt first and a string name second (RFC 9901 §4.2).
    pub fn read(encoded: &str) -> Result<Self, Refused> {
        let bytes = BASE64URL_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|_| Refused::MalformedDisclosure)?;
        let Ok(Value::Array(members)) = serde_json::from_slice::<Value>(&bytes) else {
            return Err(Refused::MalformedDisclosure);
        };
        let (salt, name, value) = match <[Value; 3]>::try_from(members) {
            Ok([Value::String(salt), Value::String(name), value]) => (salt, Some(name), value),
            Ok(_) => return Err(Refused::MalformedDisclosure),
            Err(members) => match <[Value; 2]>::try_from(members) {
                Ok([Value::String(salt), value]) => (salt, None, value),
                _ => return Err(Refused::MalformedDisclosure),
            },
        };
        Ok(Self {
            encoded: encoded.to_owned(),
            salt,
            name,
            value,
        })
    }
}

/// The digest of a disclosure or of a presentation: the hash of the string as
/// it travels, base64url without padding (RFC 9901 §4.2.3 and §4.3.1).
pub fn digest_of(
    provider: &dyn CryptoProvider,
    hash: HashAlg,
    encoded: &str,
) -> Result<String, Refused> {
    let digest = provider
        .digest()
        .hash(hash, encoded.as_bytes())
        .map_err(|_| Refused::Unhashable)?;
    Ok(BASE64URL_NOPAD.encode(&digest))
}

/// The hash `_sd_alg` names. The RFC's default when it names none; and only
/// the SHA-2 family, which is what the digests' hiding property rests on.
fn hash_named(named: Option<&Value>) -> Result<HashAlg, Refused> {
    let Some(named) = named else {
        return Ok(HashAlg::Sha256);
    };
    let Value::String(name) = named else {
        return Err(Refused::UnknownHash(named.to_string()));
    };
    [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512]
        .into_iter()
        .find(|hash| crate::thumbprint::hash_name(*hash) == Some(name.as_str()))
        .ok_or_else(|| Refused::UnknownHash(name.clone()))
}

/// A presentation cut at its tildes.
struct Parts<'a> {
    issuer_token: &'a str,
    disclosures: Vec<&'a str>,
    key_binding: Option<&'a str>,
    /// Everything up to and including the last tilde: what `sd_hash` covers.
    hashed: &'a str,
}

fn split_presentation(presented: &str) -> Result<Parts<'_>, Refused> {
    let last = presented.rfind('~').ok_or(Refused::NotAnSdJwt)?;
    let (hashed, tail) = presented.split_at(last + 1);
    let mut components = presented[..last].split('~');
    let issuer_token = components
        .next()
        .filter(|token| !token.is_empty())
        .ok_or(Refused::NotAnSdJwt)?;
    let disclosures: Vec<&str> = components.collect();
    if disclosures.iter().any(|disclosure| disclosure.is_empty()) {
        return Err(Refused::NotAnSdJwt);
    }
    Ok(Parts {
        issuer_token,
        disclosures,
        key_binding: (!tail.is_empty()).then_some(tail),
        hashed,
    })
}

/// The payload of a compact JWS, read without its signature being checked.
fn unverified_payload(token: &str) -> Result<Map<String, Value>, Refused> {
    let payload = token.split('.').nth(1).ok_or(Refused::NotAnSdJwt)?;
    let bytes = BASE64URL_NOPAD
        .decode(payload.as_bytes())
        .map_err(|_| Refused::UnreadablePayload)?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(claims)) => Ok(claims),
        _ => Err(Refused::UnreadablePayload),
    }
}
