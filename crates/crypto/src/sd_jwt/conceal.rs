use std::cmp::Reverse;

use data_encoding::BASE64URL_NOPAD;
use serde_json::json;

use super::digest_of;
use crate::jose::{Map, Value};
use crate::provider::{CryptoProvider, HashAlg};

/// Claims RFC 9901 §9.7 names as deciding whether the token is valid at all.
/// A verifier must not be the one to find out they were withheld.
const VALIDITY_CLAIMS: [&str; 5] = ["iss", "aud", "exp", "nbf", "cnf"];

/// Names the RFC keeps for its own bookkeeping.
const RESERVED_NAMES: [&str; 3] = ["_sd", "...", "_sd_alg"];

/// How many random bytes a salt draws: the RFC's recommended 128 bits.
const SALT_BYTES: usize = 16;

/// A claim the holder may withhold, named by its path of object keys from the
/// top of the payload.
#[derive(Clone, Copy, Debug)]
pub enum Concealed<'a> {
    /// The property at the end of the path.
    Property(&'a [&'a str]),
    /// One element of the array at the end of the path.
    Element(&'a [&'a str], usize),
}

impl Concealed<'_> {
    /// How deep the concealed value sits. The deepest go first, so that a
    /// property whose own members are concealed carries their digests inside
    /// its disclosure (RFC 9901 §4.2.6).
    fn depth(&self) -> usize {
        match self {
            Self::Property(path) => path.len(),
            Self::Element(path, _) => path.len() + 1,
        }
    }
}

/// What the issuer signs, and what it hands the holder beside the signature.
#[derive(Debug)]
pub struct Concealment {
    pub payload: Map<String, Value>,
    pub disclosures: Vec<String>,
}

impl Concealment {
    /// The issued SD-JWT once the payload is signed: the token, then every
    /// disclosure, each followed by a tilde.
    pub fn issued(&self, signed_payload: &str) -> String {
        let mut issued = format!("{signed_payload}~");
        for disclosure in &self.disclosures {
            issued.push_str(disclosure);
            issued.push('~');
        }
        issued
    }
}

/// Why claims could not be concealed as asked.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Unconcealable {
    #[error("nothing stands at the path to conceal")]
    NotFound,
    #[error("the claim decides whether the token is valid and stays in plain sight: {0}")]
    ValidityClaim(String),
    #[error("the claims already use a name the RFC keeps for itself: {0}")]
    ReservedName(String),
    #[error("the element is already concealed")]
    AlreadyConcealed,
    #[error("the randomness or the hash could not be drawn")]
    Unavailable,
}

/// Conceal the named claims of `claims` and return the payload to sign with
/// the disclosures that open it (RFC 9901 §4.2).
///
/// Digests are SHA-256, and the payload says so in `_sd_alg`. Every object
/// that carries digests gets `decoys` more that open nothing, and has them
/// sorted, so neither their count nor their order says what was concealed.
pub fn conceal_claims(
    provider: &dyn CryptoProvider,
    claims: Map<String, Value>,
    concealed: &[Concealed<'_>],
    decoys: usize,
) -> Result<Concealment, Unconcealable> {
    let mut payload = Value::Object(claims);
    refuse_reserved_names(&payload)?;

    let mut deepest_first = concealed.to_vec();
    deepest_first.sort_by_key(|entry| Reverse(entry.depth()));
    let mut disclosures = Vec::with_capacity(concealed.len());
    for entry in deepest_first {
        match entry {
            Concealed::Property(path) => {
                let (name, parents) = path.split_last().ok_or(Unconcealable::NotFound)?;
                if parents.is_empty() && VALIDITY_CLAIMS.contains(name) {
                    return Err(Unconcealable::ValidityClaim((*name).to_owned()));
                }
                let Some(Value::Object(parent)) = value_at(&mut payload, parents) else {
                    return Err(Unconcealable::NotFound);
                };
                let mut value = parent.remove(*name).ok_or(Unconcealable::NotFound)?;
                seal_digests(provider, &mut value, decoys)?;
                let (encoded, digest) = disclose(provider, json!([salt(provider)?, name, value]))?;
                match parent
                    .entry("_sd")
                    .or_insert_with(|| Value::Array(Vec::new()))
                {
                    Value::Array(digests) => digests.push(Value::String(digest)),
                    _ => return Err(Unconcealable::ReservedName("_sd".to_owned())),
                }
                disclosures.push(encoded);
            }
            Concealed::Element(path, index) => {
                let Some(Value::Array(elements)) = value_at(&mut payload, path) else {
                    return Err(Unconcealable::NotFound);
                };
                let slot = elements.get_mut(index).ok_or(Unconcealable::NotFound)?;
                if slot
                    .as_object()
                    .is_some_and(|carrier| carrier.contains_key("..."))
                {
                    return Err(Unconcealable::AlreadyConcealed);
                }
                let mut value = slot.take();
                seal_digests(provider, &mut value, decoys)?;
                let (encoded, digest) = disclose(provider, json!([salt(provider)?, value]))?;
                *slot = json!({ "...": digest });
                disclosures.push(encoded);
            }
        }
    }

    seal_digests(provider, &mut payload, decoys)?;
    let Value::Object(mut payload) = payload else {
        return Err(Unconcealable::NotFound);
    };
    payload.insert("_sd_alg".to_owned(), Value::String("sha-256".to_owned()));
    Ok(Concealment {
        payload,
        disclosures,
    })
}

/// The value the path of object keys leads to.
fn value_at<'v>(value: &'v mut Value, path: &[&str]) -> Option<&'v mut Value> {
    path.iter()
        .try_fold(value, |value, name| value.as_object_mut()?.get_mut(*name))
}

/// Refuse claims that already carry the RFC's own names, anywhere: a digest
/// the issuer did not put there would open whatever a holder wrote.
fn refuse_reserved_names(value: &Value) -> Result<(), Unconcealable> {
    match value {
        Value::Object(object) => {
            if let Some(name) = RESERVED_NAMES
                .iter()
                .find(|name| object.contains_key(**name))
            {
                return Err(Unconcealable::ReservedName((*name).to_owned()));
            }
            object.values().try_for_each(refuse_reserved_names)
        }
        Value::Array(elements) => elements.iter().try_for_each(refuse_reserved_names),
        _ => Ok(()),
    }
}

/// Pad and sort every `_sd` array the value holds, before the value is either
/// signed or sealed into a parent's disclosure.
fn seal_digests(
    provider: &dyn CryptoProvider,
    value: &mut Value,
    decoys: usize,
) -> Result<(), Unconcealable> {
    match value {
        Value::Object(object) => {
            for member in object.values_mut() {
                seal_digests(provider, member, decoys)?;
            }
            if let Some(Value::Array(digests)) = object.get_mut("_sd") {
                for _ in 0..decoys {
                    let decoy = digest_of(provider, HashAlg::Sha256, &salt(provider)?)
                        .map_err(|_| Unconcealable::Unavailable)?;
                    digests.push(Value::String(decoy));
                }
                digests.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
            }
            Ok(())
        }
        Value::Array(elements) => elements
            .iter_mut()
            .try_for_each(|element| seal_digests(provider, element, decoys)),
        _ => Ok(()),
    }
}

/// A disclosure of `members` and the digest that stands for it.
fn disclose(
    provider: &dyn CryptoProvider,
    members: Value,
) -> Result<(String, String), Unconcealable> {
    let encoded = BASE64URL_NOPAD.encode(members.to_string().as_bytes());
    let digest =
        digest_of(provider, HashAlg::Sha256, &encoded).map_err(|_| Unconcealable::Unavailable)?;
    Ok((encoded, digest))
}

/// A fresh salt: 128 random bits, base64url.
fn salt(provider: &dyn CryptoProvider) -> Result<String, Unconcealable> {
    let mut drawn = [0u8; SALT_BYTES];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unconcealable::Unavailable)?;
    Ok(BASE64URL_NOPAD.encode(&drawn))
}
