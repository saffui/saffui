use std::collections::{HashMap, HashSet};

use data_encoding::BASE64URL_NOPAD;

use super::{Disclosure, Parts, Refused, digest_of, hash_named, split_presentation};
use crate::jose::jwk::Jwk;
use crate::jose::jws::{self, ES256, ES384, ES512, EdDSA, JwsVerifier};
use crate::jose::{Map, Value};
use crate::provider::{CryptoProvider, HashAlg};

/// What the verifier settled before the presentation arrived.
///
/// Whether key binding is required is decided here and never read off the
/// presentation (RFC 9901 §9.5): a key binding token stripped by whoever
/// carried the credential must not relax the check.
pub struct VerifyingPolicy<'a> {
    /// The `typ` the issuer's token must carry, compared without regard to case.
    pub token_type: &'a str,
    /// Claims the processed payload must hold, whether plain or disclosed.
    pub required_claims: &'a [&'a str],
    pub key_binding: Option<KeyBinding<'a>>,
    /// Seconds since the epoch. An argument, so a replayed decision answers
    /// the same as the one it replays.
    pub now: i64,
    /// How far two clocks may disagree, in seconds, for every time claim.
    pub leeway: i64,
}

/// What a key binding token must answer.
pub struct KeyBinding<'a> {
    pub audience: &'a str,
    pub nonce: &'a str,
    /// How old a key binding token may be, from its `iat`, in seconds.
    pub max_age: i64,
}

/// A presentation that verified.
#[derive(Debug)]
pub struct Verified {
    /// The processed payload: disclosed claims in place, digests and `_sd_alg` gone.
    pub claims: Map<String, Value>,
    /// The holder key the issuer named in `cnf.jwk`, when it named one.
    pub holder_key: Option<Jwk>,
}

/// The protected header of the issuer's token, before anything is verified.
///
/// For finding the key to verify with (`x5c`, `kid`) and nothing else: every
/// member is whatever the presenter sent until the signature says otherwise.
pub fn read_issuer_header(presented: &str) -> Result<Map<String, Value>, Refused> {
    let parts = split_presentation(presented)?;
    let header = parts
        .issuer_token
        .split('.')
        .next()
        .ok_or(Refused::NotAnSdJwt)?;
    let bytes = BASE64URL_NOPAD
        .decode(header.as_bytes())
        .map_err(|_| Refused::NotAnSdJwt)?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(header)) => Ok(header),
        _ => Err(Refused::NotAnSdJwt),
    }
}

/// Verify a presentation against the issuer key the caller resolved, and
/// return its processed payload (RFC 9901 §7.1 and §7.3).
///
/// The issuer verifier carries the algorithm the key dictates; a header naming
/// another one, `none` included, is refused before any claim is read.
pub fn verify_presentation(
    provider: &dyn CryptoProvider,
    presented: &str,
    issuer: &dyn JwsVerifier,
    policy: &VerifyingPolicy<'_>,
) -> Result<Verified, Refused> {
    let parts = split_presentation(presented)?;
    match (&policy.key_binding, parts.key_binding) {
        (Some(_), None) => return Err(Refused::KeyBindingMissing),
        (None, Some(_)) => return Err(Refused::KeyBindingUnexpected),
        _ => {}
    }

    let (payload, header) = jws::deserialize_compact(parts.issuer_token, issuer)
        .map_err(|_| Refused::IssuerSignature)?;
    if !header
        .token_type()
        .is_some_and(|typ| typ.eq_ignore_ascii_case(policy.token_type))
    {
        return Err(Refused::WrongType);
    }
    let Ok(Value::Object(mut payload)) = serde_json::from_slice::<Value>(&payload) else {
        return Err(Refused::UnreadablePayload);
    };

    let hash = hash_named(payload.remove("_sd_alg").as_ref())?;
    let mut unfolding = Unfolding::of(provider, hash, &parts.disclosures)?;
    let claims = unfolding.unfold_object(payload)?;
    if unfolding.used.len() != unfolding.by_digest.len() {
        return Err(Refused::UnreferencedDisclosure);
    }

    check_validity(&claims, policy)?;
    let holder_key = holder_key_of(&claims);
    if let (Some(binding), Some(token)) = (&policy.key_binding, parts.key_binding) {
        let holder = holder_key.as_ref().ok_or(Refused::NoHolderKey)?;
        check_key_binding(provider, hash, &parts, token, holder, binding, policy)?;
    }
    Ok(Verified { claims, holder_key })
}

/// The disclosures of one presentation, put back where their digests stand.
struct Unfolding {
    by_digest: HashMap<String, Disclosure>,
    used: HashSet<String>,
    seen: HashSet<String>,
}

impl Unfolding {
    fn of(
        provider: &dyn CryptoProvider,
        hash: HashAlg,
        disclosures: &[&str],
    ) -> Result<Self, Refused> {
        let mut by_digest = HashMap::with_capacity(disclosures.len());
        for encoded in disclosures {
            let disclosure = Disclosure::read(encoded)?;
            if by_digest
                .insert(digest_of(provider, hash, encoded)?, disclosure)
                .is_some()
            {
                return Err(Refused::RepeatedDisclosure);
            }
        }
        Ok(Self {
            by_digest,
            used: HashSet::new(),
            seen: HashSet::new(),
        })
    }

    /// A digest may stand once in the whole payload, disclosures included.
    fn note(&mut self, digest: &str) -> Result<Option<Disclosure>, Refused> {
        if !self.seen.insert(digest.to_owned()) {
            return Err(Refused::RepeatedDigest);
        }
        let found = self.by_digest.get(digest).cloned();
        if found.is_some() {
            self.used.insert(digest.to_owned());
        }
        Ok(found)
    }

    fn unfold_value(&mut self, value: Value) -> Result<Value, Refused> {
        match value {
            Value::Object(object) => self.unfold_object(object).map(Value::Object),
            Value::Array(array) => self.unfold_array(array).map(Value::Array),
            plain => Ok(plain),
        }
    }

    fn unfold_object(&mut self, object: Map<String, Value>) -> Result<Map<String, Value>, Refused> {
        let mut digests = None;
        let mut unfolded = Map::with_capacity(object.len());
        for (name, value) in object {
            match name.as_str() {
                "_sd" => digests = Some(value),
                "..." => return Err(Refused::MalformedDigestCarrier),
                "_sd_alg" => return Err(Refused::MisplacedHashAlgorithm),
                _ => {
                    let value = self.unfold_value(value)?;
                    unfolded.insert(name, value);
                }
            }
        }
        let Some(digests) = digests else {
            return Ok(unfolded);
        };
        let Value::Array(digests) = digests else {
            return Err(Refused::MalformedDigestCarrier);
        };
        for digest in digests {
            let Value::String(digest) = digest else {
                return Err(Refused::MalformedDigestCarrier);
            };
            let Some(disclosure) = self.note(&digest)? else {
                continue;
            };
            let Some(name) = disclosure.name else {
                return Err(Refused::MalformedDisclosure);
            };
            if matches!(name.as_str(), "_sd" | "..." | "_sd_alg") {
                return Err(Refused::ForbiddenClaimName(name));
            }
            if unfolded.contains_key(&name) {
                return Err(Refused::ClaimCollision(name));
            }
            let value = self.unfold_value(disclosure.value)?;
            unfolded.insert(name, value);
        }
        Ok(unfolded)
    }

    fn unfold_array(&mut self, array: Vec<Value>) -> Result<Vec<Value>, Refused> {
        let mut unfolded = Vec::with_capacity(array.len());
        for element in array {
            let digest = match &element {
                Value::Object(carrier) if carrier.contains_key("...") => {
                    match (carrier.len(), carrier.get("...")) {
                        (1, Some(Value::String(digest))) => Some(digest.clone()),
                        _ => return Err(Refused::MalformedDigestCarrier),
                    }
                }
                _ => None,
            };
            let Some(digest) = digest else {
                unfolded.push(self.unfold_value(element)?);
                continue;
            };
            // An element whose disclosure was withheld leaves the array.
            let Some(disclosure) = self.note(&digest)? else {
                continue;
            };
            if disclosure.name.is_some() {
                return Err(Refused::MalformedDisclosure);
            }
            unfolded.push(self.unfold_value(disclosure.value)?);
        }
        Ok(unfolded)
    }
}

/// Required claims present, and the token inside the window it states.
fn check_validity(
    claims: &Map<String, Value>,
    policy: &VerifyingPolicy<'_>,
) -> Result<(), Refused> {
    if let Some(missing) = policy
        .required_claims
        .iter()
        .find(|name| !claims.contains_key(**name))
    {
        return Err(Refused::MissingClaim((*missing).to_owned()));
    }
    let now = policy.now as f64;
    let leeway = policy.leeway as f64;
    if let Some(expiry) = claims.get("exp") {
        let expiry = expiry.as_f64().ok_or(Refused::UnreadablePayload)?;
        if now >= expiry + leeway {
            return Err(Refused::Expired);
        }
    }
    if let Some(start) = claims.get("nbf") {
        let start = start.as_f64().ok_or(Refused::UnreadablePayload)?;
        if now + leeway < start {
            return Err(Refused::NotYetValid);
        }
    }
    Ok(())
}

/// The key the issuer named by value in `cnf.jwk`.
fn holder_key_of(claims: &Map<String, Value>) -> Option<Jwk> {
    let key = claims.get("cnf")?.as_object()?.get("jwk")?.as_object()?;
    Jwk::from_map(key.clone()).ok()
}

/// The verifier the holder key dictates. Elliptic curve keys only: the curve
/// names the algorithm, so the token's own header never chooses it, and a key
/// stating another `alg` is refused by the constructor.
fn holder_verifier(key: &Jwk) -> Option<Box<dyn JwsVerifier>> {
    let verifier: Box<dyn JwsVerifier> = match (key.key_type(), key.curve()) {
        ("EC", Some("P-256")) => Box::new(ES256.verifier_from_jwk(key).ok()?),
        ("EC", Some("P-384")) => Box::new(ES384.verifier_from_jwk(key).ok()?),
        ("EC", Some("P-521")) => Box::new(ES512.verifier_from_jwk(key).ok()?),
        ("OKP", Some("Ed25519")) => Box::new(EdDSA.verifier_from_jwk(key).ok()?),
        _ => return None,
    };
    Some(verifier)
}

/// RFC 9901 §7.3 step 5: signed by the holder key, typed, fresh, meant for
/// this verifier and this request, and over exactly what was presented.
fn check_key_binding(
    provider: &dyn CryptoProvider,
    hash: HashAlg,
    parts: &Parts<'_>,
    token: &str,
    holder: &Jwk,
    binding: &KeyBinding<'_>,
    policy: &VerifyingPolicy<'_>,
) -> Result<(), Refused> {
    let verifier = holder_verifier(holder).ok_or(Refused::NoHolderKey)?;
    let (payload, header) =
        jws::deserialize_compact(token, &*verifier).map_err(|_| Refused::KeyBindingSignature)?;
    if !header
        .token_type()
        .is_some_and(|typ| typ.eq_ignore_ascii_case("kb+jwt"))
    {
        return Err(Refused::KeyBindingType);
    }
    let Ok(Value::Object(claims)) = serde_json::from_slice::<Value>(&payload) else {
        return Err(Refused::KeyBindingUnreadable);
    };

    let issued = claims
        .get("iat")
        .and_then(Value::as_f64)
        .ok_or(Refused::KeyBindingUnreadable)?;
    let now = policy.now as f64;
    if issued > now + policy.leeway as f64 || issued < now - binding.max_age as f64 {
        return Err(Refused::KeyBindingStale);
    }
    if let Some(expiry) = claims.get("exp") {
        let expiry = expiry.as_f64().ok_or(Refused::KeyBindingUnreadable)?;
        if now >= expiry + policy.leeway as f64 {
            return Err(Refused::KeyBindingStale);
        }
    }

    let stated = |name: &str| match claims.get(name) {
        Some(Value::String(value)) => Ok(value.as_str()),
        _ => Err(Refused::KeyBindingUnreadable),
    };
    if stated("aud")? != binding.audience {
        return Err(Refused::KeyBindingAudience);
    }
    if stated("nonce")? != binding.nonce {
        return Err(Refused::KeyBindingNonce);
    }
    if stated("sd_hash")? != digest_of(provider, hash, parts.hashed)? {
        return Err(Refused::KeyBindingHash);
    }
    Ok(())
}
