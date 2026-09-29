//! Data Integrity proofs as MOSIP's issuers and Inji's wallets write them:
//! `Ed25519Signature2020` on a credential, and `JsonWebSignature2020`, a
//! detached JWS over unencoded bytes (RFC 7797), on a presentation.
//!
//! Both sign the SHA-256 of the proof's options in canonical form followed by
//! the SHA-256 of the document without its proof in canonical form. The
//! options are read under the document's own `@context`, as those wallets and
//! issuers read them: the `jws-2020` context alone does not even name `type`.

use crypto::ecdsa::der_from_raw_signature;
use crypto::provider::{CryptoProvider, HashAlg, PublicKey, SignAlg};
use data_encoding::BASE64URL_NOPAD;
use serde_json::{Map, Value};

use crate::canon::{Refused, canonicalize};
use crate::context::Contexts;
use crate::json::parse_strict;
use crate::{Unreadable, base58, to_rdf};

/// A proof suite this crate verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    Ed25519Signature2020,
    JsonWebSignature2020,
}

/// What a proof says of itself. It is read before the signature is checked, so
/// that the caller can find the key `verification_method` names; holding the
/// purpose, challenge and domain to a request is the caller's part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub suite: Suite,
    pub verification_method: String,
    pub proof_purpose: Option<String>,
    pub created: Option<String>,
    pub challenge: Option<String>,
    pub domain: Option<String>,
}

/// How much reading and canonicalization one document may cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub most_quads: usize,
    pub work: u64,
}

/// Why a proof was not verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unproven {
    #[error("the document carries no proof")]
    NoProof,
    #[error("the document carries more than one proof")]
    ManyProofs,
    #[error("the proof suite {0} is not one this verifier reads")]
    UnknownSuite(String),
    #[error("the proof is malformed: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Unreadable(#[from] Unreadable),
    #[error("the document needs more work to canonicalize than it is allowed")]
    TooComplex,
    #[error("the document could not be hashed")]
    Unhashable,
    #[error("the signature does not verify under the key given")]
    Signature,
}

/// The members a proof may carry. Any other would be signed without this
/// verifier knowing what it says.
const MEMBERS: [&str; 8] = [
    "type",
    "verificationMethod",
    "proofPurpose",
    "created",
    "challenge",
    "domain",
    "proofValue",
    "jws",
];

/// The longest detached JWS read: its header and an EdDSA or ES256 signature
/// take a few hundred characters.
const MOST_JWS_LENGTH: usize = 1_024;

/// The proof `document` carries, read without verifying it.
pub fn read_proof(document: &Value) -> Result<Proof, Unproven> {
    let split = split_proof(document)?;
    read_members(split.proof).map(|(proof, _)| proof)
}

/// Verify the proof `document` carries under `key`, every context it names
/// taken from `contexts`.
pub fn verify_proof(
    provider: &dyn CryptoProvider,
    document: &Value,
    contexts: &dyn Contexts,
    key: &PublicKey,
    bounds: Bounds,
) -> Result<Proof, Unproven> {
    let Split { proof, unsigned } = split_proof(document)?;
    let (read, signature) = read_members(proof)?;
    let mut options: Map<String, Value> = proof
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "proofValue" | "jws"))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    let context = unsigned
        .get("@context")
        .ok_or(Unproven::Malformed("a document without a context"))?;
    options.insert("@context".to_owned(), context.clone());
    let signed_data = [
        hash_canonical(provider, &Value::Object(options), contexts, bounds)?,
        hash_canonical(provider, &Value::Object(unsigned), contexts, bounds)?,
    ]
    .concat();
    let verified = match signature {
        Signature::ProofValue(signature) => {
            provider
                .signer()
                .verify(SignAlg::EdDsa, key, &signed_data, &signature)
        }
        Signature::Jws {
            algorithm,
            header,
            signature,
        } => {
            let signing_input = [header.as_bytes(), b".", &signed_data].concat();
            provider
                .signer()
                .verify(algorithm, key, &signing_input, &signature)
        }
    };
    match verified {
        Ok(true) => Ok(read),
        _ => Err(Unproven::Signature),
    }
}

/// The signature a proof carries, decoded.
enum Signature {
    ProofValue(Vec<u8>),
    Jws {
        algorithm: SignAlg,
        header: String,
        signature: Vec<u8>,
    },
}

/// A document's proof, and the document without it.
struct Split<'d> {
    proof: &'d Map<String, Value>,
    unsigned: Map<String, Value>,
}

fn split_proof(document: &Value) -> Result<Split<'_>, Unproven> {
    let Value::Object(members) = document else {
        return Err(Unproven::Malformed("a document that is not a JSON object"));
    };
    let proof = match members.get("proof") {
        None => return Err(Unproven::NoProof),
        Some(Value::Object(proof)) => proof,
        Some(Value::Array(_)) => return Err(Unproven::ManyProofs),
        Some(_) => return Err(Unproven::Malformed("a proof that is not an object")),
    };
    let mut unsigned = members.clone();
    unsigned.remove("proof");
    Ok(Split { proof, unsigned })
}

fn read_members(proof: &Map<String, Value>) -> Result<(Proof, Signature), Unproven> {
    if proof.keys().any(|name| !MEMBERS.contains(&name.as_str())) {
        return Err(Unproven::Malformed(
            "a proof member this verifier does not read",
        ));
    }
    let text = |name: &str| match proof.get(name) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(Unproven::Malformed("a proof member that is not a string")),
    };
    let suite = match text("type")?.as_deref() {
        Some("Ed25519Signature2020") => Suite::Ed25519Signature2020,
        Some("JsonWebSignature2020") => Suite::JsonWebSignature2020,
        Some(other) => return Err(Unproven::UnknownSuite(other.to_owned())),
        None => return Err(Unproven::Malformed("a proof that names no suite")),
    };
    let verification_method = text("verificationMethod")?.ok_or(Unproven::Malformed(
        "a proof that names no verification method",
    ))?;
    let signature = match (suite, text("proofValue")?, text("jws")?) {
        (Suite::Ed25519Signature2020, Some(proof_value), None) => {
            Signature::ProofValue(decode_proof_value(&proof_value)?)
        }
        (Suite::JsonWebSignature2020, None, Some(jws)) => decode_jws(&jws)?,
        _ => {
            return Err(Unproven::Malformed(
                "a proof without the one signature member its suite carries",
            ));
        }
    };
    let read = Proof {
        suite,
        verification_method,
        proof_purpose: text("proofPurpose")?,
        created: text("created")?,
        challenge: text("challenge")?,
        domain: text("domain")?,
    };
    Ok((read, signature))
}

/// An Ed25519 signature written as multibase: `z`, then base58.
fn decode_proof_value(proof_value: &str) -> Result<Vec<u8>, Unproven> {
    proof_value
        .strip_prefix('z')
        .and_then(base58::decode)
        .filter(|signature| signature.len() == 64)
        .ok_or(Unproven::Malformed(
            "a proof value that is not an Ed25519 signature in base58",
        ))
}

/// A detached JWS over unencoded bytes: a header that says so, no payload,
/// and an EdDSA or ES256 signature.
fn decode_jws(jws: &str) -> Result<Signature, Unproven> {
    let malformed = Unproven::Malformed("a JWS that is not detached and unencoded");
    if jws.len() > MOST_JWS_LENGTH {
        return Err(malformed);
    }
    let mut parts = jws.split('.');
    let (Some(header), Some(""), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed);
    };
    let decoded = BASE64URL_NOPAD
        .decode(header.as_bytes())
        .map_err(|_| malformed.clone())?;
    let Ok(Value::Object(fields)) = parse_strict(&decoded) else {
        return Err(malformed);
    };
    let unencoded = fields.get("b64") == Some(&Value::Bool(false))
        && fields.get("crit") == Some(&Value::Array(vec![Value::String("b64".to_owned())]));
    let known = fields
        .keys()
        .all(|name| matches!(name.as_str(), "alg" | "b64" | "crit" | "kid"));
    if !unencoded || !known {
        return Err(malformed);
    }
    let algorithm = match fields.get("alg").and_then(Value::as_str) {
        Some("EdDSA") => SignAlg::EdDsa,
        Some("ES256") => SignAlg::Es256,
        _ => {
            return Err(Unproven::Malformed(
                "a JWS signed with an algorithm this verifier does not accept",
            ));
        }
    };
    let signature = BASE64URL_NOPAD
        .decode(signature.as_bytes())
        .ok()
        .filter(|signature| signature.len() == 64)
        .ok_or(Unproven::Malformed(
            "a JWS signature of another length than its algorithm's",
        ))?;
    let signature = match algorithm {
        SignAlg::Es256 => der_from_raw_signature(&signature).map_err(|_| malformed)?,
        _ => signature,
    };
    Ok(Signature::Jws {
        algorithm,
        header: header.to_owned(),
        signature,
    })
}

/// The SHA-256 of `document`'s dataset in canonical form.
fn hash_canonical(
    provider: &dyn CryptoProvider,
    document: &Value,
    contexts: &dyn Contexts,
    bounds: Bounds,
) -> Result<Vec<u8>, Unproven> {
    let quads = to_rdf(document, contexts, bounds.most_quads)?;
    let canonical =
        canonicalize(provider, HashAlg::Sha256, &quads, bounds.work).map_err(|refused| {
            match refused {
                Refused::TooComplex => Unproven::TooComplex,
                Refused::Unhashable => Unproven::Unhashable,
            }
        })?;
    provider
        .digest()
        .hash(HashAlg::Sha256, canonical.nquads.as_bytes())
        .map_err(|_| Unproven::Unhashable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn with_proof(proof: Value) -> Value {
        json!({ "@context": ["https://www.w3.org/2018/credentials/v1"], "proof": proof })
    }

    fn ed25519_proof() -> Value {
        json!({
            "type": "Ed25519Signature2020",
            "verificationMethod": "did:web:issuer.test#key-0",
            "proofPurpose": "assertionMethod",
            "proofValue": format!("z{}", base58::encode(&[7; 64])),
        })
    }

    #[test]
    fn a_proof_is_read_before_it_is_verified() {
        assert_eq!(
            read_proof(&with_proof(ed25519_proof())),
            Ok(Proof {
                suite: Suite::Ed25519Signature2020,
                verification_method: "did:web:issuer.test#key-0".to_owned(),
                proof_purpose: Some("assertionMethod".to_owned()),
                created: None,
                challenge: None,
                domain: None,
            })
        );
    }

    #[test]
    fn a_document_carries_exactly_one_proof_object() {
        assert_eq!(read_proof(&json!({})), Err(Unproven::NoProof));
        assert_eq!(
            read_proof(&with_proof(json!([ed25519_proof()]))),
            Err(Unproven::ManyProofs)
        );
        assert_eq!(
            read_proof(&with_proof(json!("proof"))),
            Err(Unproven::Malformed("a proof that is not an object"))
        );
        assert_eq!(
            read_proof(&json!([])),
            Err(Unproven::Malformed("a document that is not a JSON object"))
        );
    }

    #[test]
    fn a_proof_says_only_what_this_verifier_reads() {
        let refused = |change: &dyn Fn(&mut Value), why: Unproven| {
            let mut proof = ed25519_proof();
            change(&mut proof);
            assert_eq!(read_proof(&with_proof(proof)), Err(why));
        };
        refused(
            &|proof| proof["expires"] = json!("2030-01-01T00:00:00Z"),
            Unproven::Malformed("a proof member this verifier does not read"),
        );
        refused(
            &|proof| proof["created"] = json!(2025),
            Unproven::Malformed("a proof member that is not a string"),
        );
        refused(
            &|proof| proof["type"] = json!("DataIntegrityProof"),
            Unproven::UnknownSuite("DataIntegrityProof".to_owned()),
        );
        refused(
            &|proof| {
                proof.as_object_mut().expect("an object").remove("type");
            },
            Unproven::Malformed("a proof that names no suite"),
        );
        refused(
            &|proof| {
                proof
                    .as_object_mut()
                    .expect("an object")
                    .remove("verificationMethod");
            },
            Unproven::Malformed("a proof that names no verification method"),
        );
        let without_signature =
            Unproven::Malformed("a proof without the one signature member its suite carries");
        refused(
            &|proof| proof["jws"] = json!("e30..e30"),
            without_signature.clone(),
        );
        refused(
            &|proof| {
                proof
                    .as_object_mut()
                    .expect("an object")
                    .remove("proofValue");
            },
            without_signature.clone(),
        );
        refused(
            &|proof| proof["type"] = json!("JsonWebSignature2020"),
            without_signature,
        );
    }

    #[test]
    fn a_proof_value_is_an_ed25519_signature_in_base58() {
        let not_a_signature =
            Unproven::Malformed("a proof value that is not an Ed25519 signature in base58");
        for proof_value in [
            base58::encode(&[7; 64]),
            format!("z{}", base58::encode(&[7; 63])),
            format!("z{}", base58::encode(&[7; 65])),
            "z0OIl".to_owned(),
            format!("z{}", "2".repeat(300)),
        ] {
            let mut proof = ed25519_proof();
            proof["proofValue"] = json!(proof_value);
            assert_eq!(
                read_proof(&with_proof(proof)),
                Err(not_a_signature.clone()),
                "{proof_value}"
            );
        }
    }

    /// A header naming `b64` twice would be unencoded to one reader and encoded
    /// to another.
    #[test]
    fn a_jws_header_naming_a_member_twice_is_refused() {
        let header =
            BASE64URL_NOPAD.encode(br#"{"alg":"EdDSA","b64":true,"b64":false,"crit":["b64"]}"#);
        let proof = json!({
            "type": "JsonWebSignature2020",
            "verificationMethod": "did:jwk:holder#0",
            "jws": format!("{header}..{}", BASE64URL_NOPAD.encode(&[7; 64])),
        });
        assert_eq!(
            read_proof(&with_proof(proof)),
            Err(Unproven::Malformed(
                "a JWS that is not detached and unencoded"
            ))
        );
    }

    #[test]
    fn a_jws_signature_has_its_algorithms_length() {
        let header = BASE64URL_NOPAD.encode(br#"{"alg":"EdDSA","b64":false,"crit":["b64"]}"#);
        let jws_proof = |signature: &[u8]| {
            json!({
                "type": "JsonWebSignature2020",
                "verificationMethod": "did:jwk:holder#0",
                "jws": format!("{header}..{}", BASE64URL_NOPAD.encode(signature)),
            })
        };
        assert!(read_proof(&with_proof(jws_proof(&[7; 64]))).is_ok());
        for length in [0, 63, 65] {
            assert_eq!(
                read_proof(&with_proof(jws_proof(&vec![7; length]))),
                Err(Unproven::Malformed(
                    "a JWS signature of another length than its algorithm's"
                )),
                "{length}"
            );
        }
        let long = json!({
            "type": "JsonWebSignature2020",
            "verificationMethod": "did:jwk:holder#0",
            "jws": format!("{header}..{}", "A".repeat(MOST_JWS_LENGTH)),
        });
        assert_eq!(
            read_proof(&with_proof(long)),
            Err(Unproven::Malformed(
                "a JWS that is not detached and unencoded"
            ))
        );
    }
}
