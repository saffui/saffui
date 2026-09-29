//! Data Integrity proofs, against a credential a real issuer signed and
//! presentations signed here in the exact shape Inji's wallets give them, read
//! under the contexts built in and the one context a realm would pin for the
//! credential.
//!
//! The credential and that context are in `tests/proofs`, one folder per
//! upstream, recorded in THIRD-PARTY.md.

use std::collections::HashMap;
use std::path::PathBuf;

use crypto::jose::jwk::{Ed25519, KeyPair};
use crypto::jose::jws::{ES256, EdDSA, JwsSigner};
use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, CryptoProvider, HashAlg, PublicKey};
use data_encoding::BASE64URL_NOPAD;
use jsonld::base58;
use jsonld::built_in::{CREDENTIALS_V1, HeldContexts, JWS_2020_V1};
use jsonld::canon::canonicalize;
use jsonld::json::parse_strict;
use jsonld::proof::{Bounds, Proof, Suite, Unproven, read_proof, verify_proof};
use jsonld::to_rdf;
use serde_json::{Map, Value, json};

const BOUNDS: Bounds = Bounds {
    most_quads: 1_000,
    work: 200,
};

/// The key of the insurance credential's issuer, as its DID document
/// published it when this test was written.
const INSURANCE_ISSUER_KEY: &str = "z6Mkjp2mZ8erefcvzpUgHD4ybxcW6xrY5QmYqcowxEELZ2q7";

const ED25519_PUBLIC_KEY_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn provider() -> OpenSslProvider {
    OpenSslProvider::new(&CryptoConfig::default()).expect("a provider")
}

fn fixture(path: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/proofs")
        .join(path);
    parse_strict(&std::fs::read(&path).expect("a fixture")).expect("JSON")
}

/// What a realm verifying the insurance credential pins beside the built-in
/// contexts.
fn pinned() -> HashMap<String, Value> {
    HashMap::from([(
        "https://holashchand.github.io/test_project/insurance-context.json".to_owned(),
        fixture("holashchand/insurance-context.json"),
    )])
}

fn insurance_credential() -> Value {
    fixture("vc-verifier/Ed25519Signature2020SignedSunbirdVC.json")
}

fn issuer_key() -> PublicKey {
    let decoded = base58::decode(&INSURANCE_ISSUER_KEY[1..]).expect("base58");
    let raw = decoded
        .strip_prefix(&[0xed, 0x01][..])
        .expect("an Ed25519 multicodec prefix");
    PublicKey::from_der([&ED25519_PUBLIC_KEY_PREFIX[..], raw].concat())
}

fn verify(document: &Value, key: &PublicKey) -> Result<Proof, Unproven> {
    let pinned = pinned();
    verify_proof(
        &provider(),
        document,
        &HeldContexts::new(&pinned),
        key,
        BOUNDS,
    )
}

#[test]
fn a_credential_verifies_under_its_issuers_key() {
    assert_eq!(
        verify(&insurance_credential(), &issuer_key()),
        Ok(Proof {
            suite: Suite::Ed25519Signature2020,
            verification_method: "did:web:api.released.mosip.net:identity-service:\
                02b073b8-aacd-472e-b63f-265bb7ccdd9f#key-0"
                .to_owned(),
            proof_purpose: Some("assertionMethod".to_owned()),
            created: Some("2025-02-17T07:53:17Z".to_owned()),
            challenge: None,
            domain: None,
        })
    );
}

#[test]
fn a_changed_claim_or_another_key_verifies_nothing() {
    let mut changed = insurance_credential();
    changed["credentialSubject"]["policyNumber"] = json!("5556");
    assert_eq!(verify(&changed, &issuer_key()), Err(Unproven::Signature));
    let another = EdDSA.generate_key_pair(Ed25519).expect("a key pair");
    assert_eq!(
        verify(
            &insurance_credential(),
            &PublicKey::from_der(another.to_der_public_key())
        ),
        Err(Unproven::Signature)
    );
}

/// The insurance context maps `policyName` and `policyNumber` to the same IRI,
/// so the dataset, and the proof over it, cannot tell them apart. What a
/// verifier reports must never rest on a term another term shares an IRI with.
#[test]
fn two_claims_one_iri_names_trade_places_unseen() {
    let mut swapped = insurance_credential();
    swapped["credentialSubject"]["policyName"] = json!("5555");
    swapped["credentialSubject"]["policyNumber"] = json!("wallet");
    assert!(verify(&swapped, &issuer_key()).is_ok());
}

/// A holder's key pair and the JWS algorithm it signs with.
struct Holder {
    algorithm: &'static str,
    signer: Box<dyn JwsSigner>,
    public: PublicKey,
}

impl Holder {
    fn drawn_ed25519() -> Self {
        let pair = EdDSA.generate_key_pair(Ed25519).expect("a key pair");
        Self {
            algorithm: "EdDSA",
            signer: Box::new(
                EdDSA
                    .signer_from_der(pair.to_der_private_key())
                    .expect("a signer"),
            ),
            public: PublicKey::from_der(pair.to_der_public_key()),
        }
    }

    fn drawn_p256() -> Self {
        let pair = ES256.generate_key_pair().expect("a key pair");
        Self {
            algorithm: "ES256",
            signer: Box::new(
                ES256
                    .signer_from_der(pair.to_der_private_key())
                    .expect("a signer"),
            ),
            public: PublicKey::from_der(pair.to_der_public_key()),
        }
    }
}

/// The SHA-256 of a document's dataset in canonical form, composed here from
/// the reading and the canonicalization rather than taken from the verifier.
fn hash_canonical(document: &Value) -> Vec<u8> {
    let provider = provider();
    let pinned = pinned();
    let quads =
        to_rdf(document, &HeldContexts::new(&pinned), BOUNDS.most_quads).expect("a dataset");
    let canonical =
        canonicalize(&provider, HashAlg::Sha256, &quads, BOUNDS.work).expect("canonical");
    provider
        .digest()
        .hash(HashAlg::Sha256, canonical.nquads.as_bytes())
        .expect("a digest")
}

/// A presentation of the insurance credential, signed by `holder` the way
/// Inji's wallets sign one: the options under the presentation's context,
/// no `created` and no `proofPurpose`, a detached JWS over unencoded bytes.
fn presentation_signed_by(holder: &Holder, header: &Value) -> Value {
    let holder_id = "did:jwk:eyJrdHkiOiJPS1AifQ#0";
    let mut presentation = json!({
        "@context": [CREDENTIALS_V1, JWS_2020_V1],
        "id": "urn:uuid:2341a08c-b520-4e0f-8d8c-efdb069da244",
        "type": ["VerifiablePresentation"],
        "verifiableCredential": [insurance_credential()],
        "holder": holder_id,
    });
    let mut options = Map::new();
    options.insert("@context".to_owned(), presentation["@context"].clone());
    options.insert("type".to_owned(), json!("JsonWebSignature2020"));
    options.insert("verificationMethod".to_owned(), json!(holder_id));
    options.insert("challenge".to_owned(), json!("NkdHJkBIbdOdQaAjWm8gpA"));
    options.insert(
        "domain".to_owned(),
        json!("decentralized_identifier:did:web:verifier.test:realms:acme"),
    );
    let signed_data = [
        hash_canonical(&Value::Object(options.clone())),
        hash_canonical(&presentation),
    ]
    .concat();
    let header = BASE64URL_NOPAD.encode(header.to_string().as_bytes());
    let signing_input = [header.as_bytes(), b".", &signed_data].concat();
    let signature = holder.signer.sign(&signing_input).expect("a signature");
    options.remove("@context");
    options.insert(
        "jws".to_owned(),
        json!(format!("{header}..{}", BASE64URL_NOPAD.encode(&signature))),
    );
    presentation["proof"] = Value::Object(options);
    presentation
}

fn unencoded_header(algorithm: &str) -> Value {
    json!({ "alg": algorithm, "b64": false, "crit": ["b64"] })
}

#[test]
fn a_presentation_signed_as_inji_signs_one_verifies() {
    for holder in [Holder::drawn_ed25519(), Holder::drawn_p256()] {
        let presentation = presentation_signed_by(&holder, &unencoded_header(holder.algorithm));
        assert_eq!(
            verify(&presentation, &holder.public),
            Ok(Proof {
                suite: Suite::JsonWebSignature2020,
                verification_method: "did:jwk:eyJrdHkiOiJPS1AifQ#0".to_owned(),
                proof_purpose: None,
                created: None,
                challenge: Some("NkdHJkBIbdOdQaAjWm8gpA".to_owned()),
                domain: Some(
                    "decentralized_identifier:did:web:verifier.test:realms:acme".to_owned()
                ),
            }),
            "{}",
            holder.algorithm
        );
    }
}

#[test]
fn a_presentation_answers_only_what_it_was_signed_for() {
    let holder = Holder::drawn_ed25519();
    let signed = presentation_signed_by(&holder, &unencoded_header("EdDSA"));
    let mut another_challenge = signed.clone();
    another_challenge["proof"]["challenge"] = json!("another request");
    assert_eq!(
        verify(&another_challenge, &holder.public),
        Err(Unproven::Signature)
    );
    let mut another_holder = signed.clone();
    another_holder["holder"] = json!("did:jwk:another#0");
    assert_eq!(
        verify(&another_holder, &holder.public),
        Err(Unproven::Signature)
    );
    let key_of_another = Holder::drawn_ed25519();
    assert_eq!(
        verify(&signed, &key_of_another.public),
        Err(Unproven::Signature)
    );
}

#[test]
fn a_jws_that_is_not_detached_and_unencoded_is_refused() {
    let holder = Holder::drawn_ed25519();
    for header in [
        json!({ "alg": "EdDSA" }),
        json!({ "alg": "EdDSA", "b64": false }),
        json!({ "alg": "EdDSA", "b64": true, "crit": ["b64"] }),
        json!({ "alg": "EdDSA", "b64": false, "crit": ["b64"], "typ": "JWT" }),
    ] {
        let presentation = presentation_signed_by(&holder, &header);
        assert_eq!(
            read_proof(&presentation),
            Err(Unproven::Malformed(
                "a JWS that is not detached and unencoded"
            )),
            "{header}"
        );
    }
    let mut attached = presentation_signed_by(&holder, &unencoded_header("EdDSA"));
    let jws = attached["proof"]["jws"]
        .as_str()
        .expect("a JWS")
        .replace("..", ".e30.");
    attached["proof"]["jws"] = json!(jws);
    assert_eq!(
        read_proof(&attached),
        Err(Unproven::Malformed(
            "a JWS that is not detached and unencoded"
        ))
    );
}

#[test]
fn a_jws_under_another_algorithm_is_refused() {
    let holder = Holder::drawn_ed25519();
    for algorithm in ["none", "HS256", "RS256", "ES384"] {
        let presentation = presentation_signed_by(&holder, &unencoded_header(algorithm));
        assert_eq!(
            read_proof(&presentation),
            Err(Unproven::Malformed(
                "a JWS signed with an algorithm this verifier does not accept"
            )),
            "{algorithm}"
        );
    }
}
