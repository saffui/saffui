// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

//! JSON Web Signature (JWS) support.

pub mod alg;
mod jws_algorithm;
mod jws_context;
mod jws_header;
mod jws_header_set;

use std::sync::LazyLock;

use crate::jose::JoseError;

pub use crate::jose::jws::jws_algorithm::JwsAlgorithm;
pub use crate::jose::jws::jws_algorithm::JwsSigner;
pub use crate::jose::jws::jws_algorithm::JwsVerifier;
pub use crate::jose::jws::jws_context::JwsContext;
pub use crate::jose::jws::jws_header::JwsHeader;
pub use crate::jose::jws::jws_header_set::JwsHeaderSet;

use crate::jose::jws::alg::hmac::HmacJwsAlgorithm;
pub use HmacJwsAlgorithm::Hs256 as HS256;
pub use HmacJwsAlgorithm::Hs384 as HS384;
pub use HmacJwsAlgorithm::Hs512 as HS512;

use crate::jose::jws::alg::rsassa::RsassaJwsAlgorithm;
pub use RsassaJwsAlgorithm::Rs256 as RS256;
pub use RsassaJwsAlgorithm::Rs384 as RS384;
pub use RsassaJwsAlgorithm::Rs512 as RS512;

use crate::jose::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm;
pub use RsassaPssJwsAlgorithm::Ps256 as PS256;
pub use RsassaPssJwsAlgorithm::Ps384 as PS384;
pub use RsassaPssJwsAlgorithm::Ps512 as PS512;

use crate::jose::jws::alg::ecdsa::EcdsaJwsAlgorithm;
pub use EcdsaJwsAlgorithm::Es256 as ES256;
pub use EcdsaJwsAlgorithm::Es256k as ES256K;
pub use EcdsaJwsAlgorithm::Es384 as ES384;
pub use EcdsaJwsAlgorithm::Es512 as ES512;

use crate::jose::jws::alg::eddsa::EddsaJwsAlgorithm;
pub use EddsaJwsAlgorithm::Eddsa as EdDSA;

static DEFAULT_CONTEXT: LazyLock<JwsContext> = LazyLock::new(JwsContext::new);

/// Return a representation of the data that is formatted by compact serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS heaser claims.
/// * `signer` - The JWS signer.
pub fn serialize_compact(
    payload: &[u8],
    header: &JwsHeader,
    signer: &dyn JwsSigner,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_compact(payload, header, signer)
}

/// Return a representation of the data that is formatted by compact serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS heaser claims.
/// * `selector` - a function for selecting the signing algorithm.
pub fn serialize_compact_with_selector<'a, F>(
    payload: &[u8],
    header: &JwsHeader,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(&JwsHeader) -> Option<&'a dyn JwsSigner>,
{
    DEFAULT_CONTEXT.serialize_compact_with_selector(payload, header, selector)
}

/// Return a representation of the data that is formatted by general json serialization.
///
/// # Arguments
///
/// * `protected` - The JWS protected header claims.
/// * `header` - The JWS unprotected header claims.
/// * `payload` - The payload data.
/// * `signers` - The JWS signer.
pub fn serialize_general_json(
    payload: &[u8],
    signers: &[(&JwsHeaderSet, &dyn JwsSigner)],
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_general_json(payload, signers)
}

/// Return a representation of the data that is formatted by general json serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `headers` - The protected and unprotected header claims.
/// * `selector` - a function for selecting the signing algorithm.
pub fn serialize_general_json_with_selecter<'a, F>(
    payload: &[u8],
    headers: &[&JwsHeaderSet],
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(usize, &JwsHeader) -> Option<&'a dyn JwsSigner>,
{
    DEFAULT_CONTEXT.serialize_general_json_with_selecter(payload, headers, selector)
}

/// Return a representation of the data that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS protected and unprotected header claims.
/// * `signer` - The JWS signer.
pub fn serialize_flattened_json(
    payload: &[u8],
    header: &JwsHeaderSet,
    signer: &dyn JwsSigner,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_flattened_json(payload, header, signer)
}

/// Return a representation of the data that is formatted by flatted json serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS protected and unprotected header claims.
/// * `selector` - a function for selecting the signing algorithm.
pub fn serialize_flattened_json_with_selector<'a, F>(
    payload: &[u8],
    header: &JwsHeaderSet,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(&JwsHeader) -> Option<&'a dyn JwsSigner>,
{
    DEFAULT_CONTEXT.serialize_flattened_json_with_selector(payload, header, selector)
}

/// Deserialize the input that is formatted by compact serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `verifier` - The JWS verifier.
pub fn deserialize_compact(
    input: impl AsRef<[u8]>,
    verifier: &dyn JwsVerifier,
) -> Result<(Vec<u8>, JwsHeader), JoseError> {
    DEFAULT_CONTEXT.deserialize_compact(input, verifier)
}

/// Deserialize the input that is formatted by compact serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `selector` - a function for selecting the verifying algorithm.
pub fn deserialize_compact_with_selector<'a, F>(
    input: impl AsRef<[u8]>,
    selector: F,
) -> Result<(Vec<u8>, JwsHeader), JoseError>
where
    F: Fn(&JwsHeader) -> Result<Option<&'a dyn JwsVerifier>, JoseError>,
{
    DEFAULT_CONTEXT.deserialize_compact_with_selector(input, selector)
}

/// Deserialize the input that is formatted by json serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `verifier` - The JWS verifier.
pub fn deserialize_json(
    input: impl AsRef<[u8]>,
    verifier: &dyn JwsVerifier,
) -> Result<(Vec<u8>, JwsHeader), JoseError> {
    DEFAULT_CONTEXT.deserialize_json(input, verifier)
}

/// Deserialize the input that is formatted by json serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `selector` - a function for selecting the verifying algorithm.
pub fn deserialize_json_with_selector<'a, F>(
    input: impl AsRef<[u8]>,
    selector: F,
) -> Result<(Vec<u8>, JwsHeader), JoseError>
where
    F: Fn(&JwsHeader) -> Result<Option<&'a dyn JwsVerifier>, JoseError>,
{
    DEFAULT_CONTEXT.deserialize_json_with_selector(input, selector)
}

#[cfg(test)]
mod tests {

    use anyhow::Result;

    use crate::jose::jwk::alg::ec::EcKeyPair;
    use crate::jose::jwk::alg::ed::EdKeyPair;
    use crate::jose::jwk::alg::rsa::RsaKeyPair;
    use crate::jose::jwk::alg::rsapss::RsaPssKeyPair;
    use crate::jose::jwk::{Ed448, Ed25519, KeyPair, P_256, P_384, P_521, Secp256k1};
    use crate::jose::jws::{
        self, ES256, ES256K, ES384, ES512, EdDSA, HS256, HS384, HS512, JwsHeader, JwsHeaderSet,
        JwsSigner, JwsVerifier, PS256, PS384, PS512, RS256, RS384, RS512,
    };
    use crate::jose::util::HashAlgorithm;

    /// RFC 7515 4.1.11: a `crit` naming an extension the recipient does not
    /// understand makes the JWS invalid. That is the point of the parameter —
    /// the sender is saying "refuse this rather than ignore what you cannot
    /// process".
    ///
    /// On the JSON path the check read the protected header for `critical`,
    /// a name no JWS carries, so it never ran and every unknown extension was
    /// waved through. The compact path reads `crit` and always has, which is
    /// why nothing looked wrong.
    ///
    /// Both halves matter here. The refusal alone would also pass if the JWS
    /// were rejected for some unrelated reason, so the same signature is
    /// verified again against a context that declares the extension
    /// acceptable: it must then be accepted. One input, two answers, decided
    /// by the check under test.
    #[test]
    fn a_json_jws_naming_an_unknown_critical_extension_is_refused() -> Result<()> {
        // Generated rather than loaded: this test is about header handling, and
        // a key it makes itself keeps it independent of the vendored vectors.
        let pair = EcKeyPair::generate(P_256)?;

        let mut header = JwsHeaderSet::new();
        header.set_key_id("kid-1", true);
        header.set_critical(&["urn:example:unsupported"]);

        let signer = ES256.signer_from_jwk(&pair.to_jwk_private_key())?;
        let json = jws::serialize_general_json(b"test payload!", &[(&header, &*signer)])?;

        let verifier = ES256.verifier_from_jwk(&pair.to_jwk_public_key())?;
        assert!(
            jws::deserialize_json(&json, &verifier).is_err(),
            "a JWS declaring an unsupported critical extension was accepted"
        );

        let mut context = jws::JwsContext::new();
        context.add_acceptable_critical("urn:example:unsupported");
        let (payload, _) = context.deserialize_json(&json, &verifier)?;
        assert_eq!(payload, b"test payload!".to_vec());

        Ok(())
    }

    /// Sign, verify, and refuse a signature that was touched.
    ///
    /// The refusal half is what makes the round trip mean anything: an
    /// implementation that returns `Ok(())` unconditionally passes the first
    /// half of every case below.
    fn round_trip(signer: &dyn JwsSigner, verifier: &dyn JwsVerifier) {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        let payload = b"the quick brown fox";

        let jws = jws::serialize_compact(payload, &header, signer).unwrap();
        let (decoded, decoded_header) = jws::deserialize_compact(&jws, verifier).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(decoded_header.algorithm(), Some(signer.algorithm().name()));

        let mut tampered = jws.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert!(
            jws::deserialize_compact(&tampered, verifier).is_err(),
            "a modified signature verified under {}",
            signer.algorithm().name()
        );

        let (head, _) = jws.rsplit_once('.').unwrap();
        let swapped = format!("{head}.{}", "A".repeat(4));
        assert!(jws::deserialize_compact(&swapped, verifier).is_err());
    }

    /// HMAC signing, on a key long enough for the largest digest offered.
    #[test]
    fn hmac_algorithms_round_trip() {
        let key = [0x5a_u8; 64];
        for alg in [HS256, HS384, HS512] {
            let signer = alg.signer_from_bytes(key).unwrap();
            let verifier = alg.verifier_from_bytes(key).unwrap();
            round_trip(&*signer, &*verifier);
        }
    }

    /// One generated RSA key serves the three PKCS#1 v1.5 algorithms; only the
    /// digest changes between them.
    #[test]
    fn rsassa_algorithms_round_trip() {
        let pair = RsaKeyPair::generate(2048).unwrap();
        let private = pair.to_jwk_private_key();
        let public = pair.to_jwk_public_key();

        for alg in [RS256, RS384, RS512] {
            let signer = alg.signer_from_jwk(&private).unwrap();
            let verifier = alg.verifier_from_jwk(&public).unwrap();
            round_trip(&*signer, &*verifier);
        }
    }

    /// PSS keys carry their digest, MGF1 digest and salt length, so each
    /// algorithm needs a key generated for it rather than a shared one.
    #[test]
    fn rsassa_pss_algorithms_round_trip() {
        let cases = [
            (PS256, HashAlgorithm::Sha256, 32),
            (PS384, HashAlgorithm::Sha384, 48),
            (PS512, HashAlgorithm::Sha512, 64),
        ];

        for (alg, hash, salt_len) in cases {
            let pair = RsaPssKeyPair::generate(2048, hash, hash, salt_len).unwrap();
            let signer = alg.signer_from_jwk(&pair.to_jwk_private_key()).unwrap();
            let verifier = alg.verifier_from_jwk(&pair.to_jwk_public_key()).unwrap();
            round_trip(&*signer, &*verifier);
        }
    }

    /// Each ECDSA algorithm is bound to one curve, secp256k1 included.
    #[test]
    fn ecdsa_algorithms_round_trip() {
        let cases = [
            (ES256, P_256),
            (ES384, P_384),
            (ES512, P_521),
            (ES256K, Secp256k1),
        ];

        for (alg, curve) in cases {
            let pair = EcKeyPair::generate(curve).unwrap();
            let signer = alg.signer_from_jwk(&pair.to_jwk_private_key()).unwrap();
            let verifier = alg.verifier_from_jwk(&pair.to_jwk_public_key()).unwrap();
            round_trip(&*signer, &*verifier);
        }
    }

    /// EdDSA names one algorithm over two curves; the curve comes from the key.
    #[test]
    fn eddsa_round_trips_on_both_curves() {
        for curve in [Ed25519, Ed448] {
            let pair = EdKeyPair::generate(curve).unwrap();
            let signer = EdDSA.signer_from_jwk(&pair.to_jwk_private_key()).unwrap();
            let verifier = EdDSA.verifier_from_jwk(&pair.to_jwk_public_key()).unwrap();
            round_trip(&*signer, &*verifier);
        }
    }

    /// A key of the right shape but the wrong value must not verify. Without
    /// this, a verifier that ignores the signature entirely still passes.
    #[test]
    fn a_signature_does_not_verify_under_another_key() {
        let mine = EcKeyPair::generate(P_256).unwrap();
        let theirs = EcKeyPair::generate(P_256).unwrap();

        let signer = ES256.signer_from_jwk(&mine.to_jwk_private_key()).unwrap();
        let verifier = ES256
            .verifier_from_jwk(&theirs.to_jwk_public_key())
            .unwrap();

        let header = JwsHeader::new();
        let jws = jws::serialize_compact(b"payload", &header, &*signer).unwrap();
        assert!(jws::deserialize_compact(&jws, &*verifier).is_err());
    }

    /// A key read from DER, from PEM and from a JWK must give the same signer.
    ///
    /// Three parsers per algorithm, and the matrix above only exercised one.
    /// Crossing them catches an encoding a parser reads differently from the
    /// others, which is otherwise found the day a key comes off disk.
    fn cross_encodings(signers: &[Box<dyn JwsSigner>], verifiers: &[Box<dyn JwsVerifier>]) {
        let header = JwsHeader::new();
        for signer in signers {
            let jws = jws::serialize_compact(b"payload", &header, &**signer).unwrap();
            for verifier in verifiers {
                let (decoded, _) = jws::deserialize_compact(&jws, &**verifier).unwrap();
                assert_eq!(decoded, b"payload");
            }
        }
    }

    #[test]
    fn rsassa_accepts_a_key_in_der_pem_and_jwk() {
        let pair = RsaKeyPair::generate(2048).unwrap();
        let signers: Vec<Box<dyn JwsSigner>> = vec![
            Box::new(RS256.signer_from_der(pair.to_der_private_key()).unwrap()),
            Box::new(RS256.signer_from_pem(pair.to_pem_private_key()).unwrap()),
            Box::new(RS256.signer_from_jwk(&pair.to_jwk_private_key()).unwrap()),
        ];
        let verifiers: Vec<Box<dyn JwsVerifier>> = vec![
            Box::new(RS256.verifier_from_der(pair.to_der_public_key()).unwrap()),
            Box::new(RS256.verifier_from_pem(pair.to_pem_public_key()).unwrap()),
            Box::new(RS256.verifier_from_jwk(&pair.to_jwk_public_key()).unwrap()),
        ];
        cross_encodings(&signers, &verifiers);
    }

    #[test]
    fn ecdsa_accepts_a_key_in_der_pem_and_jwk() {
        let pair = EcKeyPair::generate(P_256).unwrap();
        let signers: Vec<Box<dyn JwsSigner>> = vec![
            Box::new(ES256.signer_from_der(pair.to_der_private_key()).unwrap()),
            Box::new(ES256.signer_from_pem(pair.to_pem_private_key()).unwrap()),
            Box::new(ES256.signer_from_jwk(&pair.to_jwk_private_key()).unwrap()),
        ];
        let verifiers: Vec<Box<dyn JwsVerifier>> = vec![
            Box::new(ES256.verifier_from_der(pair.to_der_public_key()).unwrap()),
            Box::new(ES256.verifier_from_pem(pair.to_pem_public_key()).unwrap()),
            Box::new(ES256.verifier_from_jwk(&pair.to_jwk_public_key()).unwrap()),
        ];
        cross_encodings(&signers, &verifiers);
    }

    #[test]
    fn eddsa_accepts_a_key_in_der_pem_and_jwk() {
        let pair = EdKeyPair::generate(Ed25519).unwrap();
        let signers: Vec<Box<dyn JwsSigner>> = vec![
            Box::new(EdDSA.signer_from_der(pair.to_der_private_key()).unwrap()),
            Box::new(EdDSA.signer_from_pem(pair.to_pem_private_key()).unwrap()),
            Box::new(EdDSA.signer_from_jwk(&pair.to_jwk_private_key()).unwrap()),
        ];
        let verifiers: Vec<Box<dyn JwsVerifier>> = vec![
            Box::new(EdDSA.verifier_from_der(pair.to_der_public_key()).unwrap()),
            Box::new(EdDSA.verifier_from_pem(pair.to_pem_public_key()).unwrap()),
            Box::new(EdDSA.verifier_from_jwk(&pair.to_jwk_public_key()).unwrap()),
        ];
        cross_encodings(&signers, &verifiers);
    }

    #[test]
    fn rsassa_pss_accepts_a_key_in_der_pem_and_jwk() {
        let pair = RsaPssKeyPair::generate(2048, HashAlgorithm::Sha256, HashAlgorithm::Sha256, 32)
            .unwrap();
        let signers: Vec<Box<dyn JwsSigner>> = vec![
            Box::new(PS256.signer_from_der(pair.to_der_private_key()).unwrap()),
            Box::new(PS256.signer_from_jwk(&pair.to_jwk_private_key()).unwrap()),
        ];
        let verifiers: Vec<Box<dyn JwsVerifier>> = vec![
            Box::new(PS256.verifier_from_der(pair.to_der_public_key()).unwrap()),
            Box::new(PS256.verifier_from_jwk(&pair.to_jwk_public_key()).unwrap()),
        ];
        cross_encodings(&signers, &verifiers);
    }

    /// A verifier must refuse a token whose header names an algorithm other
    /// than its own. Without the check, `alg` becomes attacker-controlled.
    #[test]
    fn a_verifier_refuses_a_header_naming_another_algorithm() {
        let key = [0x5a_u8; 64];
        let signer = HS256.signer_from_bytes(key).unwrap();
        let verifier = HS384.verifier_from_bytes(key).unwrap();

        let header = JwsHeader::new();
        let jws = jws::serialize_compact(b"payload", &header, &*signer).unwrap();
        assert!(jws::deserialize_compact(&jws, &*verifier).is_err());
    }

    /// An `alg` left unprotected is not signed, and rewriting it is caught by
    /// the verifier rather than by the signature.
    ///
    /// RFC 7515 permits `alg` outside the protected header in the JSON
    /// serializations, and this implementation takes the caller at their word:
    /// asked for unprotected, it stays out of the signed bytes. So the
    /// signature does not defend it.
    ///
    /// What does is the verifier: it compares the header's `alg` against its
    /// own, so a rewritten value is refused. The check is worth pinning because
    /// it is the only thing standing there — a recipient that instead picks its
    /// verifier from the header, through `deserialize_json_with_selector`, has
    /// no such comparison to make and is choosing from unsigned bytes.
    #[test]
    fn an_unprotected_alg_is_unsigned_but_a_rewrite_is_still_refused() {
        let key = [0x5a_u8; 64];
        let signer = HS256.signer_from_bytes(key).unwrap();

        let mut set = JwsHeaderSet::new();
        set.set_algorithm("HS256", false);
        set.set_key_id("kid-1", true);

        let json = jws::serialize_flattened_json(b"payload", &set, &*signer).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();

        let protected_b64 = value["protected"].as_str().expect("a protected header");
        let protected: serde_json::Value = serde_json::from_slice(
            &crate::jose::util::decode_base64_urlsafe_no_pad(protected_b64).unwrap(),
        )
        .unwrap();

        assert_eq!(protected["kid"], "kid-1", "kid was asked to be protected");
        assert_eq!(
            protected["alg"],
            serde_json::Value::Null,
            "alg asked to be unprotected stays out of the signed header"
        );
        assert_eq!(value["header"]["alg"], "HS256");

        let verifier = HS256.verifier_from_bytes(key).unwrap();
        assert_eq!(
            jws::deserialize_json(&json, &*verifier).unwrap().0,
            b"payload",
            "the untouched token verifies"
        );

        value["header"]["alg"] = serde_json::Value::String("HS512".to_string());
        let tampered = serde_json::to_string(&value).unwrap();
        assert!(
            jws::deserialize_json(&tampered, &*verifier).is_err(),
            "a rewritten alg must be refused by the verifier, since the signature cannot"
        );
    }

    /// A general JSON JWS carries several signatures, and each verifier finds
    /// its own.
    ///
    /// The compact form holds one signature, so the matrices above never
    /// reached the code that walks a list looking for the one a given verifier
    /// can check.
    #[test]
    fn a_general_json_jws_verifies_under_each_of_its_signers() {
        let rsa = RsaKeyPair::generate(2048).unwrap();
        let ec = EcKeyPair::generate(P_256).unwrap();
        let ed = EdKeyPair::generate(Ed25519).unwrap();

        let mut h1 = JwsHeaderSet::new();
        h1.set_key_id("rsa", true);
        let mut h2 = JwsHeaderSet::new();
        h2.set_key_id("ec", true);
        let mut h3 = JwsHeaderSet::new();
        h3.set_key_id("ed", true);

        let s1 = RS256.signer_from_jwk(&rsa.to_jwk_private_key()).unwrap();
        let s2 = ES256.signer_from_jwk(&ec.to_jwk_private_key()).unwrap();
        let s3 = EdDSA.signer_from_jwk(&ed.to_jwk_private_key()).unwrap();

        let json =
            jws::serialize_general_json(b"payload", &[(&h1, &*s1), (&h2, &*s2), (&h3, &*s3)])
                .unwrap();

        let verifiers: Vec<Box<dyn JwsVerifier>> = vec![
            Box::new(RS256.verifier_from_jwk(&rsa.to_jwk_public_key()).unwrap()),
            Box::new(ES256.verifier_from_jwk(&ec.to_jwk_public_key()).unwrap()),
            Box::new(EdDSA.verifier_from_jwk(&ed.to_jwk_public_key()).unwrap()),
        ];
        for verifier in &verifiers {
            let (payload, header) = jws::deserialize_json(&json, &**verifier).unwrap();
            assert_eq!(payload, b"payload");
            assert!(header.key_id().is_some());
        }

        // A verifier holding none of these keys finds nothing to check.
        let stranger = EcKeyPair::generate(P_256).unwrap();
        let outsider = ES256
            .verifier_from_jwk(&stranger.to_jwk_public_key())
            .unwrap();
        assert!(jws::deserialize_json(&json, &*outsider).is_err());
    }

    /// The flattened form is the same token with one signature and no list.
    #[test]
    fn a_flattened_json_jws_round_trips() {
        let ec = EcKeyPair::generate(P_256).unwrap();
        let signer = ES256.signer_from_jwk(&ec.to_jwk_private_key()).unwrap();
        let verifier = ES256.verifier_from_jwk(&ec.to_jwk_public_key()).unwrap();

        let mut header = JwsHeaderSet::new();
        header.set_key_id("kid-1", true);
        header.set_token_type("JWT", false);

        let json = jws::serialize_flattened_json(b"payload", &header, &*signer).unwrap();
        let (decoded, decoded_header) = jws::deserialize_json(&json, &*verifier).unwrap();

        assert_eq!(decoded, b"payload");
        assert_eq!(decoded_header.key_id(), Some("kid-1"));
        assert_eq!(decoded_header.token_type(), Some("JWT"));

        // The payload is covered by the signature even in this form.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["payload"] =
            serde_json::Value::String(crate::jose::util::encode_base64_urlsafe_nopad(b"other"));
        let tampered = serde_json::to_string(&value).unwrap();
        assert!(jws::deserialize_json(&tampered, &*verifier).is_err());
    }

    /// The selector variants let the caller choose from the header. What they
    /// must not do is verify when the caller declines to supply anything.
    #[test]
    fn a_selector_that_returns_nothing_verifies_nothing() {
        let ec = EcKeyPair::generate(P_256).unwrap();
        let signer = ES256.signer_from_jwk(&ec.to_jwk_private_key()).unwrap();
        let verifier = ES256.verifier_from_jwk(&ec.to_jwk_public_key()).unwrap();

        let mut header = JwsHeader::new();
        header.set_key_id("kid-1");
        let jws = jws::serialize_compact(b"payload", &header, &*signer).unwrap();

        let (payload, _) = jws::deserialize_compact_with_selector(&jws, |header| {
            assert_eq!(header.key_id(), Some("kid-1"));
            Ok(Some(&verifier as &dyn JwsVerifier))
        })
        .unwrap();
        assert_eq!(payload, b"payload");

        assert!(jws::deserialize_compact_with_selector(&jws, |_| Ok(None)).is_err());
    }

    /// Malformed compact tokens are refused rather than parsed part-way.
    #[test]
    fn a_compact_jws_of_the_wrong_shape_is_refused() {
        let ec = EcKeyPair::generate(P_256).unwrap();
        let signer = ES256.signer_from_jwk(&ec.to_jwk_private_key()).unwrap();
        let verifier = ES256.verifier_from_jwk(&ec.to_jwk_public_key()).unwrap();

        let header = JwsHeader::new();
        let jws = jws::serialize_compact(b"payload", &header, &*signer).unwrap();
        let parts: Vec<&str> = jws.split('.').collect();

        let malformed = [
            String::new(),
            "not a jws".to_string(),
            parts[..2].join("."),
            format!("{jws}.extra"),
            format!("!!!.{}", parts[1..].join(".")),
        ];

        for input in malformed {
            assert!(
                jws::deserialize_compact(&input, &*verifier).is_err(),
                "accepted {input:?}"
            );
        }
    }

    /// The empty signature is the `none` algorithm's shape, and it must not
    /// verify under a real one.
    ///
    /// Stripping the signature and leaving the two other parts is the oldest
    /// JWS attack there is. It fails here because the verifier is fixed and
    /// checks the header against itself, but it is worth an assertion of its
    /// own rather than an inference.
    #[test]
    fn a_token_with_its_signature_removed_does_not_verify() {
        let ec = EcKeyPair::generate(P_256).unwrap();
        let signer = ES256.signer_from_jwk(&ec.to_jwk_private_key()).unwrap();
        let verifier = ES256.verifier_from_jwk(&ec.to_jwk_public_key()).unwrap();

        let header = JwsHeader::new();
        let jws = jws::serialize_compact(b"payload", &header, &*signer).unwrap();
        let (head, _) = jws.rsplit_once('.').unwrap();

        assert!(jws::deserialize_compact(format!("{head}."), &*verifier).is_err());

        // And the same token re-headed as `none`.
        let mut claims = serde_json::Map::new();
        claims.insert("alg".to_string(), serde_json::Value::String("none".into()));
        let none_header =
            crate::jose::util::encode_base64_urlsafe_nopad(serde_json::to_vec(&claims).unwrap());
        let payload = head.split_once('.').unwrap().1;
        assert!(jws::deserialize_compact(format!("{none_header}.{payload}."), &*verifier).is_err());
    }
}
