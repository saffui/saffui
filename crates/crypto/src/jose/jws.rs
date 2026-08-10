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

    use crate::jose::jwk::P_256;
    use crate::jose::jwk::alg::ec::EcKeyPair;
    use crate::jose::jws::{self, ES256, JwsHeaderSet};

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
}
