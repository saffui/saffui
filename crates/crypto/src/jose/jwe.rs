// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

//! JSON Web Encryption (JWE) support.

pub mod alg;
pub mod enc;
mod jwe_algorithm;
mod jwe_compression;
mod jwe_content_encryption;
mod jwe_context;
mod jwe_header;
mod jwe_header_set;
pub mod zip;

use std::sync::LazyLock;

use crate::jose::JoseError;

pub use crate::jose::jwe::jwe_algorithm::JweAlgorithm;
pub use crate::jose::jwe::jwe_algorithm::JweDecrypter;
pub use crate::jose::jwe::jwe_algorithm::JweEncrypter;
pub use crate::jose::jwe::jwe_compression::JweCompression;
pub use crate::jose::jwe::jwe_content_encryption::JweContentEncryption;
pub use crate::jose::jwe::jwe_context::JweContext;
pub use crate::jose::jwe::jwe_header::JweHeader;
pub use crate::jose::jwe::jwe_header_set::JweHeaderSet;

pub use crate::jose::jwe::alg::direct::DirectJweAlgorithm::Dir;

use crate::jose::jwe::alg::ecdh_es::EcdhEsJweAlgorithm;
pub use EcdhEsJweAlgorithm::EcdhEs as ECDH_ES;
pub use EcdhEsJweAlgorithm::EcdhEsA128kw as ECDH_ES_A128KW;
pub use EcdhEsJweAlgorithm::EcdhEsA192kw as ECDH_ES_A192KW;
pub use EcdhEsJweAlgorithm::EcdhEsA256kw as ECDH_ES_A256KW;

use crate::jose::jwe::alg::aeskw::AeskwJweAlgorithm;
pub use AeskwJweAlgorithm::A128kw as A128KW;
pub use AeskwJweAlgorithm::A192kw as A192KW;
pub use AeskwJweAlgorithm::A256kw as A256KW;

use crate::jose::jwe::alg::aesgcmkw::AesgcmkwJweAlgorithm;
pub use AesgcmkwJweAlgorithm::A128gcmkw as A128GCMKW;
pub use AesgcmkwJweAlgorithm::A192gcmkw as A192GCMKW;
pub use AesgcmkwJweAlgorithm::A256gcmkw as A256GCMKW;

use crate::jose::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweAlgorithm;
pub use Pbes2HmacAeskwJweAlgorithm::Pbes2Hs256A128kw as PBES2_HS256_A128KW;
pub use Pbes2HmacAeskwJweAlgorithm::Pbes2Hs384A192kw as PBES2_HS384_A192KW;
pub use Pbes2HmacAeskwJweAlgorithm::Pbes2Hs512A256kw as PBES2_HS512_A256KW;

use crate::jose::jwe::alg::rsaes::RsaesJweAlgorithm;
#[allow(deprecated)]
pub use RsaesJweAlgorithm::Rsa1_5 as RSA1_5;
pub use RsaesJweAlgorithm::RsaOaep as RSA_OAEP;
pub use RsaesJweAlgorithm::RsaOaep256 as RSA_OAEP_256;
pub use RsaesJweAlgorithm::RsaOaep384 as RSA_OAEP_384;
pub use RsaesJweAlgorithm::RsaOaep512 as RSA_OAEP_512;

static DEFAULT_CONTEXT: LazyLock<JweContext> = LazyLock::new(JweContext::new);

/// Return a representation of the data that is formatted by compact serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS heaser claims.
/// * `encrypter` - The JWS encrypter.
pub fn serialize_compact(
    payload: &[u8],
    header: &JweHeader,
    encrypter: &dyn JweEncrypter,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_compact(payload, header, encrypter)
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
    header: &JweHeader,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(&JweHeader) -> Option<&'a dyn JweEncrypter>,
{
    DEFAULT_CONTEXT.serialize_compact_with_selector(payload, header, selector)
}

/// Return a representation of the data that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWE shared protected and unprotected header claims.
/// * `recipients` - The JWE header claims and the JWE encrypter pair for recipients.
/// * `aad` - The JWE additional authenticated data.
pub fn serialize_general_json(
    payload: &[u8],
    header: Option<&JweHeaderSet>,
    recipients: &[(Option<&JweHeader>, &dyn JweEncrypter)],
    aad: Option<&[u8]>,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_general_json(payload, header, recipients, aad)
}

/// Return a representation of the data that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS shared protected and unprotected header claims.
/// * `recipient_headers` - The JWE unprotected header claims for recipients.
/// * `aad` - The JWE additional authenticated data.
/// * `selector` - a function for selecting the encrypting algorithm.
pub fn serialize_general_json_with_selector<'a, F>(
    payload: &[u8],
    header: Option<&JweHeaderSet>,
    recipient_headers: &[Option<&JweHeader>],
    aad: Option<&[u8]>,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(usize, &JweHeader) -> Option<&'a dyn JweEncrypter>,
{
    DEFAULT_CONTEXT.serialize_general_json_with_selector(
        payload,
        header,
        recipient_headers,
        aad,
        selector,
    )
}

/// Return a representation of the data that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `header` - The JWE shared protected and unprotected header claims.
/// * `recipient_header` - The JWE unprotected header claims.
/// * `aad` - The JWE additional authenticated data.
/// * `payload` - The payload data.
/// * `encrypter` - The JWS encrypter.
pub fn serialize_flattened_json(
    payload: &[u8],
    header: Option<&JweHeaderSet>,
    recipient_header: Option<&JweHeader>,
    aad: Option<&[u8]>,
    encrypter: &dyn JweEncrypter,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_flattened_json(payload, header, recipient_header, aad, encrypter)
}

/// Return a representation of the data that is formatted by flatted json serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS shared protected and unprotected header claims.
/// * `recipient_header` - The JWS unprotected header claims.
/// * `aad` - The JWE additional authenticated data.
/// * `selector` - a function for selecting the encrypting algorithm.
pub fn serialize_flattened_json_with_selector<'a, F>(
    payload: &[u8],
    header: Option<&JweHeaderSet>,
    recipient_header: Option<&JweHeader>,
    aad: Option<&[u8]>,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(&JweHeader) -> Option<&'a dyn JweEncrypter>,
{
    DEFAULT_CONTEXT.serialize_flattened_json_with_selector(
        payload,
        header,
        recipient_header,
        aad,
        selector,
    )
}

/// Deserialize the input that is formatted by compact serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `decrypter` - The JWS decrypter.
pub fn deserialize_compact(
    input: &str,
    decrypter: &dyn JweDecrypter,
) -> Result<(Vec<u8>, JweHeader), JoseError> {
    DEFAULT_CONTEXT.deserialize_compact(input, decrypter)
}

/// Deserialize the input that is formatted by compact serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `selector` - a function for selecting the decrypting algorithm.
pub fn deserialize_compact_with_selector<'a, F>(
    input: &str,
    selector: F,
) -> Result<(Vec<u8>, JweHeader), JoseError>
where
    F: Fn(&JweHeader) -> Result<Option<&'a dyn JweDecrypter>, JoseError>,
{
    DEFAULT_CONTEXT.deserialize_compact_with_selector(input, selector)
}

/// Deserialize the input that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `decrypter` - The JWE decrypter.
pub fn deserialize_json(
    input: &str,
    decrypter: &dyn JweDecrypter,
) -> Result<(Vec<u8>, JweHeader), JoseError> {
    DEFAULT_CONTEXT.deserialize_json(input, decrypter)
}

/// Deserialize the input that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `selector` - a function for selecting the decrypting algorithm.
pub fn deserialize_json_with_selector<'a, F>(
    input: &str,
    selector: F,
) -> Result<(Vec<u8>, JweHeader), JoseError>
where
    F: Fn(&JweHeader) -> Result<Option<&'a dyn JweDecrypter>, JoseError>,
{
    DEFAULT_CONTEXT.deserialize_json_with_selector(input, selector)
}

#[cfg(test)]
mod tests {

    use anyhow::Result;

    use serde_json::json;

    use crate::jose::Value;
    use crate::jose::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption;
    use crate::jose::jwe::enc::aesgcm::AesgcmJweEncryption;
    use crate::jose::jwe::{
        self, A128GCMKW, A128KW, A192GCMKW, A192KW, A256GCMKW, A256KW, Dir, ECDH_ES,
        ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW, JweAlgorithm, JweContentEncryption,
        JweDecrypter, JweEncrypter, JweHeader, PBES2_HS256_A128KW, PBES2_HS384_A192KW,
        PBES2_HS512_A256KW, RSA_OAEP, RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512,
    };
    // RSA1_5 is deprecated upstream. Imported on its own so the allow covers
    // the name and nothing else in the list above.
    #[allow(deprecated)]
    use crate::jose::jwe::RSA1_5;
    use crate::jose::jwk::alg::ec::EcKeyPair;
    use crate::jose::jwk::alg::ecx::EcxKeyPair;
    use crate::jose::jwk::alg::rsa::RsaKeyPair;
    use crate::jose::jwk::{Jwk, KeyPair, P_256, P_384, P_521, X448, X25519};

    use crate::jose::util;

    #[test]
    fn test_jwe_compact_serialization() -> Result<()> {
        for enc in [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A256GCM",
            "A256GCM",
        ] {
            let mut src_header = JweHeader::new();
            src_header.set_content_encryption(enc);
            src_header.set_token_type("JWT");
            let src_payload = b"test payload!";

            //println!("{}", enc);

            let alg = Dir;
            let key = match enc {
                "A128CBC-HS256" => util::random_bytes(32),
                "A192CBC-HS384" => util::random_bytes(48),
                "A256CBC-HS512" => util::random_bytes(64),
                "A128GCM" => util::random_bytes(16),
                "A192GCM" => util::random_bytes(24),
                "A256GCM" => util::random_bytes(32),
                _ => unreachable!(),
            };
            let encrypter = alg.encrypter_from_bytes(&key)?;
            let jwe = jwe::serialize_compact(src_payload, &src_header, &encrypter)?;

            let decrypter = alg.decrypter_from_bytes(&key)?;
            let (dst_payload, dst_header) = jwe::deserialize_compact(&jwe, &decrypter)?;

            src_header.set_claim("alg", Some(Value::String(alg.name().to_string())))?;
            assert_eq!(src_header, dst_header);
            assert_eq!(src_payload.to_vec(), dst_payload);
        }

        Ok(())
    }

    /// Encrypt, decrypt, and refuse a ciphertext that was touched.
    ///
    /// The refusal half matters as much as the round trip: AEAD is only worth
    /// anything if a modified token fails, and a decrypter that ignores the tag
    /// round-trips perfectly.
    fn round_trip(alg_name: &str, encrypter: &dyn JweEncrypter, decrypter: &dyn JweDecrypter) {
        for enc in [
            &AescbcHmacJweEncryption::A128cbcHs256 as &dyn JweContentEncryption,
            &AescbcHmacJweEncryption::A192cbcHs384,
            &AescbcHmacJweEncryption::A256cbcHs512,
            &AesgcmJweEncryption::A128gcm,
            &AesgcmJweEncryption::A192gcm,
            &AesgcmJweEncryption::A256gcm,
        ] {
            let mut header = JweHeader::new();
            header.set_content_encryption(enc.name());
            let payload = b"the quick brown fox";

            let jwe = jwe::serialize_compact(payload, &header, encrypter).unwrap();
            let (decoded, _) = jwe::deserialize_compact(&jwe, decrypter).unwrap();
            assert_eq!(decoded, payload, "{alg_name} with {}", enc.name());

            let mut parts: Vec<&str> = jwe.split('.').collect();
            assert_eq!(parts.len(), 5, "compact JWE has five parts");
            let ciphertext = parts[3].to_string();
            let flipped = flip_last_base64_char(&ciphertext);
            parts[3] = &flipped;
            let tampered = parts.join(".");
            assert!(
                jwe::deserialize_compact(&tampered, decrypter).is_err(),
                "{alg_name} with {} accepted a modified ciphertext",
                enc.name()
            );
        }
    }

    fn flip_last_base64_char(s: &str) -> String {
        let mut out = s.to_string();
        let last = out.pop().unwrap();
        out.push(if last == 'A' { 'B' } else { 'A' });
        out
    }

    fn oct_jwk(len: usize) -> Jwk {
        let key = util::random_bytes(len);
        let mut jwk = Jwk::new("oct");
        jwk.set_key_use("enc");
        jwk.set_parameter("k", Some(json!(util::encode_base64_urlsafe_nopad(&key))))
            .unwrap();
        jwk
    }

    /// AES key wrap, one key length per algorithm.
    #[test]
    fn aeskw_algorithms_round_trip() {
        for (alg, len) in [(A128KW, 16), (A192KW, 24), (A256KW, 32)] {
            let jwk = oct_jwk(len);
            let encrypter = alg.encrypter_from_jwk(&jwk).unwrap();
            let decrypter = alg.decrypter_from_jwk(&jwk).unwrap();
            round_trip(alg.name(), &encrypter, &decrypter);
        }
    }

    /// AES-GCM key wrap, which also carries its own iv and tag in the header.
    #[test]
    fn aesgcmkw_algorithms_round_trip() {
        for (alg, len) in [(A128GCMKW, 16), (A192GCMKW, 24), (A256GCMKW, 32)] {
            let jwk = oct_jwk(len);
            let encrypter = alg.encrypter_from_jwk(&jwk).unwrap();
            let decrypter = alg.decrypter_from_jwk(&jwk).unwrap();
            round_trip(alg.name(), &encrypter, &decrypter);
        }
    }

    /// RSAES. RSA1_5 is deprecated and padding-oracle prone, and is covered
    /// here because it is reachable, not because it should be chosen.
    #[test]
    #[allow(deprecated)]
    fn rsaes_algorithms_round_trip() {
        let pair = RsaKeyPair::generate(2048).unwrap();
        let private = pair.to_jwk_private_key();
        let public = pair.to_jwk_public_key();

        for alg in [RSA1_5, RSA_OAEP, RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512] {
            let encrypter = alg.encrypter_from_jwk(&public).unwrap();
            let decrypter = alg.decrypter_from_jwk(&private).unwrap();
            round_trip(alg.name(), &encrypter, &decrypter);
        }
    }

    /// ECDH-ES, both the direct agreement and the three key-wrapping variants,
    /// on each curve the implementation accepts.
    #[test]
    fn ecdh_es_algorithms_round_trip() {
        for curve in [P_256, P_384, P_521] {
            let pair = EcKeyPair::generate(curve).unwrap();
            let private = pair.to_jwk_private_key();
            let public = pair.to_jwk_public_key();

            for alg in [ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW] {
                let encrypter = alg.encrypter_from_jwk(&public).unwrap();
                let decrypter = alg.decrypter_from_jwk(&private).unwrap();
                round_trip(alg.name(), &encrypter, &decrypter);
            }
        }
    }

    /// ECDH-ES over the montgomery curves, which take a different key type.
    #[test]
    fn ecdh_es_round_trips_on_montgomery_curves() {
        for curve in [X25519, X448] {
            let pair = EcxKeyPair::generate(curve).unwrap();
            let encrypter = ECDH_ES
                .encrypter_from_jwk(&pair.to_jwk_public_key())
                .unwrap();
            let decrypter = ECDH_ES
                .decrypter_from_jwk(&pair.to_jwk_private_key())
                .unwrap();
            round_trip(ECDH_ES.name(), &encrypter, &decrypter);
        }
    }

    /// PBES2 derives the key encryption key from a passphrase.
    #[test]
    fn pbes2_algorithms_round_trip() {
        for alg in [PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW] {
            let encrypter = alg
                .encrypter_from_bytes(b"correct horse battery staple")
                .unwrap();
            let decrypter = alg
                .decrypter_from_bytes(b"correct horse battery staple")
                .unwrap();
            round_trip(alg.name(), &encrypter, &decrypter);
        }
    }

    /// A ciphertext must not decrypt under a different key of the same shape.
    #[test]
    fn a_jwe_does_not_decrypt_under_another_key() {
        let mine = oct_jwk(32);
        let theirs = oct_jwk(32);

        let mut header = JweHeader::new();
        header.set_content_encryption(AesgcmJweEncryption::A256gcm.name());
        let encrypter = A256KW.encrypter_from_jwk(&mine).unwrap();
        let jwe = jwe::serialize_compact(b"payload", &header, &encrypter).unwrap();

        let decrypter = A256KW.decrypter_from_jwk(&theirs).unwrap();
        assert!(jwe::deserialize_compact(&jwe, &decrypter).is_err());
    }
}
