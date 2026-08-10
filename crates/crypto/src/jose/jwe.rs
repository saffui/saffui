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

    use crate::jose::Value;
    use crate::jose::jwe::{self, Dir, JweAlgorithm, JweHeader};

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
}
