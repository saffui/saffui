// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

//! JSON Web Token (JWT) support.

pub mod alg;
mod jwt_context;
mod jwt_payload;
mod jwt_payload_validator;

pub use crate::jose::jwt::jwt_context::JwtContext;
pub use crate::jose::jwt::jwt_payload::JwtPayload;
pub use crate::jose::jwt::jwt_payload_validator::JwtPayloadValidator;

pub use crate::jose::jwt::alg::unsecured::UnsecuredJwsAlgorithm::None;

use std::sync::LazyLock;

use crate::jose::jwe::{JweDecrypter, JweEncrypter, JweHeader};
use crate::jose::jwk::{Jwk, JwkSet};
use crate::jose::jws::{JwsHeader, JwsSigner, JwsVerifier};
use crate::jose::{JoseError, JoseHeader};

static DEFAULT_CONTEXT: LazyLock<JwtContext> = LazyLock::new(JwtContext::new);

/// Return the string repsentation of the JWT with a "none" algorithm.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWT heaser claims.
pub fn encode_unsecured(payload: &JwtPayload, header: &JwsHeader) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.encode_unsecured(payload, header)
}

/// Return the string repsentation of the JWT with the siginig algorithm.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS heaser claims.
/// * `signer` - a signer object.
pub fn encode_with_signer(
    payload: &JwtPayload,
    header: &JwsHeader,
    signer: &dyn JwsSigner,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.encode_with_signer(payload, header, signer)
}

/// Return the string repsentation of the JWT with the encrypting algorithm.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWE heaser claims.
/// * `encrypter` - a encrypter object.
pub fn encode_with_encrypter(
    payload: &JwtPayload,
    header: &JweHeader,
    encrypter: &dyn JweEncrypter,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.encode_with_encrypter(payload, header, encrypter)
}

/// Return the Jose header decoded from JWT.
///
/// # Arguments
///
/// * `input` - a JWT string representation.
pub fn decode_header(input: impl AsRef<[u8]>) -> Result<Box<dyn JoseHeader>, JoseError> {
    DEFAULT_CONTEXT.decode_header(input)
}

/// Return the JWT object decoded with the "none" algorithm.
///
/// # Arguments
///
/// * `input` - a JWT string representation.
pub fn decode_unsecured(input: impl AsRef<[u8]>) -> Result<(JwtPayload, JwsHeader), JoseError> {
    DEFAULT_CONTEXT.decode_unsecured(input)
}

/// Return the JWT object decoded by the selected verifier.
///
/// # Arguments
///
/// * `verifier` - a verifier of the signing algorithm.
/// * `input` - a JWT string representation.
pub fn decode_with_verifier(
    input: impl AsRef<[u8]>,
    verifier: &dyn JwsVerifier,
) -> Result<(JwtPayload, JwsHeader), JoseError> {
    DEFAULT_CONTEXT.decode_with_verifier(input, verifier)
}

/// Return the JWT object decoded with a selected verifying algorithm.
///
/// # Arguments
///
/// * `input` - a JWT string representation.
/// * `selector` - a function for selecting the verifying algorithm.
pub fn decode_with_verifier_selector<'a, F>(
    input: impl AsRef<[u8]>,
    selector: F,
) -> Result<(JwtPayload, JwsHeader), JoseError>
where
    F: Fn(&JwsHeader) -> Result<Option<&'a dyn JwsVerifier>, JoseError>,
{
    DEFAULT_CONTEXT.decode_with_verifier_selector(input, selector)
}

/// Return the JWT object decoded by using a JWK set.
///
/// # Arguments
///
/// * `input` - a JWT string representation.
/// * `jwk_set` - a JWK set.
/// * `selector` - a function for selecting the verifying algorithm.
pub fn decode_with_verifier_in_jwk_set<F>(
    input: impl AsRef<[u8]>,
    jwk_set: &JwkSet,
    selector: F,
) -> Result<(JwtPayload, JwsHeader), JoseError>
where
    F: Fn(&Jwk) -> Result<Option<&dyn JwsVerifier>, JoseError>,
{
    DEFAULT_CONTEXT.decode_with_verifier_in_jwk_set(input, jwk_set, selector)
}

/// Return the JWT object decoded by the selected decrypter.
///
/// # Arguments
///
/// * `input` - a JWT string representation.
/// * `decrypter` - a decrypter of the decrypting algorithm.
pub fn decode_with_decrypter(
    input: impl AsRef<[u8]>,
    decrypter: &dyn JweDecrypter,
) -> Result<(JwtPayload, JweHeader), JoseError> {
    DEFAULT_CONTEXT.decode_with_decrypter(input, decrypter)
}

/// Return the JWT object decoded with a selected decrypting algorithm.
///
/// # Arguments
///
/// * `input` - a JWT string representation.
/// * `decrypter_selector` - a function for selecting the decrypting algorithm.
pub fn decode_with_decrypter_selector<'a, F>(
    input: impl AsRef<[u8]>,
    selector: F,
) -> Result<(JwtPayload, JweHeader), JoseError>
where
    F: Fn(&JweHeader) -> Result<Option<&'a dyn JweDecrypter>, JoseError>,
{
    DEFAULT_CONTEXT.decode_with_decrypter_selector(input, selector)
}

/// Return the JWT object decoded by using a JWK set.
///
/// # Arguments
///
/// * `input` - a JWT string representation.
/// * `jwk_set` - a JWK set.
/// * `selector` - a function for selecting the decrypting algorithm.
pub fn decode_with_decrypter_in_jwk_set<F>(
    input: impl AsRef<[u8]>,
    jwk_set: &JwkSet,
    selector: F,
) -> Result<(JwtPayload, JweHeader), JoseError>
where
    F: Fn(&Jwk) -> Result<Option<&dyn JweDecrypter>, JoseError>,
{
    DEFAULT_CONTEXT.decode_with_decrypter_in_jwk_set(input, jwk_set, selector)
}

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use serde_json::json;

    use std::time::{Duration, SystemTime};

    use crate::jose::jwe::{A256KW, JweHeader};
    use crate::jose::jwk::KeyPair;
    use crate::jose::jwk::P_256;
    use crate::jose::jwk::alg::ec::EcKeyPair;
    use crate::jose::jws::{ES256, HS256, HS384, HS512, JwsHeader};
    use crate::jose::jwt::{self, JwtPayload, JwtPayloadValidator};
    use crate::jose::util;

    #[test]
    fn test_jwt_unsecured() -> Result<()> {
        let mut src_header = JwsHeader::new();
        src_header.set_token_type("JWT");
        let src_payload = JwtPayload::new();
        let jwt_string = jwt::encode_unsecured(&src_payload, &src_header)?;
        let (dst_payload, dst_header) = jwt::decode_unsecured(&jwt_string)?;

        src_header.set_claim("alg", Some(json!("none")))?;
        assert_eq!(src_header, dst_header);
        assert_eq!(src_payload, dst_payload);

        Ok(())
    }

    #[test]
    fn test_jwt_none() -> Result<()> {
        let alg = jwt::None;
        let mut src_header = JwsHeader::new();
        src_header.set_token_type("JWT");
        let src_payload = JwtPayload::new();
        let signer = alg.signer();
        let jwt_string = jwt::encode_with_signer(&src_payload, &src_header, &signer)?;

        let verifier = alg.verifier();
        let (dst_payload, dst_header) = jwt::decode_with_verifier(&jwt_string, &verifier)?;

        src_header.set_claim("alg", Some(json!(alg.name())))?;
        assert_eq!(src_header, dst_header);
        assert_eq!(src_payload, dst_payload);

        Ok(())
    }

    #[test]
    fn test_jwt_with_hmac() -> Result<()> {
        for alg in &[HS256, HS384, HS512] {
            let private_key = util::random_bytes(64);

            let mut src_header = JwsHeader::new();
            src_header.set_token_type("JWT");
            let src_payload = JwtPayload::new();
            let signer = alg.signer_from_bytes(&private_key)?;
            let jwt_string = jwt::encode_with_signer(&src_payload, &src_header, &signer)?;

            let verifier = alg.verifier_from_bytes(&private_key)?;
            let (dst_payload, dst_header) = jwt::decode_with_verifier(&jwt_string, &verifier)?;

            src_header.set_claim("alg", Some(json!(alg.name())))?;
            assert_eq!(src_header, dst_header);
            assert_eq!(src_payload, dst_payload);
        }

        Ok(())
    }

    /// A signed JWT round-trips, and its registered claims survive.
    #[test]
    fn a_signed_jwt_round_trips_with_its_claims() -> Result<()> {
        let pair = EcKeyPair::generate(P_256)?;
        let signer = ES256.signer_from_jwk(&pair.to_jwk_private_key())?;
        let verifier = ES256.verifier_from_jwk(&pair.to_jwk_public_key())?;

        let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let expires = issued + Duration::from_secs(3600);

        let mut payload = JwtPayload::new();
        payload.set_issuer("https://issuer.test");
        payload.set_subject("subject-1");
        payload.set_audience(vec!["first", "second"]);
        payload.set_issued_at(&issued);
        payload.set_not_before(&issued);
        payload.set_expires_at(&expires);
        payload.set_jwt_id("jti-1");
        payload.set_claim("custom", Some(json!("value")))?;

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        let jwt = jwt::encode_with_signer(&payload, &header, &*signer)?;

        let (decoded, decoded_header) = jwt::decode_with_verifier(&jwt, &*verifier)?;
        assert_eq!(decoded_header.token_type(), Some("JWT"));
        assert_eq!(decoded.issuer(), Some("https://issuer.test"));
        assert_eq!(decoded.subject(), Some("subject-1"));
        assert_eq!(decoded.audience(), Some(vec!["first", "second"]));
        assert_eq!(decoded.jwt_id(), Some("jti-1"));
        assert_eq!(decoded.claim("custom"), Some(&json!("value")));
        assert_eq!(decoded.expires_at(), Some(expires));

        Ok(())
    }

    /// An encrypted JWT round-trips the same way.
    #[test]
    fn an_encrypted_jwt_round_trips() -> Result<()> {
        let key = util::random_bytes(32);
        let encrypter = A256KW.encrypter_from_bytes(&key)?;
        let decrypter = A256KW.decrypter_from_bytes(&key)?;

        let mut payload = JwtPayload::new();
        payload.set_subject("subject-1");

        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption("A128GCM");

        let jwt = jwt::encode_with_encrypter(&payload, &header, &encrypter)?;
        let (decoded, _) = jwt::decode_with_decrypter(&jwt, &decrypter)?;
        assert_eq!(decoded.subject(), Some("subject-1"));

        Ok(())
    }

    /// The header can be read without holding a key, which is how a recipient
    /// picks one. It must not be mistaken for verification.
    #[test]
    fn the_header_can_be_read_before_any_key_is_chosen() -> Result<()> {
        let pair = EcKeyPair::generate(P_256)?;
        let signer = ES256.signer_from_jwk(&pair.to_jwk_private_key())?;

        let mut header = JwsHeader::new();
        header.set_key_id("kid-1");
        let jwt = jwt::encode_with_signer(&JwtPayload::new(), &header, &*signer)?;

        let read = jwt::decode_header(&jwt)?;
        assert_eq!(read.claim("kid"), Some(&json!("kid-1")));

        Ok(())
    }

    /// Validation is what the claims are for: a token outside its window, from
    /// another issuer, or for another audience must be rejected.
    #[test]
    fn the_validator_rejects_a_token_outside_its_terms() -> Result<()> {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let hour = Duration::from_secs(3600);

        let mut payload = JwtPayload::new();
        payload.set_issuer("https://issuer.test");
        payload.set_audience(vec!["intended"]);
        payload.set_not_before(&now);
        payload.set_expires_at(&(now + hour));
        payload.set_jwt_id("jti-1");

        let mut ok = JwtPayloadValidator::new();
        ok.set_base_time(now + Duration::from_secs(60));
        ok.set_issuer("https://issuer.test");
        ok.set_audience("intended");
        ok.set_jwt_id("jti-1");
        assert!(ok.validate(&payload).is_ok());

        // Expired.
        let mut late = JwtPayloadValidator::new();
        late.set_base_time(now + hour + Duration::from_secs(1));
        assert!(late.validate(&payload).is_err());

        // Not yet valid.
        let mut early = JwtPayloadValidator::new();
        early.set_base_time(now - Duration::from_secs(1));
        assert!(early.validate(&payload).is_err());

        // Another issuer, and another audience.
        let mut wrong_issuer = JwtPayloadValidator::new();
        wrong_issuer.set_base_time(now);
        wrong_issuer.set_issuer("https://elsewhere.test");
        assert!(wrong_issuer.validate(&payload).is_err());

        let mut wrong_audience = JwtPayloadValidator::new();
        wrong_audience.set_base_time(now);
        wrong_audience.set_audience("someone-else");
        assert!(wrong_audience.validate(&payload).is_err());

        Ok(())
    }

    /// A payload claim of the wrong JSON type is refused, and removing one
    /// takes it out.
    #[test]
    fn a_payload_claim_of_the_wrong_type_is_refused() -> Result<()> {
        let mut payload = JwtPayload::new();

        assert!(payload.set_claim("iss", Some(json!(1))).is_err());
        assert!(payload.set_claim("aud", Some(json!(false))).is_err());
        assert!(payload.set_claim("exp", Some(json!("soon"))).is_err());

        payload.set_subject("subject-1");
        payload.set_claim("sub", None)?;
        assert_eq!(payload.subject(), None);

        Ok(())
    }
}
