//! The compact form of a signed token. The signature itself is the signer's:
//! this only decides what is signed and what is believed.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use crate::keys::SigningKey;
use crate::ports::crypto::{CryptoFailure, SignatureAlgorithm, Signer};
use crate::secret::Secret;

/// Signs `claims` under `key` and returns the three parts joined by dots.
///
/// # Errors
///
/// Returns the failure of the signer.
pub fn sign_compact(
    signer: &dyn Signer,
    key: &SigningKey,
    private_key: &Secret,
    token_type: &str,
    claims: &Value,
) -> Result<String, CryptoFailure> {
    let header = json!({ "alg": key.algorithm.name(), "kid": key.key_id, "typ": token_type });
    let mut token = URL_SAFE_NO_PAD.encode(header.to_string());
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(claims.to_string()));
    let signature = signer.sign(key.algorithm, private_key, token.as_bytes())?;
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(signature));
    Ok(token)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedToken {
    pub token_type: Option<String>,
    pub claims: Value,
}

/// Verifies a compact token against the keys of a realm.
///
/// The key is chosen by the `kid` of the header among the keys of the realm
/// and nowhere else, and the algorithm is the one stored with that key: the
/// header may only agree. Returns `None` for anything that does not verify,
/// whatever the reason.
#[must_use]
pub fn verify_compact(
    signer: &dyn Signer,
    token: &str,
    keys: &[SigningKey],
) -> Option<VerifiedToken> {
    let mut parts = token.split('.');
    let (header, claims, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let read_json = |part: &str| -> Option<Value> {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
    };
    let read_header = read_json(header)?;
    let key = keys
        .iter()
        .find(|key| read_header["kid"].as_str() == Some(key.key_id.as_str()))?;
    if SignatureAlgorithm::parse(read_header["alg"].as_str()?) != Some(key.algorithm) {
        return None;
    }
    let signing_input = &token[..header.len() + 1 + claims.len()];
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    if signer.verify(
        key.algorithm,
        &key.public_jwk,
        signing_input.as_bytes(),
        &signature,
    ) != Ok(true)
    {
        return None;
    }
    Some(VerifiedToken {
        token_type: read_header["typ"].as_str().map(str::to_owned),
        claims: read_json(claims)?,
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{sign_compact, verify_compact};
    use crate::keys::SigningKey;
    use crate::ports::crypto::{SignatureAlgorithm, Signer};
    use crate::secret::Secret;
    use crate::testkit::crypto::WeakSigner;

    fn generate(signer: &WeakSigner) -> (SigningKey, Secret) {
        let generated = signer
            .generate_key(SignatureAlgorithm::Es256)
            .expect("a key");
        let key = SigningKey {
            id: Uuid::nil(),
            key_id: generated.key_id,
            algorithm: generated.algorithm,
            public_jwk: generated.public_jwk,
            sealed_private_key: Vec::new(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        (key, generated.private_key)
    }

    fn replace_header(token: &str, header: &serde_json::Value) -> String {
        let rest = token.split_once('.').expect("a compact token").1;
        format!("{}.{rest}", URL_SAFE_NO_PAD.encode(header.to_string()))
    }

    #[test]
    fn a_token_is_read_back_by_the_key_that_signed_it_and_by_no_other() {
        let signer = WeakSigner::default();
        let (key, private_key) = generate(&signer);
        let (other, _) = generate(&signer);
        let claims = json!({ "sub": "billing" });

        let token = sign_compact(&signer, &key, &private_key, "at+jwt", &claims).expect("a token");

        let verified =
            verify_compact(&signer, &token, std::slice::from_ref(&key)).expect("a verified token");
        assert_eq!(verified.claims, claims);
        assert_eq!(verified.token_type.as_deref(), Some("at+jwt"));
        assert_eq!(
            verify_compact(&signer, &token, &[other]),
            None,
            "the key is not of this realm"
        );
        assert_eq!(verify_compact(&signer, &token, &[]), None);
    }

    #[test]
    fn the_header_cannot_choose_the_algorithm_or_drop_the_signature() {
        let signer = WeakSigner::default();
        let (key, private_key) = generate(&signer);
        let token =
            sign_compact(&signer, &key, &private_key, "at+jwt", &json!({})).expect("a token");
        let keys = std::slice::from_ref(&key);

        for algorithm in ["none", "HS256", "RS256", "es256"] {
            let forged = replace_header(&token, &json!({ "alg": algorithm, "kid": key.key_id }));
            assert_eq!(
                verify_compact(&signer, &forged, keys),
                None,
                "alg {algorithm}"
            );
        }
        let unsigned = format!("{}.", token.rsplit_once('.').expect("three parts").0);
        assert_eq!(verify_compact(&signer, &unsigned, keys), None);
        assert_eq!(
            verify_compact(&signer, &format!("{token}.extra"), keys),
            None
        );
        assert_eq!(verify_compact(&signer, "not a token", keys), None);
    }
}
