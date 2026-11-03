use saffui_core::ports::crypto::{CryptoFailure, GeneratedSigningKey, SignatureAlgorithm, Signer};
use saffui_core::secret::Secret;
use serde_json::Value;

use super::SharedProvider;
use crate::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
use crate::jose::jwk::{Jwk, KeyPair};
use crate::jose::jws::alg::ecdsa::EcdsaJwsAlgorithm;
use crate::jose::jws::{JwsSigner, JwsVerifier};
use crate::thumbprint::jwk_sha256_thumbprint;

/// The keys and signatures of the JOSE layer of this crate, behind the
/// signing port of the core. A private key is carried as PKCS#8 DER, a
/// public key as a JWK.
pub struct JoseSigner {
    provider: SharedProvider,
}

impl JoseSigner {
    #[must_use]
    pub fn new(provider: SharedProvider) -> Self {
        Self { provider }
    }
}

impl Signer for JoseSigner {
    fn generate_key(
        &self,
        algorithm: SignatureAlgorithm,
    ) -> Result<GeneratedSigningKey, CryptoFailure> {
        let pair = match algorithm {
            SignatureAlgorithm::Es256 => {
                EcKeyPair::generate(EcCurve::P256).map_err(|_| CryptoFailure)?
            }
        };
        let mut public = pair.to_jwk_public_key();
        // The identifier is the thumbprint of the key alone (RFC 7638): it is
        // computed before anything else is written on the key.
        let key_id =
            jwk_sha256_thumbprint(self.provider.as_ref(), &public).map_err(|_| CryptoFailure)?;
        public.set_key_id(&key_id);
        public.set_algorithm(algorithm.name());
        public.set_key_use("sig");
        Ok(GeneratedSigningKey {
            algorithm,
            key_id,
            private_key: Secret::new(pair.to_der_private_key()),
            public_jwk: Value::Object(public.into()),
        })
    }

    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        private_key: &Secret,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoFailure> {
        let signed = match algorithm {
            SignatureAlgorithm::Es256 => EcdsaJwsAlgorithm::Es256
                .signer_from_der(private_key.expose())
                .and_then(|signer| signer.sign(message)),
        };
        signed.map_err(|_| CryptoFailure)
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        public_jwk: &Value,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoFailure> {
        let members = public_jwk.as_object().ok_or(CryptoFailure)?;
        let key = Jwk::from_map(members.clone()).map_err(|_| CryptoFailure)?;
        // A key of another type or another curve does not read: the
        // algorithm is never taken from the key.
        let verifier = match algorithm {
            SignatureAlgorithm::Es256 => EcdsaJwsAlgorithm::Es256
                .verifier_from_jwk(&key)
                .map_err(|_| CryptoFailure)?,
        };
        // A key that cannot be read is a failure. A signature that does not
        // verify, whatever its shape, is an answer.
        Ok(verifier.verify(message, signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use saffui_core::ports::crypto::{SignatureAlgorithm, Signer};
    use saffui_core::secret::Secret;
    use serde_json::json;

    use super::JoseSigner;
    use crate::adapters::open_provider;

    const ES256: SignatureAlgorithm = SignatureAlgorithm::Es256;
    const MESSAGE: &[u8] = b"header.payload";

    fn open_signer() -> JoseSigner {
        JoseSigner::new(open_provider().expect("a provider"))
    }

    #[test]
    fn a_generated_key_publishes_no_private_member_and_is_named_by_its_thumbprint() {
        let signer = JoseSigner::new(open_provider().expect("a provider"));

        let key = signer
            .generate_key(SignatureAlgorithm::Es256)
            .expect("a key");
        let other = signer
            .generate_key(SignatureAlgorithm::Es256)
            .expect("another key");

        let members = key.public_jwk.as_object().expect("an object");
        let mut names: Vec<&str> = members.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, ["alg", "crv", "kid", "kty", "use", "x", "y"]);
        assert_eq!(key.public_jwk["kty"], "EC");
        assert_eq!(key.public_jwk["crv"], "P-256");
        assert_eq!(key.public_jwk["alg"], "ES256");
        assert_eq!(key.public_jwk["use"], "sig");
        assert_eq!(key.public_jwk["kid"], key.key_id.as_str());
        assert_eq!(key.key_id.len(), 43, "32 bytes in base64url");
        assert_ne!(key.key_id, other.key_id);
    }

    #[test]
    fn a_signature_is_64_raw_bytes_and_verifies_under_its_key_only() {
        let signer = open_signer();
        let key = signer.generate_key(ES256).expect("a key");
        let other = signer.generate_key(ES256).expect("another key");

        let signature = signer
            .sign(ES256, &key.private_key, MESSAGE)
            .expect("a signature");

        assert_eq!(signature.len(), 64, "r and s, as a JWS carries them");
        assert_eq!(
            signer.verify(ES256, &key.public_jwk, MESSAGE, &signature),
            Ok(true)
        );
        assert_eq!(
            signer.verify(ES256, &other.public_jwk, MESSAGE, &signature),
            Ok(false)
        );
        assert_eq!(
            signer.verify(ES256, &key.public_jwk, b"header.payloae", &signature),
            Ok(false)
        );
    }

    #[test]
    fn an_altered_a_truncated_or_an_empty_signature_does_not_verify() {
        let signer = open_signer();
        let key = signer.generate_key(ES256).expect("a key");
        let signature = signer
            .sign(ES256, &key.private_key, MESSAGE)
            .expect("a signature");
        let mut altered = signature.clone();
        altered[10] ^= 1;

        for forged in [&altered[..], &signature[..63], &[][..], &[0_u8; 64][..]] {
            assert_eq!(
                signer.verify(ES256, &key.public_jwk, MESSAGE, forged),
                Ok(false),
                "{} bytes",
                forged.len()
            );
        }
    }

    #[test]
    fn a_key_that_is_not_one_fails_instead_of_answering() {
        let signer = open_signer();
        let key = signer.generate_key(ES256).expect("a key");
        let signature = signer
            .sign(ES256, &key.private_key, MESSAGE)
            .expect("a signature");

        for not_a_key in [
            json!("text"),
            json!({ "kty": "EC", "crv": "P-256", "x": "AA", "y": "AA" }),
            json!({ "kty": "RSA", "n": "AQAB", "e": "AQAB" }),
        ] {
            assert!(
                signer
                    .verify(ES256, &not_a_key, MESSAGE, &signature)
                    .is_err(),
                "{not_a_key}"
            );
        }
        assert!(
            signer
                .sign(ES256, &Secret::new(vec![1, 2, 3]), MESSAGE)
                .is_err()
        );
    }
}
