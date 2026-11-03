use saffui_core::ports::crypto::{CryptoFailure, GeneratedSigningKey, SignatureAlgorithm, Signer};
use saffui_core::secret::Secret;
use serde_json::Value;

use super::SharedProvider;
use crate::jose::jwk::KeyPair;
use crate::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
use crate::thumbprint::jwk_sha256_thumbprint;

/// The keys of the JOSE layer of this crate, behind the signing port of the
/// core. A private key is carried as PKCS#8 DER, a public key as a JWK.
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
}

#[cfg(test)]
mod tests {
    use saffui_core::ports::crypto::{SignatureAlgorithm, Signer};

    use super::JoseSigner;
    use crate::adapters::open_provider;

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
}
