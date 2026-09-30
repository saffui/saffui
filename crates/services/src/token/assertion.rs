//! What this realm signs to prove itself to another server's token endpoint:
//! a client assertion, RFC 7523, the way `private_key_jwt` wants it.

use chrono::{DateTime, Utc};
use crypto::jose::jws::{ES256, JwsHeader, JwsSigner, PS256, RS256};
use crypto::jose::jwt::{self, JwtPayload};
use crypto::provider::CryptoProvider;
use secrecy::{ExposeSecret, SecretBox};

/// How long an assertion stands. CAMARA refuses one standing past 300
/// seconds; one minute leaves room for a clock that runs slow.
const LIFESPAN: i64 = 60;

/// What an assertion is signed with: ES256 under a P-256 key, as CAMARA
/// operators take it, PS256 under an RSA-PSS key, as eSignet 2.0 does, or
/// RS256 under an RSA key, the one eSignet 1.x verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionAlgorithm {
    Es256,
    Ps256,
    Rs256,
}

impl AssertionAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Ps256 => "PS256",
            Self::Rs256 => "RS256",
        }
    }
}

/// A key this realm signs its assertions with, and the name the other server
/// registered it under.
pub struct AssertionKey<'a> {
    pub kid: &'a str,
    pub private_pem: &'a SecretBox<Vec<u8>>,
    pub algorithm: AssertionAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the assertion could not be signed")]
pub struct Unsigned;

/// An assertion for `client_id`, addressed to `audience` alone, with an
/// identifier of its own so a server can refuse it twice.
pub fn client_assertion(
    provider: &dyn CryptoProvider,
    key: &AssertionKey<'_>,
    client_id: &str,
    audience: &str,
    now: DateTime<Utc>,
) -> Result<String, Unsigned> {
    let mut drawn = [0u8; 16];
    provider.rand().fill(&mut drawn).map_err(|_| Unsigned)?;
    let jti = data_encoding::HEXLOWER.encode(&drawn);

    let mut header = JwsHeader::new();
    header.set_algorithm(key.algorithm.name());
    header.set_token_type("JWT");
    header.set_key_id(key.kid);

    let mut payload = JwtPayload::new();
    payload.set_issuer(client_id);
    payload.set_subject(client_id);
    payload.set_audience(vec![audience]);
    payload.set_jwt_id(&jti);
    // Whole seconds, as the realm's own tokens carry them: a fraction is
    // lawful and still not what every server reads.
    for (claim, at) in [
        ("iat", now.timestamp()),
        ("exp", now.timestamp() + LIFESPAN),
    ] {
        payload
            .set_claim(claim, Some(serde_json::json!(at)))
            .map_err(|_| Unsigned)?;
    }

    let pem = key.private_pem.expose_secret();
    let signer: Box<dyn JwsSigner> = match key.algorithm {
        AssertionAlgorithm::Es256 => Box::new(ES256.signer_from_pem(pem).map_err(|_| Unsigned)?),
        AssertionAlgorithm::Ps256 => Box::new(PS256.signer_from_pem(pem).map_err(|_| Unsigned)?),
        AssertionAlgorithm::Rs256 => Box::new(RS256.signer_from_pem(pem).map_err(|_| Unsigned)?),
    };
    jwt::encode_with_signer(&payload, &header, &*signer).map_err(|_| Unsigned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::jose::jwk::KeyPair;
    use crypto::jose::jwk::alg::ec::EcKeyPair;
    use crypto::jose::jwk::alg::rsa::RsaKeyPair;
    use crypto::jose::jwk::alg::rsapss::RsaPssKeyPair;
    use crypto::jose::jws::JwsVerifier;
    use crypto::jose::util::HashAlgorithm;
    use crypto::provider::CryptoConfig;
    use crypto::provider::openssl::OpenSslProvider;

    fn read_signed(key: &AssertionKey<'_>, verifier: &dyn JwsVerifier) -> (JwsHeader, JwtPayload) {
        let provider = OpenSslProvider::new(&CryptoConfig::default()).expect("a provider");
        let now = DateTime::from_timestamp(1_800_000_000, 0).expect("a moment");
        let assertion = client_assertion(&provider, key, "rp-1", "https://idp.test", now)
            .expect("an assertion");
        let (payload, header) =
            jwt::decode_with_verifier(&assertion, verifier).expect("a signature that holds");
        (header, payload)
    }

    #[test]
    fn an_assertion_is_signed_with_the_algorithm_its_key_names() {
        let ec = EcKeyPair::generate(crypto::jose::jwk::P_256).expect("an EC key");
        let ec_pem = SecretBox::new(Box::new(ec.to_pem_private_key()));
        let (header, payload) = read_signed(
            &AssertionKey {
                kid: "ec-1",
                private_pem: &ec_pem,
                algorithm: AssertionAlgorithm::Es256,
            },
            &ES256
                .verifier_from_jwk(&ec.to_jwk_public_key())
                .expect("a verifier"),
        );
        assert_eq!(header.algorithm(), Some("ES256"));
        assert_eq!(header.key_id(), Some("ec-1"));
        assert_eq!(payload.audience(), Some(vec!["https://idp.test"]));

        let rsa = RsaPssKeyPair::generate(2048, HashAlgorithm::Sha256, HashAlgorithm::Sha256, 32)
            .expect("an RSA-PSS key");
        let rsa_pem = SecretBox::new(Box::new(rsa.to_pem_private_key()));
        let (header, payload) = read_signed(
            &AssertionKey {
                kid: "rsa-1",
                private_pem: &rsa_pem,
                algorithm: AssertionAlgorithm::Ps256,
            },
            &PS256
                .verifier_from_jwk(&rsa.to_jwk_public_key())
                .expect("a verifier"),
        );
        assert_eq!(header.algorithm(), Some("PS256"));
        assert_eq!(header.key_id(), Some("rsa-1"));
        assert_eq!(payload.issuer(), Some("rp-1"));
        assert_eq!(payload.subject(), Some("rp-1"));

        let classic = RsaKeyPair::generate(2048).expect("an RSA key");
        let classic_pem = SecretBox::new(Box::new(classic.to_pem_private_key()));
        let (header, payload) = read_signed(
            &AssertionKey {
                kid: "rsa-2",
                private_pem: &classic_pem,
                algorithm: AssertionAlgorithm::Rs256,
            },
            &RS256
                .verifier_from_jwk(&classic.to_jwk_public_key())
                .expect("a verifier"),
        );
        assert_eq!(header.algorithm(), Some("RS256"));
        assert_eq!(header.key_id(), Some("rsa-2"));
        assert_eq!(payload.audience(), Some(vec!["https://idp.test"]));
    }

    /// A key signs under the one scheme it was drawn for: an RSA-PSS key never
    /// signs RS256, nor a classic RSA key PS256.
    #[test]
    fn a_key_of_another_family_signs_nothing() {
        let provider = OpenSslProvider::new(&CryptoConfig::default()).expect("a provider");
        let now = DateTime::from_timestamp(1_800_000_000, 0).expect("a moment");
        let pem_of = |pem: Vec<u8>| SecretBox::new(Box::new(pem));
        let ec = EcKeyPair::generate(crypto::jose::jwk::P_256).expect("an EC key");
        let pss = RsaPssKeyPair::generate(2048, HashAlgorithm::Sha256, HashAlgorithm::Sha256, 32)
            .expect("an RSA-PSS key");
        let classic = RsaKeyPair::generate(2048).expect("an RSA key");
        for (pem, algorithm) in [
            (pem_of(ec.to_pem_private_key()), AssertionAlgorithm::Ps256),
            (pem_of(pss.to_pem_private_key()), AssertionAlgorithm::Rs256),
            (
                pem_of(classic.to_pem_private_key()),
                AssertionAlgorithm::Ps256,
            ),
        ] {
            assert_eq!(
                client_assertion(
                    &provider,
                    &AssertionKey {
                        kid: "key-1",
                        private_pem: &pem,
                        algorithm,
                    },
                    "rp-1",
                    "https://idp.test",
                    now,
                ),
                Err(Unsigned),
                "{}",
                algorithm.name()
            );
        }
    }
}
