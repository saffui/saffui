use crypto::provider::SignAlg;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::str_enum::str_enum;

str_enum! {
    #[postgres(name = "key_use")]
    /// What a key is for, spelled as RFC 7517 §4.2 spells it, so the record and
    /// the published JWK say the same word.
    pub enum KeyUse {
        Sig => "sig",
        Enc => "enc",
    }
}

str_enum! {
    #[postgres(name = "key_status")]
    /// Where a key stands in its rotation.
    pub enum KeyStatus {
        /// Signs new tokens. One per realm and use.
        Active => "active",
        /// Verifies only. Stays in the JWKS so tokens signed before the
        /// rotation still validate.
        Passive => "passive",
        /// Neither signs nor verifies, and is not published.
        Disabled => "disabled",
    }
}

str_enum! {
    /// The JWE key-management algorithms a client may register for encrypted id
    /// tokens and UserInfo responses.
    ///
    /// Asymmetric only. Encryption here is to the *client's* public key from its
    /// registered JWKS, so the symmetric families (`dir`, `AxxxKW`,
    /// `AxxxGCMKW`, `PBES2-*`) have no key to use, and `RSA1_5` is deprecated
    /// cryptography that is not offered at all.
    pub enum JweAlgorithm {
        RsaOaep => "RSA-OAEP",
        RsaOaep256 => "RSA-OAEP-256",
        RsaOaep384 => "RSA-OAEP-384",
        RsaOaep512 => "RSA-OAEP-512",
        EcdhEs => "ECDH-ES",
        EcdhEsA128kw => "ECDH-ES+A128KW",
        EcdhEsA192kw => "ECDH-ES+A192KW",
        EcdhEsA256kw => "ECDH-ES+A256KW",
    }
}

impl JweAlgorithm {
    /// The JWK `kty` values that can hold a recipient key for this algorithm.
    /// ECDH-ES accepts both `EC` (the P-curves) and `OKP` (X25519 and X448).
    pub fn key_types(self) -> &'static [&'static str] {
        match self {
            Self::RsaOaep | Self::RsaOaep256 | Self::RsaOaep384 | Self::RsaOaep512 => &["RSA"],
            Self::EcdhEs | Self::EcdhEsA128kw | Self::EcdhEsA192kw | Self::EcdhEsA256kw => {
                &["EC", "OKP"]
            }
        }
    }
}

str_enum! {
    /// The JWE content-encryption (`enc`) values (RFC 7518 §5.1).
    pub enum JweEncryption {
        A128CbcHs256 => "A128CBC-HS256",
        A192CbcHs384 => "A192CBC-HS384",
        A256CbcHs512 => "A256CBC-HS512",
        A128Gcm => "A128GCM",
        A192Gcm => "A192GCM",
        A256Gcm => "A256GCM",
    }
}

impl JweEncryption {
    /// What a client gets when it registers an encryption `alg` and no `enc`
    /// (OpenID Connect Registration §2).
    pub const DEFAULT: JweEncryption = JweEncryption::A128CbcHs256;
}

/// A realm's signing key, private material included.
///
/// Neither `Serialize` nor `Debug` is derived, and both omissions are the point:
/// a derived `Serialize` would let this reach an API response with one
/// `serde_json::to_string`, and a derived `Debug` would put the private key in
/// any log line that formatted a struct holding one. [`RealmSigningKeyView`] is
/// what callers get.
#[derive(Clone)]
pub struct RealmSigningKey {
    pub tenant: String,
    pub realm_id: String,
    /// RFC 7638 JWK thumbprint — the `kid` tokens and the JWKS reference.
    pub kid: String,
    pub algorithm: SignAlg,
    pub key_use: KeyUse,
    pub status: KeyStatus,
    pub priority: i64,
    /// PEM-encoded private key.
    pub private_pem: Vec<u8>,
    /// Public JWK, for JWKS publication.
    pub public_jwk: Value,
    /// Creation time, Unix epoch seconds.
    pub created_at: i64,
}

impl std::fmt::Debug for RealmSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealmSigningKey")
            .field("tenant", &self.tenant)
            .field("realm_id", &self.realm_id)
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("key_use", &self.key_use)
            .field("status", &self.status)
            .field("priority", &self.priority)
            .field("private_pem", &"<redacted>")
            .field("public_jwk", &self.public_jwk)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl RealmSigningKey {
    /// The JWK `kty`, read from the algorithm rather than stored beside it.
    pub fn key_type(&self) -> &'static str {
        self.algorithm.key_type()
    }
}

/// The private-free projection of a [`RealmSigningKey`], for admin responses and
/// JWKS assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmSigningKeyView {
    pub kid: String,
    pub realm_id: String,
    pub algorithm: SignAlg,
    pub key_type: String,
    pub key_use: KeyUse,
    pub status: KeyStatus,
    pub priority: i64,
    pub public_jwk: Value,
    pub created_at: i64,
}

impl From<&RealmSigningKey> for RealmSigningKeyView {
    fn from(key: &RealmSigningKey) -> Self {
        Self {
            kid: key.kid.clone(),
            realm_id: key.realm_id.clone(),
            algorithm: key.algorithm,
            key_type: key.key_type().to_owned(),
            key_use: key.key_use,
            status: key.status,
            priority: key.priority,
            public_jwk: key.public_jwk.clone(),
            created_at: key.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;

    fn key() -> RealmSigningKey {
        RealmSigningKey {
            tenant: "acme".into(),
            realm_id: "acme".into(),
            kid: "kid-1".into(),
            algorithm: SignAlg::Es256,
            key_use: KeyUse::Sig,
            status: KeyStatus::Active,
            priority: 7,
            private_pem: b"-----BEGIN PRIVATE KEY-----secret".to_vec(),
            public_jwk: serde_json::json!({"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}),
            created_at: 42,
        }
    }

    #[test]
    fn the_catalogues_agree_with_their_own_spelling() {
        assert_eq!(KeyUse::ALL.len(), 2);
        assert_eq!(KeyStatus::ALL.len(), 3);
        assert_eq!(JweAlgorithm::ALL.len(), 8);
        assert_eq!(JweEncryption::ALL.len(), 6);
        assert_round_trips(KeyUse::ALL);
        assert_round_trips(KeyStatus::ALL);
        assert_round_trips(JweAlgorithm::ALL);
        assert_round_trips(JweEncryption::ALL);
    }

    /// The spellings are the ones the specifications name, not merely spellings
    /// that agree with themselves. `use` is lowercase in RFC 7517 §4.2, and the
    /// stored record has to say the same word the published JWK does; the JWE
    /// names carry punctuation that is easy to normalise away by hand.
    #[test]
    fn the_spellings_are_the_ones_the_specifications_name() {
        assert_eq!(KeyUse::Sig.as_str(), "sig");
        assert_eq!(KeyUse::Enc.as_str(), "enc");
        assert_eq!(KeyStatus::Active.as_str(), "active");
        assert_eq!(KeyStatus::Disabled.as_str(), "disabled");
        assert_eq!(JweAlgorithm::RsaOaep256.as_str(), "RSA-OAEP-256");
        assert_eq!(JweAlgorithm::EcdhEsA128kw.as_str(), "ECDH-ES+A128KW");
        assert_eq!(JweEncryption::A256CbcHs512.as_str(), "A256CBC-HS512");
        assert_eq!(JweEncryption::A192Gcm.as_str(), "A192GCM");
    }

    /// The deprecated and the symmetric families were left out on purpose, and
    /// a caller must not be able to register one by name.
    #[test]
    fn the_excluded_encryption_algorithms_stay_excluded() {
        for excluded in ["RSA1_5", "dir", "A128KW", "A256GCMKW", "PBES2-HS256+A128KW"] {
            assert!(
                excluded.parse::<JweAlgorithm>().is_err(),
                "{excluded} must never be registrable"
            );
        }
    }

    /// A recipient key of the wrong family cannot carry the algorithm, so the
    /// pairing is what a registration check reads.
    #[test]
    fn each_key_management_algorithm_names_the_key_types_it_can_use() {
        for alg in JweAlgorithm::ALL {
            assert!(!alg.key_types().is_empty(), "{alg} names no key type");
            for kty in alg.key_types() {
                assert!(matches!(*kty, "RSA" | "EC" | "OKP"), "{alg}: {kty}");
            }
        }
        assert_eq!(JweAlgorithm::RsaOaep256.key_types(), &["RSA"]);
        assert_eq!(JweAlgorithm::EcdhEs.key_types(), &["EC", "OKP"]);
        assert!(
            !JweAlgorithm::RsaOaep.key_types().contains(&"EC"),
            "an RSA algorithm must not accept an elliptic curve key"
        );
    }

    /// The registration default is the one the specification names.
    #[test]
    fn the_encryption_default_is_the_registered_one() {
        assert_eq!(JweEncryption::DEFAULT, JweEncryption::A128CbcHs256);
        assert_eq!(JweEncryption::DEFAULT.as_str(), "A128CBC-HS256");
    }

    /// The key type is read from the algorithm, so the two cannot be written
    /// down disagreeing.
    #[test]
    fn the_key_type_follows_the_algorithm() {
        for algorithm in SignAlg::ALL {
            let key = RealmSigningKey { algorithm, ..key() };
            assert_eq!(key.key_type(), algorithm.key_type());
            assert_eq!(
                RealmSigningKeyView::from(&key).key_type,
                algorithm.key_type()
            );
        }
    }

    /// The view exists because the key carries a private PEM, so the conversion
    /// is the boundary between a secret and a public document.
    ///
    /// Asserted field by field rather than by eye: adding a field to the key and
    /// mirroring it into the view without thinking is how private material
    /// reaches a JWKS, and that mistake would compile.
    #[test]
    fn the_public_view_carries_no_private_material() {
        let key = key();
        let view = RealmSigningKeyView::from(&key);

        assert_eq!(view.kid, key.kid);
        assert_eq!(view.realm_id, key.realm_id);
        assert_eq!(view.algorithm, key.algorithm);
        assert_eq!(view.key_use, key.key_use);
        assert_eq!(view.status, key.status);
        assert_eq!(view.priority, key.priority);
        assert_eq!(view.created_at, key.created_at);
        assert_eq!(view.public_jwk, key.public_jwk);

        let json = serde_json::to_string(&view).unwrap();
        assert!(
            !json.contains("PRIVATE KEY"),
            "the view serialised private material: {json}"
        );
        assert!(
            !json.contains("private_pem"),
            "the view exposes private_pem"
        );
        for private_member in ["\"d\"", "\"p\"", "\"q\""] {
            assert!(
                !json.contains(private_member),
                "the view carries private JWK member {private_member}"
            );
        }
    }

    /// The other way private material escapes is a log line. `Debug` is written
    /// rather than derived so the PEM is not in it.
    #[test]
    fn debug_does_not_render_the_private_key() {
        let rendered = format!("{:?}", key());
        assert!(
            !rendered.contains("PRIVATE KEY"),
            "Debug rendered the private key: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("kid-1"), "the rest still renders");
    }
}
