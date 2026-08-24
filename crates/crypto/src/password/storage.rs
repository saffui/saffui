use data_encoding::BASE64;
use secrecy::{ExposeSecret, SecretBox};

use crate::password::legacy::LegacyHash;
use crate::provider::{Argon2Params, CryptoError, CryptoProvider, HashAlg, Result};

/// Salt bytes for PBKDF2. RFC 8018 §4.1 asks for at least eight; sixteen
/// matches what Argon2id draws, so neither form is the weaker one.
const PBKDF2_SALT_LEN: usize = 16;

/// A stored password credential.
///
/// This is the logical shape. How it reaches a database — which column holds
/// the derived material and which holds the cost metadata — belongs to whatever
/// persists it, and the split matters: the cost is readable without touching
/// the secret, which is what lets a rehash decision be made without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredPassword {
    /// An Argon2id PHC string: `$argon2id$v=19$m=...,t=...,p=...$salt$hash`.
    Argon2id { encoded: String },
    /// PBKDF2-HMAC, with salt and derived key in padded standard base64.
    Pbkdf2 {
        algorithm: String,
        iterations: u32,
        salt: String,
        hash: String,
    },
}

impl StoredPassword {
    /// Hash a new password. This is what every new credential should be.
    ///
    /// The salt is drawn fresh by the provider on every call. Two accounts
    /// sharing a password must not share a hash, or one leaked table sorts the
    /// user base into groups who can be attacked once each.
    pub fn hash_argon2id(
        provider: &dyn CryptoProvider,
        params: Argon2Params,
        password: &SecretBox<String>,
    ) -> Result<Self> {
        Ok(Self::Argon2id {
            encoded: provider.password().hash(password, params)?,
        })
    }

    /// Hash a password in the PBKDF2 form, for a system that expects it.
    ///
    /// The derived key is the length of the PRF's own output. Asking for more
    /// adds no entropy (RFC 8018 §5.2) and costs another full pass per block.
    pub fn hash_pbkdf2(
        provider: &dyn CryptoProvider,
        algorithm: &str,
        iterations: u32,
        password: &SecretBox<String>,
    ) -> Result<Self> {
        let hash = pbkdf2_prf(algorithm)?;

        let mut salt = [0u8; PBKDF2_SALT_LEN];
        provider.rand().fill(&mut salt)?;

        let derived =
            provider
                .kdf()
                .pbkdf2_hmac(hash, password, &salt, iterations, hash.output_len())?;

        Ok(Self::Pbkdf2 {
            algorithm: algorithm.to_ascii_lowercase(),
            iterations,
            salt: BASE64.encode(&salt),
            hash: BASE64.encode(derived.expose_secret()),
        })
    }

    /// The verifying side's view of this credential.
    ///
    /// The PRF is resolved by the same function that chose it when hashing, so
    /// the two cannot drift. Mapping the name a second time here is how a
    /// credential gets written in a spelling the reader does not accept — a
    /// stored password that verifies against nothing, which no login can
    /// recover from because migrating needs a login that succeeds.
    pub fn to_legacy_hash(&self) -> Result<LegacyHash> {
        match self {
            Self::Argon2id { encoded } => Ok(LegacyHash::Argon2id {
                encoded: encoded.clone(),
            }),
            Self::Pbkdf2 {
                algorithm,
                iterations,
                salt,
                hash,
            } => {
                let (iterations, salt, hash) = (*iterations, salt.clone(), hash.clone());
                match pbkdf2_prf(algorithm)? {
                    HashAlg::Sha1 => Ok(LegacyHash::Pbkdf2HmacSha1 {
                        iterations,
                        salt,
                        hash,
                    }),
                    HashAlg::Sha256 => Ok(LegacyHash::Pbkdf2HmacSha256 {
                        iterations,
                        salt,
                        hash,
                    }),
                    HashAlg::Sha512 => Ok(LegacyHash::Pbkdf2HmacSha512 {
                        iterations,
                        salt,
                        hash,
                    }),
                    _ => Err(CryptoError::UnsupportedAlgorithm),
                }
            }
        }
    }
}

/// The PRF a PBKDF2 algorithm name asks for.
///
/// Matched exactly against the names actually in use, rather than by looking
/// for a digit in the string. A substring test reads `PBKDF2WithHmacSHA512` and
/// `md5-512-whatever` the same way, and a credential verified under the wrong
/// PRF never matches — a lockout that looks like a forgotten password.
pub(crate) fn pbkdf2_prf(name: &str) -> Result<HashAlg> {
    match name.to_ascii_lowercase().as_str() {
        "pbkdf2-sha1" | "pbkdf2withhmacsha1" => Ok(HashAlg::Sha1),
        "pbkdf2-sha256" | "pbkdf2withhmacsha256" => Ok(HashAlg::Sha256),
        "pbkdf2-sha512" | "pbkdf2withhmacsha512" => Ok(HashAlg::Sha512),
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::provider::CryptoConfig;
    use crate::provider::openssl::OpenSslProvider;

    fn provider() -> OpenSslProvider {
        OpenSslProvider::new(&CryptoConfig::default()).unwrap()
    }

    fn password(text: &str) -> SecretBox<String> {
        SecretBox::new(Box::new(text.to_string()))
    }

    /// What this module writes, the provider reads back.
    ///
    /// The two sides are the whole point: a stored form nothing can verify is
    /// an account that can never log in again.
    #[test]
    fn an_argon2id_credential_verifies_against_the_provider() {
        let provider = provider();
        let stored = StoredPassword::hash_argon2id(
            &provider,
            Argon2Params::default(),
            &password("correct horse"),
        )
        .unwrap();

        let StoredPassword::Argon2id { encoded } = &stored else {
            panic!("not an Argon2id credential");
        };

        assert!(encoded.starts_with("$argon2id$"));
        assert!(
            provider
                .password()
                .verify(&password("correct horse"), encoded)
                .unwrap()
        );
        assert!(
            !provider
                .password()
                .verify(&password("wrong horse"), encoded)
                .unwrap()
        );
    }

    /// The salt is drawn per call, so one password stored twice is two
    /// credentials.
    #[test]
    fn the_same_password_stores_differently_each_time() {
        let provider = provider();
        let once = StoredPassword::hash_argon2id(
            &provider,
            Argon2Params::default(),
            &password("correct horse"),
        )
        .unwrap();
        let twice = StoredPassword::hash_argon2id(
            &provider,
            Argon2Params::default(),
            &password("correct horse"),
        )
        .unwrap();

        assert_ne!(once, twice);
    }

    /// The PBKDF2 salt is drawn per call too.
    ///
    /// Without this the Argon2id test above passes alone and a zero salt goes
    /// unnoticed: the credential still recomputes from its own fields, and every
    /// account sharing a password shares a hash.
    #[test]
    fn the_pbkdf2_salt_is_drawn_per_call() {
        let provider = provider();
        let salt_of = || {
            let stored =
                StoredPassword::hash_pbkdf2(&provider, "pbkdf2-sha256", 1000, &password("secret"))
                    .unwrap();
            let StoredPassword::Pbkdf2 { salt, hash, .. } = stored else {
                panic!("not a PBKDF2 credential");
            };
            (salt, hash)
        };

        let (first_salt, first_hash) = salt_of();
        let (second_salt, second_hash) = salt_of();

        assert_ne!(first_salt, second_salt, "the salt repeated");
        assert_ne!(first_hash, second_hash, "the derived key repeated");
        assert_ne!(
            BASE64.decode(first_salt.as_bytes()).unwrap(),
            [0u8; PBKDF2_SALT_LEN],
            "the salt was never drawn"
        );
    }

    /// A PBKDF2 credential holds what verifying it needs, and the derived key
    /// is reproducible from those fields alone.
    #[test]
    fn a_pbkdf2_credential_can_be_recomputed_from_its_own_fields() {
        let provider = provider();
        let stored =
            StoredPassword::hash_pbkdf2(&provider, "pbkdf2-sha256", 1000, &password("secret"))
                .unwrap();

        let StoredPassword::Pbkdf2 {
            algorithm,
            iterations,
            salt,
            hash,
        } = &stored
        else {
            panic!("not a PBKDF2 credential");
        };

        assert_eq!(algorithm, "pbkdf2-sha256");
        assert_eq!(*iterations, 1000);
        assert_eq!(BASE64.decode(salt.as_bytes()).unwrap().len(), 16);

        let recomputed = provider
            .kdf()
            .pbkdf2_hmac(
                HashAlg::Sha256,
                &password("secret"),
                &BASE64.decode(salt.as_bytes()).unwrap(),
                1000,
                32,
            )
            .unwrap();
        assert_eq!(BASE64.encode(recomputed.expose_secret()), *hash);

        let wrong = provider
            .kdf()
            .pbkdf2_hmac(
                HashAlg::Sha256,
                &password("other"),
                &BASE64.decode(salt.as_bytes()).unwrap(),
                1000,
                32,
            )
            .unwrap();
        assert_ne!(BASE64.encode(wrong.expose_secret()), *hash);
    }

    /// Every PRF has its own derived length, and the name is stored normalised.
    #[test]
    fn each_prf_derives_its_own_width() {
        let provider = provider();

        for (name, width) in [
            ("pbkdf2-sha1", 20),
            ("PBKDF2WithHmacSHA256", 32),
            ("pbkdf2-sha512", 64),
        ] {
            let stored =
                StoredPassword::hash_pbkdf2(&provider, name, 1000, &password("secret")).unwrap();

            let StoredPassword::Pbkdf2 {
                algorithm, hash, ..
            } = &stored
            else {
                panic!("not a PBKDF2 credential");
            };

            assert_eq!(*algorithm, name.to_ascii_lowercase());
            assert_eq!(
                BASE64.decode(hash.as_bytes()).unwrap().len(),
                width,
                "{name}"
            );
        }
    }

    /// Everything this module can write, it can hand to the verifying side.
    ///
    /// The two mappings used to be written separately, and a name accepted by
    /// one and not the other mints a credential that verifies against nothing.
    /// Nothing recovers from that: migrating a password needs a login, and the
    /// login is what cannot succeed.
    #[test]
    fn every_credential_this_module_writes_can_be_handed_over() {
        let provider = provider();

        for name in [
            "pbkdf2-sha1",
            "pbkdf2-sha256",
            "pbkdf2-sha512",
            "PBKDF2WithHmacSHA1",
            "PBKDF2WithHmacSHA256",
            "PBKDF2WithHmacSHA512",
        ] {
            let stored =
                StoredPassword::hash_pbkdf2(&provider, name, 1000, &password("secret")).unwrap();
            let legacy = stored
                .to_legacy_hash()
                .unwrap_or_else(|_| panic!("{name} was written and cannot be handed over"));

            let (expected_salt, expected_hash) = match &stored {
                StoredPassword::Pbkdf2 { salt, hash, .. } => (salt, hash),
                _ => panic!("not a PBKDF2 credential"),
            };
            let (salt, hash) = match &legacy {
                LegacyHash::Pbkdf2HmacSha1 { salt, hash, .. }
                | LegacyHash::Pbkdf2HmacSha256 { salt, hash, .. }
                | LegacyHash::Pbkdf2HmacSha512 { salt, hash, .. } => (salt, hash),
                other => panic!("{name} became {other:?}"),
            };
            assert_eq!(salt, expected_salt, "{name}");
            assert_eq!(hash, expected_hash, "{name}");
        }

        let argon2 =
            StoredPassword::hash_argon2id(&provider, Argon2Params::default(), &password("secret"))
                .unwrap();
        assert!(matches!(
            argon2.to_legacy_hash().unwrap(),
            LegacyHash::Argon2id { .. }
        ));
    }

    /// A name that is not one of the known ones is refused, rather than read
    /// for whichever digits it happens to contain.
    #[test]
    fn an_unknown_algorithm_is_refused() {
        let provider = provider();

        for name in [
            "",
            "pbkdf2",
            "pbkdf2-sha384",
            "md5-256",
            "sha512",
            "pbkdf2-sha256-extra",
            "bcrypt",
        ] {
            assert!(
                matches!(
                    StoredPassword::hash_pbkdf2(&provider, name, 1000, &password("secret")),
                    Err(CryptoError::UnsupportedAlgorithm)
                ),
                "{name:?} was accepted"
            );
        }
    }
}
