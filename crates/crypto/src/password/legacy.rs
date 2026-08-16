//! The catalogue of password formats a customer can arrive with.
//!
//! A migration only ever happens during a successful login, because that is the
//! one moment the plaintext exists. So every format a customer might already
//! have needs a name here, including the ones this crate cannot yet check: an
//! importer that cannot name a format has to reject the whole import, and a
//! customer with one unrecognised column cannot move at all.
//!
//! The serde tag is the persisted form. Adding a variant is safe; renaming one
//! orphans every credential already imported under the old name.

use serde::{Deserialize, Serialize};

use crate::password::phc::argon2id_below_policy;
use crate::provider::Argon2Params;

/// A stored password, in whatever shape it arrived.
///
/// The normalised PBKDF2 variants carry base64 salt and hash rather than any
/// one framework's on-disk spelling, because RFC 8018 defines no storage
/// encoding and every framework picked a different one. Translating to this
/// shape is the importer's job; the framework-specific variants below exist
/// where that translation would lose something.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "algo", rename_all = "snake_case")]
pub enum LegacyHash {
    // Argon2, already the target or a sibling variant.
    Argon2id {
        encoded: String,
    },
    Argon2i {
        encoded: String,
    },
    Argon2d {
        encoded: String,
    },

    // Normalised PBKDF2: base64 salt and hash, derived length taken from the
    // decoded hash.
    Pbkdf2HmacSha1 {
        iterations: u32,
        salt: String,
        hash: String,
    },
    Pbkdf2HmacSha256 {
        iterations: u32,
        salt: String,
        hash: String,
    },
    Pbkdf2HmacSha512 {
        iterations: u32,
        salt: String,
        hash: String,
    },

    // Django. Its salt is plain text, not encoded — running it through a base64
    // decoder yields a different salt and every verification fails.
    DjangoPbkdf2Sha256 {
        iterations: u32,
        salt: String,
        hash: String,
    },
    DjangoPbkdf2Sha1 {
        iterations: u32,
        salt: String,
        hash: String,
    },
    /// bcrypt over the lowercase hex of SHA-256(password), which is how Django
    /// works around bcrypt's 72-byte limit.
    DjangoBcryptSha256 {
        encoded: String,
    },
    /// Django prefixes the PHC string; the importer strips the prefix.
    DjangoArgon2 {
        encoded: String,
    },

    // Rails Devise, Laravel, bcryptjs.
    Bcrypt {
        hash: String,
    },
    /// The same, keeping the variant letter for an audit trail.
    BcryptVariant {
        variant: char,
        hash: String,
    },

    // Spring Security, whose `{id}hash` prefix the importer strips.
    SpringBcrypt {
        hash: String,
    },
    SpringArgon2 {
        encoded: String,
    },
    SpringScrypt {
        encoded: String,
    },
    SpringNoop {
        plain: String,
    },

    // ASP.NET Identity, a binary blob tagged 0x00 or 0x01.
    AspNetIdentityV2 {
        binary: Vec<u8>,
    },
    AspNetIdentityV3 {
        binary: Vec<u8>,
    },

    // Keycloak and Auth0.
    KeycloakPbkdf2 {
        variant: String,
        iterations: u32,
        salt: String,
        hash: String,
    },
    Auth0Bcrypt {
        hash: String,
    },

    // The PHP family.
    PhpPasswordHash {
        encoded: String,
    },
    PhpassPortable {
        encoded: String,
    },
    Drupal8Plus {
        encoded: String,
    },
    Magento2 {
        encoded: String,
    },

    // scrypt.
    Scrypt {
        n: u32,
        r: u32,
        p: u32,
        salt: String,
        hash: String,
    },
    ScryptKc {
        encoded: String,
    },

    // Bare digests. The salted variants assume `digest(salt || password)` —
    // salt first, raw bytes, no separator. That is not universal: Spring's
    // MessageDigestPasswordEncoder computes `digest(password + "{" + salt +
    // "}")`, and older databases use `password || salt`. Nothing in the tag
    // records which, so the importer has to normalise to this one.
    Md5 {
        hash: String,
    },
    Md5Salted {
        salt: String,
        hash: String,
    },
    Sha1 {
        hash: String,
    },
    Sha1Salted {
        salt: String,
        hash: String,
    },
    Sha256Salted {
        salt: String,
        hash: String,
    },
    Sha512Salted {
        salt: String,
        hash: String,
    },

    /// A proprietary format, checked by an uploaded module that the service
    /// layer resolves from the identifier.
    Custom {
        verifier_id: String,
        encoded: String,
    },

    /// Plaintext.
    Plain {
        plain: String,
    },
}

/// How bad a stored format is, which decides how urgently it is replaced.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WeaknessLevel {
    /// A modern KDF: bcrypt, PBKDF2, scrypt, Argon2. Replace it in time.
    AcceptableMigration,
    /// Broken or plaintext. Replace it before the login finishes.
    Critical,
}

/// When to replace a stored hash after a successful verification.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RehashUrgency {
    /// Nothing to do: already Argon2id at policy.
    None,
    /// Replace it in the background.
    Background,
    /// Replace it before concluding the login, and raise an audit event.
    Immediate,
}

impl LegacyHash {
    /// How weak this format is.
    ///
    /// Matched variant by variant, with no catch-all. A default arm would file
    /// every format added later under "acceptable" without anyone deciding
    /// that, and the one added later is exactly the one nobody thought about.
    pub fn weakness_level(&self) -> WeaknessLevel {
        use WeaknessLevel::{AcceptableMigration, Critical};

        match self {
            // Unsalted or uniterated digests: a copy of the database is a copy
            // of the passwords.
            Self::Md5 { .. }
            | Self::Md5Salted { .. }
            | Self::Sha1 { .. }
            | Self::Sha1Salted { .. }
            | Self::Sha256Salted { .. }
            | Self::Sha512Salted { .. } => Critical,

            // Not hashed at all.
            Self::Plain { .. } | Self::SpringNoop { .. } => Critical,

            Self::Argon2id { .. }
            | Self::Argon2i { .. }
            | Self::Argon2d { .. }
            | Self::DjangoArgon2 { .. }
            | Self::SpringArgon2 { .. } => AcceptableMigration,

            Self::Pbkdf2HmacSha1 { .. }
            | Self::Pbkdf2HmacSha256 { .. }
            | Self::Pbkdf2HmacSha512 { .. }
            | Self::DjangoPbkdf2Sha256 { .. }
            | Self::DjangoPbkdf2Sha1 { .. }
            | Self::KeycloakPbkdf2 { .. }
            | Self::AspNetIdentityV2 { .. }
            | Self::AspNetIdentityV3 { .. } => AcceptableMigration,

            Self::Bcrypt { .. }
            | Self::BcryptVariant { .. }
            | Self::SpringBcrypt { .. }
            | Self::Auth0Bcrypt { .. }
            | Self::DjangoBcryptSha256 { .. }
            | Self::PhpPasswordHash { .. }
            | Self::PhpassPortable { .. }
            | Self::Drupal8Plus { .. }
            | Self::Magento2 { .. } => AcceptableMigration,

            Self::Scrypt { .. } | Self::ScryptKc { .. } | Self::SpringScrypt { .. } => {
                AcceptableMigration
            }

            // Opaque, so its strength is unknown. It is still replaced at the
            // next login like everything else here; what it does not get is the
            // blocking rehash and the audit event, which are for formats known
            // to be broken rather than merely unexamined.
            Self::Custom { .. } => AcceptableMigration,
        }
    }

    /// Whether a successful login has to be rehashed before it concludes.
    ///
    /// Blocking costs the user an Argon2id pass once. Deferring leaves a
    /// readable password in the database until a background job gets to it,
    /// which is a window measured in whatever the queue depth happens to be.
    pub fn force_immediate_rehash(&self) -> bool {
        matches!(self.weakness_level(), WeaknessLevel::Critical)
    }

    /// Whether the stored format is already the target.
    ///
    /// The variant only. For an Argon2id hash whose cost has fallen behind, see
    /// [`Self::rehash_urgency_for_policy`].
    pub fn is_target(&self) -> bool {
        matches!(self, Self::Argon2id { .. })
    }

    /// What to do after a successful verification.
    pub fn rehash_urgency(&self) -> RehashUrgency {
        if self.is_target() {
            RehashUrgency::None
        } else if self.force_immediate_rehash() {
            RehashUrgency::Immediate
        } else {
            RehashUrgency::Background
        }
    }

    /// The same, but reading the cost out of an Argon2id string.
    ///
    /// This is what lets the cost parameters rise without anyone being asked to
    /// change their password: the upgrade happens at the next login, with the
    /// plaintext, once per active account.
    pub fn rehash_urgency_for_policy(&self, policy: Argon2Params) -> RehashUrgency {
        match self {
            Self::Argon2id { encoded } if argon2id_below_policy(encoded, policy) => {
                RehashUrgency::Background
            }
            other => other.rehash_urgency(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One of every variant, paired with the name it is persisted under.
    fn every_variant() -> Vec<(&'static str, LegacyHash)> {
        let text = || "x".to_string();
        let pbkdf2 = |f: fn(u32, String, String) -> LegacyHash| f(1000, text(), text());

        vec![
            ("argon2id", LegacyHash::Argon2id { encoded: text() }),
            ("argon2i", LegacyHash::Argon2i { encoded: text() }),
            ("argon2d", LegacyHash::Argon2d { encoded: text() }),
            (
                "pbkdf2_hmac_sha1",
                pbkdf2(|i, s, h| LegacyHash::Pbkdf2HmacSha1 {
                    iterations: i,
                    salt: s,
                    hash: h,
                }),
            ),
            (
                "pbkdf2_hmac_sha256",
                pbkdf2(|i, s, h| LegacyHash::Pbkdf2HmacSha256 {
                    iterations: i,
                    salt: s,
                    hash: h,
                }),
            ),
            (
                "pbkdf2_hmac_sha512",
                pbkdf2(|i, s, h| LegacyHash::Pbkdf2HmacSha512 {
                    iterations: i,
                    salt: s,
                    hash: h,
                }),
            ),
            (
                "django_pbkdf2_sha256",
                pbkdf2(|i, s, h| LegacyHash::DjangoPbkdf2Sha256 {
                    iterations: i,
                    salt: s,
                    hash: h,
                }),
            ),
            (
                "django_pbkdf2_sha1",
                pbkdf2(|i, s, h| LegacyHash::DjangoPbkdf2Sha1 {
                    iterations: i,
                    salt: s,
                    hash: h,
                }),
            ),
            (
                "django_bcrypt_sha256",
                LegacyHash::DjangoBcryptSha256 { encoded: text() },
            ),
            (
                "django_argon2",
                LegacyHash::DjangoArgon2 { encoded: text() },
            ),
            ("bcrypt", LegacyHash::Bcrypt { hash: text() }),
            (
                "bcrypt_variant",
                LegacyHash::BcryptVariant {
                    variant: 'b',
                    hash: text(),
                },
            ),
            ("spring_bcrypt", LegacyHash::SpringBcrypt { hash: text() }),
            (
                "spring_argon2",
                LegacyHash::SpringArgon2 { encoded: text() },
            ),
            (
                "spring_scrypt",
                LegacyHash::SpringScrypt { encoded: text() },
            ),
            ("spring_noop", LegacyHash::SpringNoop { plain: text() }),
            (
                "asp_net_identity_v2",
                LegacyHash::AspNetIdentityV2 { binary: vec![0] },
            ),
            (
                "asp_net_identity_v3",
                LegacyHash::AspNetIdentityV3 { binary: vec![1] },
            ),
            (
                "keycloak_pbkdf2",
                LegacyHash::KeycloakPbkdf2 {
                    variant: text(),
                    iterations: 1000,
                    salt: text(),
                    hash: text(),
                },
            ),
            ("auth0_bcrypt", LegacyHash::Auth0Bcrypt { hash: text() }),
            (
                "php_password_hash",
                LegacyHash::PhpPasswordHash { encoded: text() },
            ),
            (
                "phpass_portable",
                LegacyHash::PhpassPortable { encoded: text() },
            ),
            ("drupal8_plus", LegacyHash::Drupal8Plus { encoded: text() }),
            ("magento2", LegacyHash::Magento2 { encoded: text() }),
            (
                "scrypt",
                LegacyHash::Scrypt {
                    n: 16384,
                    r: 8,
                    p: 1,
                    salt: text(),
                    hash: text(),
                },
            ),
            ("scrypt_kc", LegacyHash::ScryptKc { encoded: text() }),
            ("md5", LegacyHash::Md5 { hash: text() }),
            (
                "md5_salted",
                LegacyHash::Md5Salted {
                    salt: text(),
                    hash: text(),
                },
            ),
            ("sha1", LegacyHash::Sha1 { hash: text() }),
            (
                "sha1_salted",
                LegacyHash::Sha1Salted {
                    salt: text(),
                    hash: text(),
                },
            ),
            (
                "sha256_salted",
                LegacyHash::Sha256Salted {
                    salt: text(),
                    hash: text(),
                },
            ),
            (
                "sha512_salted",
                LegacyHash::Sha512Salted {
                    salt: text(),
                    hash: text(),
                },
            ),
            (
                "custom",
                LegacyHash::Custom {
                    verifier_id: text(),
                    encoded: text(),
                },
            ),
            ("plain", LegacyHash::Plain { plain: text() }),
        ]
    }

    /// The persisted name of every variant, pinned.
    ///
    /// These strings are in customer databases. A rename passes review as a
    /// tidy-up and orphans every credential already imported under the old
    /// name — an account that cannot be verified and cannot be migrated, since
    /// migrating needs a login that can no longer succeed.
    #[test]
    fn every_variant_keeps_its_persisted_name() {
        for (expected, hash) in every_variant() {
            let json: serde_json::Value = serde_json::to_value(&hash).unwrap();
            assert_eq!(
                json.get("algo").and_then(|v| v.as_str()),
                Some(expected),
                "{hash:?} is not persisted as {expected:?}"
            );
        }
    }

    /// Everything written can be read back as what it was.
    #[test]
    fn every_variant_round_trips() {
        for (name, hash) in every_variant() {
            let text = serde_json::to_string(&hash).unwrap();
            let back: LegacyHash = serde_json::from_str(&text).unwrap();
            assert_eq!(back, hash, "{name} did not survive the round trip");
        }
    }

    /// Nothing is missing from the catalogue's own test.
    ///
    /// The two tests above only cover what this list holds, so a variant added
    /// without a line here would be checked by nothing at all.
    #[test]
    fn the_list_covers_the_whole_catalogue() {
        let names: Vec<&str> = every_variant().into_iter().map(|(name, _)| name).collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();

        assert_eq!(unique.len(), names.len(), "a name is listed twice");
        assert_eq!(
            names.len(),
            34,
            "the catalogue changed size; add the new variant here and to the classification test"
        );
    }

    /// A format that hands over the password to anyone holding the database is
    /// replaced before the login concludes.
    #[test]
    fn broken_formats_block_the_login_until_they_are_replaced() {
        let critical = [
            LegacyHash::Md5 { hash: "x".into() },
            LegacyHash::Md5Salted {
                salt: "s".into(),
                hash: "x".into(),
            },
            LegacyHash::Sha1 { hash: "x".into() },
            LegacyHash::Sha1Salted {
                salt: "s".into(),
                hash: "x".into(),
            },
            LegacyHash::Sha256Salted {
                salt: "s".into(),
                hash: "x".into(),
            },
            LegacyHash::Sha512Salted {
                salt: "s".into(),
                hash: "x".into(),
            },
            LegacyHash::Plain { plain: "x".into() },
            LegacyHash::SpringNoop { plain: "x".into() },
        ];

        for hash in critical {
            assert_eq!(hash.weakness_level(), WeaknessLevel::Critical, "{hash:?}");
            assert!(hash.force_immediate_rehash(), "{hash:?}");
            assert_eq!(hash.rehash_urgency(), RehashUrgency::Immediate, "{hash:?}");
        }
    }

    /// Everything else is a real KDF and is replaced in the background.
    #[test]
    fn every_other_format_migrates_in_the_background() {
        for (name, hash) in every_variant() {
            if hash.weakness_level() == WeaknessLevel::Critical || hash.is_target() {
                continue;
            }

            assert!(!hash.force_immediate_rehash(), "{name}");
            assert_eq!(hash.rehash_urgency(), RehashUrgency::Background, "{name}");
        }
    }

    /// Only Argon2id is the target, and only at policy.
    #[test]
    fn the_target_is_argon2id_at_the_current_cost() {
        let policy = Argon2Params {
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
            output_len: 32,
        };
        let salt_and_hash = "$c29tZXNhbHQxMjM0NTY$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

        let at_policy = LegacyHash::Argon2id {
            encoded: format!("$argon2id$v=19$m=19456,t=2,p=1{salt_and_hash}"),
        };
        assert!(at_policy.is_target());
        assert_eq!(at_policy.rehash_urgency(), RehashUrgency::None);
        assert_eq!(
            at_policy.rehash_urgency_for_policy(policy),
            RehashUrgency::None
        );

        // Below policy the variant is still the target, so the plain urgency
        // says nothing to do — which is exactly why the policy-aware form
        // exists.
        for weaker in [
            "$argon2id$v=19$m=8192,t=2,p=1",
            "$argon2id$v=19$m=19456,t=1,p=1",
            "$argon2id$m=19456,t=2,p=1",
            "$argon2id$not a phc string",
        ] {
            let hash = LegacyHash::Argon2id {
                encoded: format!("{weaker}{salt_and_hash}"),
            };
            assert_eq!(hash.rehash_urgency(), RehashUrgency::None, "{weaker}");
            assert_eq!(
                hash.rehash_urgency_for_policy(policy),
                RehashUrgency::Background,
                "{weaker}"
            );
        }

        // A sibling variant is not the target however it is parameterised.
        let sibling = LegacyHash::Argon2i {
            encoded: format!("$argon2i$v=19$m=19456,t=2,p=1{salt_and_hash}"),
        };
        assert!(!sibling.is_target());
        assert_eq!(
            sibling.rehash_urgency_for_policy(policy),
            RehashUrgency::Background
        );
    }
}
