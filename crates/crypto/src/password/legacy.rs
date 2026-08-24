use data_encoding::{BASE64, HEXLOWER_PERMISSIVE};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use crate::constant_time::eq as ct_eq;
use crate::password::phc::argon2id_below_policy;
use crate::password::storage::pbkdf2_prf;
use crate::provider::{Argon2Params, CryptoError, CryptoProvider, HashAlg, LegacyDigest, Result};

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
    /// Verify `password` against this stored hash.
    ///
    /// The answer is only ever "it matched" or "it did not". No error says
    /// which format failed or why — the caller collapses everything into one
    /// invalid-credentials response anyway, and a distinguishable error here
    /// would undo that at the source.
    ///
    /// A format this crate cannot check yet is an error, never `Ok(true)`.
    pub fn verify(
        &self,
        provider: &dyn CryptoProvider,
        password: &SecretBox<String>,
    ) -> Result<bool> {
        let raw = password.expose_secret().as_bytes();

        match self {
            // The Argon2 family reads its variant and cost out of the string
            // itself, so every wrapper around a PHC string lands here. That is
            // also what makes a rehash possible: verifying needs no advance
            // knowledge of the parameters.
            Self::Argon2id { encoded }
            | Self::Argon2i { encoded }
            | Self::Argon2d { encoded }
            | Self::DjangoArgon2 { encoded }
            | Self::SpringArgon2 { encoded } => {
                provider.password().verify_legacy_argon2(password, encoded)
            }

            // bcrypt reads its own cost and variant. Only the first 72 bytes of
            // a password count, which is a property of the format rather than a
            // fault here, and one the rehash removes.
            Self::Bcrypt { hash }
            | Self::BcryptVariant { hash, .. }
            | Self::SpringBcrypt { hash }
            | Self::Auth0Bcrypt { hash }
            | Self::PhpPasswordHash { encoded: hash } => {
                provider.password().verify_bcrypt(password, hash)
            }

            // bcrypt over the LOWERCASE hex of SHA-256(password). The case is
            // part of the bcrypt input: uppercase hex simply fails to verify.
            Self::DjangoBcryptSha256 { encoded } => {
                let digest = provider.legacy_digest().digest(LegacyDigest::Sha256, raw)?;
                let hex = SecretBox::new(Box::new(hex_lower(&digest)));
                provider.password().verify_bcrypt(&hex, encoded)
            }

            // Normalised PBKDF2: both fields base64.
            Self::Pbkdf2HmacSha1 {
                iterations,
                salt,
                hash,
            } => pbkdf2_check(
                provider,
                HashAlg::Sha1,
                password,
                &b64(salt)?,
                *iterations,
                &b64(hash)?,
            ),
            Self::Pbkdf2HmacSha256 {
                iterations,
                salt,
                hash,
            } => pbkdf2_check(
                provider,
                HashAlg::Sha256,
                password,
                &b64(salt)?,
                *iterations,
                &b64(hash)?,
            ),
            Self::Pbkdf2HmacSha512 {
                iterations,
                salt,
                hash,
            } => pbkdf2_check(
                provider,
                HashAlg::Sha512,
                password,
                &b64(salt)?,
                *iterations,
                &b64(hash)?,
            ),

            // Django's salt is raw text. Decoding it as base64 yields different
            // bytes and every verification fails.
            Self::DjangoPbkdf2Sha256 {
                iterations,
                salt,
                hash,
            } => pbkdf2_check(
                provider,
                HashAlg::Sha256,
                password,
                salt.as_bytes(),
                *iterations,
                &b64(hash)?,
            ),
            Self::DjangoPbkdf2Sha1 {
                iterations,
                salt,
                hash,
            } => pbkdf2_check(
                provider,
                HashAlg::Sha1,
                password,
                salt.as_bytes(),
                *iterations,
                &b64(hash)?,
            ),

            Self::KeycloakPbkdf2 {
                variant,
                iterations,
                salt,
                hash,
            } => {
                let alg = pbkdf2_prf(variant)?;
                pbkdf2_check(
                    provider,
                    alg,
                    password,
                    &b64(salt)?,
                    *iterations,
                    &b64(hash)?,
                )
            }

            Self::AspNetIdentityV2 { binary } => aspnet_v2(provider, password, binary),
            Self::AspNetIdentityV3 { binary } => aspnet_v3(provider, password, binary),

            Self::Md5 { hash } => digest_hex_eq(provider, LegacyDigest::Md5, raw, hash),
            Self::Sha1 { hash } => digest_hex_eq(provider, LegacyDigest::Sha1, raw, hash),

            // Salted digests, as `digest(salt || password)`. See the note on
            // the variants: the importer owes this convention.
            Self::Md5Salted { salt, hash } => {
                salted_digest_hex_eq(provider, LegacyDigest::Md5, salt, raw, hash)
            }
            Self::Sha1Salted { salt, hash } => {
                salted_digest_hex_eq(provider, LegacyDigest::Sha1, salt, raw, hash)
            }
            Self::Sha256Salted { salt, hash } => {
                salted_digest_hex_eq(provider, LegacyDigest::Sha256, salt, raw, hash)
            }
            Self::Sha512Salted { salt, hash } => {
                salted_digest_hex_eq(provider, LegacyDigest::Sha512, salt, raw, hash)
            }

            // Plaintext, still compared in constant time: how long the two
            // agree for is not something the answer should take longer to say.
            Self::Plain { plain } | Self::SpringNoop { plain } => Ok(ct_eq(plain.as_bytes(), raw)),

            // Not implemented here. Fails closed, never `Ok(true)`.
            Self::Scrypt { .. }
            | Self::ScryptKc { .. }
            | Self::SpringScrypt { .. }
            | Self::PhpassPortable { .. }
            | Self::Drupal8Plus { .. }
            | Self::Magento2 { .. }
            | Self::Custom { .. } => Err(CryptoError::UnsupportedAlgorithm),
        }
    }

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

/// The shortest stored PBKDF2 hash worth comparing against.
///
/// The derived length is taken from the stored hash, so a degenerate record
/// weakens the check itself: an empty hash derives zero bytes and compares
/// equal to zero bytes, which lets every password through. One byte is barely
/// better. No real format stores fewer than twenty, so a 128-bit floor rejects
/// only what is corrupt or hostile.
const MIN_PBKDF2_HASH_LEN: usize = 16;

/// The most PBKDF2 iterations a stored record may ask for.
///
/// The count comes out of the record, which came from an import. Measured here,
/// PBKDF2-HMAC-SHA256 runs a million iterations in about 120 ms, so a record
/// naming `u32::MAX` would hold a worker for nine minutes — per login attempt,
/// on a password that need not even be correct. Ten million is an order of
/// magnitude above any real default and still bounded.
const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;

fn b64(text: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(text.as_bytes())
        .map_err(|_| CryptoError::InvalidParams)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pbkdf2_check(
    provider: &dyn CryptoProvider,
    alg: HashAlg,
    password: &SecretBox<String>,
    salt: &[u8],
    iterations: u32,
    expected: &[u8],
) -> Result<bool> {
    // Both checks come before the derivation, so a hostile record never reaches
    // the work it was written to cause.
    if expected.len() < MIN_PBKDF2_HASH_LEN || iterations == 0 {
        return Err(CryptoError::InvalidParams);
    }
    if iterations > MAX_PBKDF2_ITERATIONS {
        return Err(CryptoError::InvalidParams);
    }

    let derived = provider
        .kdf()
        .pbkdf2_hmac(alg, password, salt, iterations, expected.len())?;

    Ok(ct_eq(derived.expose_secret(), expected))
}

fn digest_hex_eq(
    provider: &dyn CryptoProvider,
    alg: LegacyDigest,
    data: &[u8],
    expected_hex: &str,
) -> Result<bool> {
    // Permissive about case, because historic exports mix it, and strict about
    // everything else: a corrupt field becomes an error rather than a match.
    let expected = HEXLOWER_PERMISSIVE
        .decode(expected_hex.as_bytes())
        .map_err(|_| CryptoError::InvalidParams)?;

    Ok(ct_eq(
        &provider.legacy_digest().digest(alg, data)?,
        &expected,
    ))
}

fn salted_digest_hex_eq(
    provider: &dyn CryptoProvider,
    alg: LegacyDigest,
    salt: &str,
    password: &[u8],
    expected_hex: &str,
) -> Result<bool> {
    let mut input = Vec::with_capacity(salt.len() + password.len());
    input.extend_from_slice(salt.as_bytes());
    input.extend_from_slice(password);

    digest_hex_eq(provider, alg, &input, expected_hex)
}

/// ASP.NET Identity v2: `[0x00] salt(16) subkey(32)`, PBKDF2-HMAC-SHA1 at 1000
/// iterations. Every length is fixed by the format, so they are checked before
/// anything is indexed.
fn aspnet_v2(
    provider: &dyn CryptoProvider,
    password: &SecretBox<String>,
    binary: &[u8],
) -> Result<bool> {
    if binary.len() != 1 + 16 + 32 || binary[0] != 0x00 {
        return Err(CryptoError::InvalidParams);
    }

    pbkdf2_check(
        provider,
        HashAlg::Sha1,
        password,
        &binary[1..17],
        1000,
        &binary[17..49],
    )
}

/// ASP.NET Identity v3: `[0x01] prf(u32) iterations(u32) saltLen(u32) salt
/// subkey`, big-endian, with prf 0=SHA-1, 1=SHA-256, 2=SHA-512.
///
/// `saltLen` and `iterations` both come out of the blob, so both are bounded
/// before use: the length against the buffer that actually exists, with a
/// checked addition rather than a note about pointer width, and the iteration
/// count by `pbkdf2_check`.
fn aspnet_v3(
    provider: &dyn CryptoProvider,
    password: &SecretBox<String>,
    binary: &[u8],
) -> Result<bool> {
    if binary.len() < 13 || binary[0] != 0x01 {
        return Err(CryptoError::InvalidParams);
    }

    let be = |at: usize| {
        u32::from_be_bytes([binary[at], binary[at + 1], binary[at + 2], binary[at + 3]])
    };
    let (prf, iterations, salt_len) = (be(1), be(5), be(9) as usize);

    let salt_start = 13usize;
    let subkey_start = salt_start
        .checked_add(salt_len)
        .ok_or(CryptoError::InvalidParams)?;
    if binary.len() <= subkey_start {
        return Err(CryptoError::InvalidParams);
    }

    let alg = match prf {
        0 => HashAlg::Sha1,
        1 => HashAlg::Sha256,
        2 => HashAlg::Sha512,
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    };

    pbkdf2_check(
        provider,
        alg,
        password,
        &binary[salt_start..subkey_start],
        iterations,
        &binary[subkey_start..],
    )
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

    use crate::provider::openssl::OpenSslProvider;
    use crate::provider::{CryptoConfig, CryptoProvider};

    const PASSWORD: &str = "correct horse";

    fn provider() -> OpenSslProvider {
        OpenSslProvider::new(&CryptoConfig::default()).unwrap()
    }

    fn secret(text: &str) -> SecretBox<String> {
        SecretBox::new(Box::new(text.to_string()))
    }

    fn derive(p: &OpenSslProvider, alg: HashAlg, salt: &[u8], iterations: u32) -> Vec<u8> {
        p.kdf()
            .pbkdf2_hmac(alg, &secret(PASSWORD), salt, iterations, alg.output_len())
            .unwrap()
            .expose_secret()
            .clone()
    }

    fn digest_of(p: &OpenSslProvider, alg: LegacyDigest, data: &[u8]) -> String {
        hex_lower(&p.legacy_digest().digest(alg, data).unwrap())
    }

    /// One valid credential for `PASSWORD` in every format that can be checked.
    ///
    /// Each is built here from the primitives rather than pasted, so a match
    /// means the reading path agrees with an independently written one — not
    /// that it agrees with a string somebody once copied out of a bug report.
    fn verifiable(p: &OpenSslProvider) -> Vec<(&'static str, LegacyHash)> {
        let salt = b"saltsalt12345678";
        let b64 = |bytes: &[u8]| BASE64.encode(bytes);
        let argon2 = p
            .password()
            .hash(&secret(PASSWORD), Argon2Params::default())
            .unwrap();
        let bcrypt = bcrypt::hash(PASSWORD, 4).unwrap();

        vec![
            (
                "argon2id",
                LegacyHash::Argon2id {
                    encoded: argon2.clone(),
                },
            ),
            (
                "django_argon2",
                LegacyHash::DjangoArgon2 {
                    encoded: argon2.clone(),
                },
            ),
            (
                "spring_argon2",
                LegacyHash::SpringArgon2 { encoded: argon2 },
            ),
            (
                "bcrypt",
                LegacyHash::Bcrypt {
                    hash: bcrypt.clone(),
                },
            ),
            (
                "bcrypt_variant",
                LegacyHash::BcryptVariant {
                    variant: 'b',
                    hash: bcrypt.clone(),
                },
            ),
            (
                "spring_bcrypt",
                LegacyHash::SpringBcrypt {
                    hash: bcrypt.clone(),
                },
            ),
            (
                "auth0_bcrypt",
                LegacyHash::Auth0Bcrypt {
                    hash: bcrypt.clone(),
                },
            ),
            (
                "php_password_hash",
                LegacyHash::PhpPasswordHash { encoded: bcrypt },
            ),
            (
                "django_bcrypt_sha256",
                LegacyHash::DjangoBcryptSha256 {
                    encoded: bcrypt::hash(
                        digest_of(p, LegacyDigest::Sha256, PASSWORD.as_bytes()),
                        4,
                    )
                    .unwrap(),
                },
            ),
            (
                "pbkdf2_hmac_sha1",
                LegacyHash::Pbkdf2HmacSha1 {
                    iterations: 1000,
                    salt: b64(salt),
                    hash: b64(&derive(p, HashAlg::Sha1, salt, 1000)),
                },
            ),
            (
                "pbkdf2_hmac_sha256",
                LegacyHash::Pbkdf2HmacSha256 {
                    iterations: 1000,
                    salt: b64(salt),
                    hash: b64(&derive(p, HashAlg::Sha256, salt, 1000)),
                },
            ),
            (
                "pbkdf2_hmac_sha512",
                LegacyHash::Pbkdf2HmacSha512 {
                    iterations: 1000,
                    salt: b64(salt),
                    hash: b64(&derive(p, HashAlg::Sha512, salt, 1000)),
                },
            ),
            (
                "django_pbkdf2_sha256",
                LegacyHash::DjangoPbkdf2Sha256 {
                    iterations: 1000,
                    salt: "plainsalt".to_string(),
                    hash: b64(&derive(p, HashAlg::Sha256, b"plainsalt", 1000)),
                },
            ),
            (
                "django_pbkdf2_sha1",
                LegacyHash::DjangoPbkdf2Sha1 {
                    iterations: 1000,
                    salt: "plainsalt".to_string(),
                    hash: b64(&derive(p, HashAlg::Sha1, b"plainsalt", 1000)),
                },
            ),
            (
                "keycloak_pbkdf2",
                LegacyHash::KeycloakPbkdf2 {
                    variant: "PBKDF2WithHmacSHA512".to_string(),
                    iterations: 1000,
                    salt: b64(salt),
                    hash: b64(&derive(p, HashAlg::Sha512, salt, 1000)),
                },
            ),
            (
                "asp_net_identity_v2",
                LegacyHash::AspNetIdentityV2 {
                    binary: {
                        let mut blob = vec![0x00];
                        blob.extend_from_slice(salt);
                        blob.extend_from_slice(
                            &p.kdf()
                                .pbkdf2_hmac(HashAlg::Sha1, &secret(PASSWORD), salt, 1000, 32)
                                .unwrap()
                                .expose_secret()
                                .clone(),
                        );
                        blob
                    },
                },
            ),
            (
                "asp_net_identity_v3",
                LegacyHash::AspNetIdentityV3 {
                    binary: {
                        let mut blob = vec![0x01];
                        blob.extend_from_slice(&1u32.to_be_bytes());
                        blob.extend_from_slice(&1000u32.to_be_bytes());
                        blob.extend_from_slice(&(salt.len() as u32).to_be_bytes());
                        blob.extend_from_slice(salt);
                        blob.extend_from_slice(&derive(p, HashAlg::Sha256, salt, 1000));
                        blob
                    },
                },
            ),
            (
                "md5",
                LegacyHash::Md5 {
                    hash: digest_of(p, LegacyDigest::Md5, PASSWORD.as_bytes()),
                },
            ),
            (
                "sha1",
                LegacyHash::Sha1 {
                    hash: digest_of(p, LegacyDigest::Sha1, PASSWORD.as_bytes()),
                },
            ),
            (
                "plain",
                LegacyHash::Plain {
                    plain: PASSWORD.to_string(),
                },
            ),
            (
                "spring_noop",
                LegacyHash::SpringNoop {
                    plain: PASSWORD.to_string(),
                },
            ),
        ]
    }

    /// Every checkable format accepts its own password and refuses others.
    #[test]
    fn every_supported_format_verifies_its_own_password() {
        let p = provider();

        for (name, hash) in verifiable(&p) {
            assert!(
                hash.verify(&p, &secret(PASSWORD)).unwrap(),
                "{name} refused its own password"
            );

            for wrong in ["correct hors", "correct horse ", "", "Correct Horse"] {
                assert!(
                    !hash.verify(&p, &secret(wrong)).unwrap(),
                    "{name} accepted {wrong:?}"
                );
            }
        }
    }

    /// Salted digests hash `salt || password`, in that order.
    ///
    /// Nothing in the stored record says which convention it came from, so the
    /// one this crate implements has to be pinned by a test rather than left to
    /// whoever reads the code next.
    #[test]
    fn salted_digests_hash_the_salt_first() {
        let p = provider();
        let salt = "s4lt";

        for (alg, build) in [
            (
                LegacyDigest::Md5,
                (|salt: String, hash: String| LegacyHash::Md5Salted { salt, hash })
                    as fn(String, String) -> LegacyHash,
            ),
            (LegacyDigest::Sha1, |salt, hash| LegacyHash::Sha1Salted {
                salt,
                hash,
            }),
            (LegacyDigest::Sha256, |salt, hash| {
                LegacyHash::Sha256Salted { salt, hash }
            }),
            (LegacyDigest::Sha512, |salt, hash| {
                LegacyHash::Sha512Salted { salt, hash }
            }),
        ] {
            let salt_first = format!("{salt}{PASSWORD}");
            let hash = build(salt.to_string(), digest_of(&p, alg, salt_first.as_bytes()));
            assert!(hash.verify(&p, &secret(PASSWORD)).unwrap(), "{alg:?}");
            assert!(!hash.verify(&p, &secret("other")).unwrap(), "{alg:?}");

            // The other convention must not also pass, or the record's meaning
            // depends on which one is tried first.
            let password_first = format!("{PASSWORD}{salt}");
            let swapped = build(
                salt.to_string(),
                digest_of(&p, alg, password_first.as_bytes()),
            );
            assert!(
                !swapped.verify(&p, &secret(PASSWORD)).unwrap(),
                "{alg:?} accepted the password-first convention as well"
            );
        }
    }

    /// Hex is read whatever its case, and anything that is not hex is an error
    /// rather than a mismatch.
    #[test]
    fn a_stored_digest_is_read_case_insensitively() {
        let p = provider();
        let lower = digest_of(&p, LegacyDigest::Sha1, PASSWORD.as_bytes());

        let upper = LegacyHash::Sha1 {
            hash: lower.to_uppercase(),
        };
        assert!(upper.verify(&p, &secret(PASSWORD)).unwrap());

        for broken in ["", "zz", "nothex", &lower[..lower.len() - 1]] {
            let hash = LegacyHash::Sha1 {
                hash: broken.to_string(),
            };
            let outcome = hash.verify(&p, &secret(PASSWORD));
            assert!(
                !matches!(outcome, Ok(true)),
                "{broken:?} was read as a match"
            );
        }
    }

    /// Django's salt is text. Base64-decoding it gives other bytes, and every
    /// verification would fail — silently, and only for Django imports.
    #[test]
    fn the_django_salt_is_text_and_not_base64() {
        let p = provider();
        let salt = "abcdefgh";

        let as_text = LegacyHash::DjangoPbkdf2Sha256 {
            iterations: 1000,
            salt: salt.to_string(),
            hash: BASE64.encode(&derive(&p, HashAlg::Sha256, salt.as_bytes(), 1000)),
        };
        assert!(as_text.verify(&p, &secret(PASSWORD)).unwrap());

        // The same salt read as base64 is different bytes, so a record built
        // that way must not verify.
        let decoded = BASE64.decode(salt.as_bytes()).unwrap();
        assert_ne!(decoded, salt.as_bytes());
        let as_base64 = LegacyHash::DjangoPbkdf2Sha256 {
            iterations: 1000,
            salt: salt.to_string(),
            hash: BASE64.encode(&derive(&p, HashAlg::Sha256, &decoded, 1000)),
        };
        assert!(!as_base64.verify(&p, &secret(PASSWORD)).unwrap());
    }

    /// A record naming an absurd iteration count is refused before the work.
    #[test]
    fn an_unbounded_iteration_count_is_refused() {
        let p = provider();
        let salt = BASE64.encode(b"saltsalt12345678");
        let hash = BASE64.encode(&[0u8; 32]);

        for iterations in [0, MAX_PBKDF2_ITERATIONS + 1, u32::MAX] {
            let record = LegacyHash::Pbkdf2HmacSha256 {
                iterations,
                salt: salt.clone(),
                hash: hash.clone(),
            };

            let started = std::time::Instant::now();
            assert!(
                matches!(
                    record.verify(&p, &secret(PASSWORD)),
                    Err(CryptoError::InvalidParams)
                ),
                "{iterations} iterations was accepted"
            );
            assert!(
                started.elapsed() < std::time::Duration::from_millis(200),
                "{iterations} iterations was refused only after doing the work"
            );
        }
    }

    /// A stored hash too short to authenticate anything is refused.
    ///
    /// The derived length comes from the stored hash, so an empty one derives
    /// nothing and compares equal to nothing — every password would pass.
    #[test]
    fn a_degenerate_stored_hash_is_refused() {
        let p = provider();
        let salt = BASE64.encode(b"saltsalt12345678");

        for length in [0usize, 1, MIN_PBKDF2_HASH_LEN - 1] {
            let record = LegacyHash::Pbkdf2HmacSha256 {
                iterations: 1000,
                salt: salt.clone(),
                hash: BASE64.encode(&vec![0u8; length]),
            };
            assert!(
                matches!(
                    record.verify(&p, &secret(PASSWORD)),
                    Err(CryptoError::InvalidParams)
                ),
                "a {length}-byte stored hash was accepted"
            );
        }
    }

    /// An ASP.NET blob that lies about its own lengths is refused, not indexed.
    #[test]
    fn a_malformed_aspnet_blob_is_refused() {
        let p = provider();

        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("v2 empty", vec![]),
            ("v2 wrong marker", vec![0x02; 49]),
            ("v2 short", vec![0x00; 48]),
            ("v2 long", vec![0x00; 50]),
            ("v3 empty", vec![]),
            ("v3 header only", vec![0x01; 12]),
        ];

        // A salt length that runs past the buffer, and one that overflows a
        // pointer-sized addition.
        for declared in [0xFFFF_FFFFu32, 1000, 0] {
            let mut blob = vec![0x01];
            blob.extend_from_slice(&1u32.to_be_bytes());
            blob.extend_from_slice(&1000u32.to_be_bytes());
            blob.extend_from_slice(&declared.to_be_bytes());
            blob.extend_from_slice(b"saltsalt12345678");
            blob.extend_from_slice(&[0u8; 32]);
            cases.push(("v3 declared salt length", blob));
        }

        // An unknown PRF number.
        let mut unknown_prf = vec![0x01];
        unknown_prf.extend_from_slice(&9u32.to_be_bytes());
        unknown_prf.extend_from_slice(&1000u32.to_be_bytes());
        unknown_prf.extend_from_slice(&16u32.to_be_bytes());
        unknown_prf.extend_from_slice(b"saltsalt12345678");
        unknown_prf.extend_from_slice(&[0u8; 32]);
        cases.push(("v3 unknown prf", unknown_prf));

        for (what, binary) in cases {
            let hash = if what.starts_with("v2") {
                LegacyHash::AspNetIdentityV2 { binary }
            } else {
                LegacyHash::AspNetIdentityV3 { binary }
            };
            assert!(
                !matches!(hash.verify(&p, &secret(PASSWORD)), Ok(true)),
                "{what} verified"
            );
        }
    }

    /// A format this crate cannot check fails, and never reports a match.
    #[test]
    fn an_unsupported_format_never_reports_a_match() {
        let p = provider();
        let unsupported = [
            LegacyHash::Scrypt {
                n: 16384,
                r: 8,
                p: 1,
                salt: "s".into(),
                hash: "h".into(),
            },
            LegacyHash::ScryptKc {
                encoded: "x".into(),
            },
            LegacyHash::SpringScrypt {
                encoded: "x".into(),
            },
            LegacyHash::PhpassPortable {
                encoded: "x".into(),
            },
            LegacyHash::Drupal8Plus {
                encoded: "x".into(),
            },
            LegacyHash::Magento2 {
                encoded: "x".into(),
            },
            LegacyHash::Custom {
                verifier_id: "x".into(),
                encoded: "y".into(),
            },
        ];

        for hash in unsupported {
            assert!(
                matches!(
                    hash.verify(&p, &secret(PASSWORD)),
                    Err(CryptoError::UnsupportedAlgorithm)
                ),
                "{hash:?} did not fail closed"
            );
        }
    }

    /// Every variant in the catalogue is either checkable or explicitly not.
    ///
    /// Without this a variant added later would fall through both lists and be
    /// covered by neither test.
    #[test]
    fn the_catalogue_is_either_checkable_or_explicitly_not() {
        let p = provider();
        let checkable: Vec<&str> = verifiable(&p).into_iter().map(|(n, _)| n).collect();
        let salted_or_unsupported = [
            "md5_salted",
            "sha1_salted",
            "sha256_salted",
            "sha512_salted",
            "scrypt",
            "scrypt_kc",
            "spring_scrypt",
            "phpass_portable",
            "drupal8_plus",
            "magento2",
            "custom",
            "argon2i",
            "argon2d",
        ];

        for (name, _) in every_variant() {
            assert!(
                checkable.contains(&name) || salted_or_unsupported.contains(&name),
                "{name} is covered by no verification test"
            );
        }
    }
}
