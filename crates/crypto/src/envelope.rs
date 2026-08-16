//! Envelope encryption of secrets at rest, keyed per realm.
//!
//! The job is that a database dump taken without the KEK yields nothing usable.
//!
//! ```text
//!   KEK  one per deployment, never persisted
//!    |
//!    +-- wrap/unwrap --> DEK  one per realm per version, persisted WRAPPED
//!                         |
//!                         +-- seal/open --> the stored blob
//! ```
//!
//! # What is here and what is not
//!
//! This is cryptography and knows nothing about storage — it sits below any
//! layer that could read a table. So it offers four primitives: mint a DEK,
//! wrap one, unwrap one, and seal or open a value under a DEK the caller
//! supplies. *Which* DEK belongs to a realm is a question for whatever owns the
//! table.
//!
//! That split is what makes the DEK a stored, rotatable, destroyable object
//! rather than a pure function of the KEK. Deriving `DEK = HKDF(KEK, realm)`
//! needs no table and is wrong three ways that only surface on the day they
//! matter: rotating the KEK would mean re-encrypting every ciphertext instead
//! of rewriting one row per realm, one realm's key could not be destroyed
//! without destroying every realm's, and the KEK could never move into a
//! hardware token, since the derivation would have to run there too.
//!
//! # The wire format
//!
//! ```text
//!   "SAF1"        4 bytes   magic and version of this layout
//!   dek_version   4 bytes   big-endian; which DEK generation sealed it
//!   nonce        12 bytes   fresh per seal, from the CSPRNG
//!   ciphertext            includes the GCM tag
//! ```
//!
//! The `dek_version` lets a retired DEK keep opening what it sealed while that
//! ciphertext is progressively re-sealed under a newer one, so a reader never
//! guesses which key to use. The magic tells a sealed blob from a value written
//! before any of this existed — enabling encryption otherwise needs a migration
//! that rewrites every row before the first read, which is unrecoverable if it
//! half-applies.
//!
//! # Why the scope is authenticated
//!
//! The tenant, realm, purpose and row identity go into the additional
//! authenticated data. The DEK alone already stops a blob opening under another
//! realm, but it would leave a sealed value free to move *within* one: one
//! signing key's blob pasted over another key's row would still open. Binding
//! the scope makes every ciphertext openable in exactly one place.

use std::sync::Arc;

use secrecy::{ExposeSecret, SecretBox};

use crate::provider::{AeadAlg, CryptoError, CryptoProvider, HashAlg, HmacAlg, Result};
use crate::secret::{Dek, KeyWrappingKey};

/// Magic and layout version. A reader that does not recognise the version
/// refuses the blob rather than trying to parse it.
const MAGIC: &[u8; 4] = b"SAF1";

/// The prefix shared by every version of this format, which tells "a sealed
/// blob I cannot read" from "a value written before sealing existed". Those are
/// very different situations and must not be confused.
const MAGIC_FAMILY: &[u8; 3] = b"SAF";

/// AES-GCM nonce length; 96 bits is what GCM is specified for.
const NONCE_LEN: usize = 12;

/// Big-endian u32.
const VERSION_LEN: usize = 4;

/// Offset of the nonce: magic, then the DEK version.
const HEADER_LEN: usize = MAGIC.len() + VERSION_LEN;

/// AES-256, so a 32-byte DEK.
pub const DEK_LEN: usize = 32;

/// Shortest KEK accepted.
///
/// The KEK is stretched by HKDF, which makes a passphrase-shaped input usable
/// but adds no entropy to it. Refusing only the empty string would accept `"a"`,
/// which produces a perfectly working cipher with nothing behind it.
const MIN_KEK_LEN: usize = 16;

/// Domain separation for wrapping. The KEK does exactly two things — wrap DEKs
/// and identify itself — and they must not share a derived key.
const WRAP_INFO: &[u8] = b"saffui/kek-wrap/v1";

/// The label whose MAC under the KEK is the KEK's public fingerprint.
const KEK_ID_LABEL: &[u8] = b"saffui/kek-id/v1";

/// A data encryption key and the generation it belongs to.
///
/// Carries its version because every seal stamps it into the header, and a DEK
/// separated from its version produces blobs nothing can open.
pub struct RealmDek {
    pub version: u32,
    /// Typed, so a key that wraps DEKs cannot be put here and used to seal a
    /// value. Both are 32 secret bytes and the swap produces ciphertext that
    /// opens under nothing.
    pub key: Dek,
}

impl std::fmt::Debug for RealmDek {
    /// Renders the version and never the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealmDek")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Which secret, in which realm, a ciphertext belongs to.
///
/// Every field is authenticated. `purpose` separates kinds of secret that share
/// a realm — a signing key from a client secret — and `id` names the row, so two
/// secrets of the same kind in one realm cannot be swapped for one another.
#[derive(Debug, Clone, Copy)]
pub struct SecretScope<'a> {
    pub tenant: &'a str,
    pub realm_id: &'a str,
    pub purpose: &'a str,
    pub id: &'a str,
}

impl SecretScope<'_> {
    /// The additional authenticated data: the scope, encoded so that only one
    /// scope produces it.
    ///
    /// Each field carries its length rather than a separator. A separator needs
    /// a byte that cannot occur in any field, and `&str` can hold every byte
    /// including NUL — so `("ab", "c")` and `("a", "bc")` would encode
    /// identically, which is precisely the confusion the scope exists to
    /// prevent. A length prefix needs no such assumption.
    fn aad(&self) -> Vec<u8> {
        let fields = [self.tenant, self.realm_id, self.purpose, self.id];
        let mut aad = Vec::with_capacity(
            MAGIC.len() + fields.iter().map(|f| f.len() + VERSION_LEN).sum::<usize>(),
        );

        aad.extend_from_slice(MAGIC);
        for field in fields {
            aad.extend_from_slice(&(field.len() as u32).to_be_bytes());
            aad.extend_from_slice(field.as_bytes());
        }
        aad
    }
}

/// The envelope operations, over a deployment KEK.
///
/// Holds the KEK and nothing else: no realm state, no cache, no storage.
pub struct Envelope {
    crypto: Arc<dyn CryptoProvider>,
    kek: SecretBox<Vec<u8>>,
}

impl std::fmt::Debug for Envelope {
    /// Never renders the KEK. A derived `Debug` would put deployment key
    /// material into any log line that formatted a struct holding one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope").finish_non_exhaustive()
    }
}

impl Envelope {
    /// Build from a deployment KEK.
    ///
    /// The KEK is whatever the operator mounted, so it goes through HKDF rather
    /// than being used raw: the extract step is what makes a passphrase-shaped
    /// input acceptable, and demanding exactly 32 random bytes would push
    /// operators towards pasting base64 into an environment variable.
    pub fn new(crypto: Arc<dyn CryptoProvider>, kek: &str) -> Result<Self> {
        if kek.len() < MIN_KEK_LEN {
            return Err(CryptoError::InvalidKey);
        }

        Ok(Self {
            crypto,
            kek: SecretBox::new(Box::new(kek.as_bytes().to_vec())),
        })
    }

    /// A stable, non-secret identifier for this KEK.
    ///
    /// A MAC of a fixed label under the KEK. It names the key without revealing
    /// it, which is what makes rotation an operation rather than a guess: a
    /// stored row whose fingerprint does not match the running KEK was wrapped
    /// by a different one, and that can be reported exactly instead of arriving
    /// as an unexplained decryption failure. It also makes a half-finished
    /// rotation resumable, since the rows left to re-wrap are precisely the
    /// ones whose fingerprint is stale.
    pub fn kek_id(&self) -> Result<String> {
        let tag = self
            .crypto
            .hmac()
            .hmac(HmacAlg::Hs256, &self.kek, KEK_ID_LABEL)?;

        Ok(tag.iter().take(16).map(|b| format!("{b:02x}")).collect())
    }

    /// The key-wrapping key: HKDF of the KEK under a fixed label.
    ///
    /// Derived separately from the fingerprint so that publishing `kek_id` says
    /// nothing about the key that actually wraps DEKs.
    fn wrapping_key(&self) -> Result<KeyWrappingKey> {
        let derived =
            self.crypto
                .kdf()
                .hkdf(HashAlg::Sha256, &self.kek, None, WRAP_INFO, DEK_LEN)?;

        Ok(KeyWrappingKey::new(derived.expose_secret().clone()))
    }

    /// Mint a fresh DEK for `version`.
    pub fn generate_dek(&self, version: u32) -> Result<RealmDek> {
        let mut key = vec![0u8; DEK_LEN];
        self.crypto.rand().fill(&mut key)?;

        Ok(RealmDek {
            version,
            key: Dek::new(key),
        })
    }

    /// Encrypt a DEK under the KEK, for storage.
    ///
    /// Scoped through the same authenticated machinery as any other secret, so
    /// a wrapped DEK lifted from one realm's row into another's will not
    /// unwrap.
    pub fn wrap_dek(&self, scope: &SecretScope<'_>, dek: &RealmDek) -> Result<Vec<u8>> {
        self.seal_with(
            self.wrapping_key()?.secret(),
            dek.version,
            scope,
            dek.key.expose(),
        )
    }

    /// Recover a DEK from its stored form.
    pub fn unwrap_dek(
        &self,
        scope: &SecretScope<'_>,
        version: u32,
        wrapped: &[u8],
    ) -> Result<RealmDek> {
        let key = self.open_with(self.wrapping_key()?.secret(), version, scope, wrapped)?;

        // A DEK of the wrong width would fail later, inside AES, as an opaque
        // operation failure. It is a malformed key and says so here.
        if key.expose_secret().len() != DEK_LEN {
            return Err(CryptoError::InvalidKey);
        }

        Ok(RealmDek {
            version,
            key: Dek::new(key.expose_secret().clone()),
        })
    }

    /// Encrypt `plaintext` for `scope` under `dek`.
    pub fn seal(
        &self,
        dek: &RealmDek,
        scope: &SecretScope<'_>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        self.seal_with(dek.key.secret(), dek.version, scope, plaintext)
    }

    /// Decrypt a blob sealed for the same scope under the same DEK generation.
    pub fn open(
        &self,
        dek: &RealmDek,
        scope: &SecretScope<'_>,
        sealed: &[u8],
    ) -> Result<SecretBox<Vec<u8>>> {
        self.open_with(dek.key.secret(), dek.version, scope, sealed)
    }

    /// The shared sealing routine, over any key of the right width.
    ///
    /// The nonce is drawn fresh per call. GCM fails catastrophically on nonce
    /// reuse under one key — two messages under one nonce leak their XOR and
    /// the authentication key — and a DEK is stable for a realm's lifetime, so
    /// the nonce is the only thing keeping its messages apart. It must never
    /// come from the plaintext, or from a counter that could restart.
    fn seal_with(
        &self,
        key: &SecretBox<Vec<u8>>,
        version: u32,
        scope: &SecretScope<'_>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        self.crypto.rand().fill(&mut nonce)?;

        let ciphertext =
            self.crypto
                .aead()
                .encrypt(AeadAlg::A256Gcm, key, &nonce, &scope.aad(), plaintext)?;

        let mut sealed = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(MAGIC);
        sealed.extend_from_slice(&version.to_be_bytes());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);

        Ok(sealed)
    }

    /// The shared opening routine. Total: every malformed input is an error.
    fn open_with(
        &self,
        key: &SecretBox<Vec<u8>>,
        version: u32,
        scope: &SecretScope<'_>,
        sealed: &[u8],
    ) -> Result<SecretBox<Vec<u8>>> {
        // The generation is checked here rather than left to GCM. A caller that
        // fetched the wrong DEK made a mistake worth naming; letting the tag
        // fail would report it as corruption.
        if dek_version(sealed) != Some(version) {
            return Err(CryptoError::InvalidKey);
        }

        // Shorter than its own header: slicing would panic rather than fail.
        if sealed.len() < HEADER_LEN + NONCE_LEN {
            return Err(CryptoError::InvalidKey);
        }

        let nonce = &sealed[HEADER_LEN..HEADER_LEN + NONCE_LEN];
        let ciphertext = &sealed[HEADER_LEN + NONCE_LEN..];

        let plaintext =
            self.crypto
                .aead()
                .decrypt(AeadAlg::A256Gcm, key, nonce, &scope.aad(), ciphertext)?;

        Ok(SecretBox::new(Box::new(plaintext)))
    }
}

/// Whether a stored value is a sealed blob of the layout this module writes.
pub fn is_sealed(stored: &[u8]) -> bool {
    stored.starts_with(MAGIC)
}

/// Whether a stored value claims to be sealed in *some* version of this format.
///
/// Distinct from [`is_sealed`] on purpose. A blob from a future version has to
/// be refused loudly, never mistaken for a value written before sealing existed
/// and handed back as though it were a private key — which is what a caller
/// asking only "is this my exact version" would do after a downgrade.
pub fn is_sealed_any_version(stored: &[u8]) -> bool {
    stored.starts_with(MAGIC_FAMILY)
}

/// The DEK generation a blob was sealed under, if it is one.
///
/// Read before any key is fetched: the header says which DEK to ask for, so a
/// retired generation still opens what it sealed.
pub fn dek_version(sealed: &[u8]) -> Option<u32> {
    if !is_sealed(sealed) || sealed.len() < HEADER_LEN {
        return None;
    }

    sealed[MAGIC.len()..HEADER_LEN]
        .try_into()
        .ok()
        .map(u32::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::provider::CryptoConfig;
    use crate::provider::openssl::OpenSslProvider;

    const KEK: &str = "a deployment key encryption key";

    fn envelope() -> Envelope {
        let provider = Arc::new(OpenSslProvider::new(&CryptoConfig::default()).unwrap());
        Envelope::new(provider, KEK).unwrap()
    }

    fn scope() -> SecretScope<'static> {
        SecretScope {
            tenant: "acme",
            realm_id: "main",
            purpose: "signing-key",
            id: "kid-1",
        }
    }

    /// A value sealed for a scope opens for that scope and comes back whole.
    #[test]
    fn a_sealed_value_opens_where_it_was_sealed() {
        let envelope = envelope();
        let dek = envelope.generate_dek(1).unwrap();

        for plaintext in [
            &b""[..],
            b"x",
            b"a private key, more or less",
            &[0xff; 4096],
        ] {
            let sealed = envelope.seal(&dek, &scope(), plaintext).unwrap();

            assert!(is_sealed(&sealed));
            assert_eq!(dek_version(&sealed), Some(1));
            assert_ne!(&sealed[HEADER_LEN + NONCE_LEN..], plaintext);

            let opened = envelope.open(&dek, &scope(), &sealed).unwrap();
            assert_eq!(opened.expose_secret().as_slice(), plaintext);
        }
    }

    /// The nonce is drawn per seal, so one value sealed twice is two blobs.
    ///
    /// A DEK lives as long as its realm, so the nonce is the only thing keeping
    /// its messages apart: a repeat leaks the XOR of two plaintexts and the
    /// authentication key with it.
    #[test]
    fn the_nonce_is_drawn_for_every_seal() {
        let envelope = envelope();
        let dek = envelope.generate_dek(1).unwrap();

        let first = envelope.seal(&dek, &scope(), b"payload").unwrap();
        let second = envelope.seal(&dek, &scope(), b"payload").unwrap();

        assert_ne!(first, second);
        assert_ne!(
            first[HEADER_LEN..HEADER_LEN + NONCE_LEN],
            second[HEADER_LEN..HEADER_LEN + NONCE_LEN]
        );
    }

    /// A blob opens in exactly one place: change any part of the scope and it
    /// does not.
    #[test]
    fn a_blob_moved_anywhere_else_does_not_open() {
        let envelope = envelope();
        let dek = envelope.generate_dek(1).unwrap();
        let sealed = envelope.seal(&dek, &scope(), b"payload").unwrap();

        let elsewhere = [
            SecretScope {
                tenant: "other",
                ..scope()
            },
            SecretScope {
                realm_id: "other",
                ..scope()
            },
            SecretScope {
                purpose: "client-secret",
                ..scope()
            },
            SecretScope {
                id: "kid-2",
                ..scope()
            },
        ];

        for moved in elsewhere {
            assert!(
                envelope.open(&dek, &moved, &sealed).is_err(),
                "opened under {moved:?}"
            );
        }
    }

    /// Two scopes that differ only in where one field ends do not share an AAD.
    ///
    /// A separator-based encoding needs a byte no field can contain, and `&str`
    /// can hold every byte there is — including the NUL such an encoding would
    /// pick. Splitting the same characters differently would then produce the
    /// same authenticated data, and a blob would open in a place it was never
    /// sealed for.
    #[test]
    fn scopes_that_split_the_same_characters_differently_are_distinct() {
        let envelope = envelope();
        let dek = envelope.generate_dek(1).unwrap();

        let cases = [
            (
                SecretScope {
                    tenant: "ab",
                    realm_id: "c",
                    purpose: "p",
                    id: "i",
                },
                SecretScope {
                    tenant: "a",
                    realm_id: "bc",
                    purpose: "p",
                    id: "i",
                },
            ),
            // The byte a separator scheme would rely on, inside a field.
            (
                SecretScope {
                    tenant: "a\0b",
                    realm_id: "c",
                    purpose: "p",
                    id: "i",
                },
                SecretScope {
                    tenant: "a",
                    realm_id: "b\0c",
                    purpose: "p",
                    id: "i",
                },
            ),
        ];

        for (one, other) in cases {
            assert_ne!(one.aad(), other.aad(), "{one:?} and {other:?} share an AAD");

            let sealed = envelope.seal(&dek, &one, b"payload").unwrap();
            assert!(
                envelope.open(&dek, &other, &sealed).is_err(),
                "{other:?} opened a blob sealed for {one:?}"
            );
        }
    }

    /// Another DEK, or another generation of the same one, does not open it.
    #[test]
    fn another_key_or_generation_does_not_open_it() {
        let envelope = envelope();
        let first = envelope.generate_dek(1).unwrap();
        let sealed = envelope.seal(&first, &scope(), b"payload").unwrap();

        let other = envelope.generate_dek(1).unwrap();
        assert!(envelope.open(&other, &scope(), &sealed).is_err());

        // Right key material, wrong generation: named here rather than left to
        // surface as a tag failure.
        let renumbered = RealmDek {
            version: 2,
            key: Dek::new(first.key.expose().to_vec()),
        };
        assert!(matches!(
            envelope.open(&renumbered, &scope(), &sealed),
            Err(CryptoError::InvalidKey)
        ));
    }

    /// A retired generation still opens what it sealed, which is what makes a
    /// rotation something other than an outage.
    #[test]
    fn a_retired_generation_still_opens_its_own_blobs() {
        let envelope = envelope();
        let old = envelope.generate_dek(1).unwrap();
        let new = envelope.generate_dek(2).unwrap();

        let old_blob = envelope.seal(&old, &scope(), b"payload").unwrap();
        let new_blob = envelope.seal(&new, &scope(), b"payload").unwrap();

        assert_eq!(dek_version(&old_blob), Some(1));
        assert_eq!(dek_version(&new_blob), Some(2));
        assert_eq!(
            envelope
                .open(&old, &scope(), &old_blob)
                .unwrap()
                .expose_secret()
                .as_slice(),
            b"payload"
        );
        assert_eq!(
            envelope
                .open(&new, &scope(), &new_blob)
                .unwrap()
                .expose_secret()
                .as_slice(),
            b"payload"
        );
    }

    /// A DEK survives a round trip through its stored form, and only under the
    /// realm it belongs to.
    #[test]
    fn a_wrapped_dek_comes_back_only_in_its_own_realm() {
        let envelope = envelope();
        let dek = envelope.generate_dek(7).unwrap();
        let wrapped = envelope.wrap_dek(&scope(), &dek).unwrap();

        let back = envelope.unwrap_dek(&scope(), 7, &wrapped).unwrap();
        assert_eq!(back.version, 7);
        assert_eq!(back.key.expose(), dek.key.expose());

        // The unwrapped DEK is the working key, not merely equal bytes.
        let sealed = envelope.seal(&dek, &scope(), b"payload").unwrap();
        assert_eq!(
            envelope
                .open(&back, &scope(), &sealed)
                .unwrap()
                .expose_secret()
                .as_slice(),
            b"payload"
        );

        let stolen = SecretScope {
            realm_id: "other",
            ..scope()
        };
        assert!(envelope.unwrap_dek(&stolen, 7, &wrapped).is_err());
        assert!(envelope.unwrap_dek(&scope(), 8, &wrapped).is_err());
    }

    /// A different KEK unwraps nothing, and says so by its fingerprint first.
    #[test]
    fn a_different_kek_is_visible_before_it_fails() {
        let provider = Arc::new(OpenSslProvider::new(&CryptoConfig::default()).unwrap());
        let mine = Envelope::new(provider.clone(), KEK).unwrap();
        let theirs = Envelope::new(provider, "a different deployment key").unwrap();

        assert_ne!(mine.kek_id().unwrap(), theirs.kek_id().unwrap());
        assert_eq!(mine.kek_id().unwrap(), mine.kek_id().unwrap());
        assert_eq!(mine.kek_id().unwrap().len(), 32);

        let dek = mine.generate_dek(1).unwrap();
        let wrapped = mine.wrap_dek(&scope(), &dek).unwrap();
        assert!(theirs.unwrap_dek(&scope(), 1, &wrapped).is_err());
    }

    /// The wrapping key is derived under its own label, and stays there.
    ///
    /// The label is part of the on-disk contract: derive under a different one
    /// and every wrapped DEK already stored becomes unopenable. It is also what
    /// keeps the KEK's two jobs apart, so publishing the fingerprint says
    /// nothing about the key that actually wraps.
    #[test]
    fn the_wrapping_key_is_derived_under_its_own_label() {
        let envelope = envelope();
        let wrapping = envelope.wrapping_key().unwrap();

        let expected = envelope
            .crypto
            .kdf()
            .hkdf(HashAlg::Sha256, &envelope.kek, None, WRAP_INFO, DEK_LEN)
            .unwrap();
        assert_eq!(wrapping.expose(), expected.expose_secret().as_slice());

        let under_the_other_label = envelope
            .crypto
            .kdf()
            .hkdf(HashAlg::Sha256, &envelope.kek, None, KEK_ID_LABEL, DEK_LEN)
            .unwrap();
        assert_ne!(
            wrapping.expose(),
            under_the_other_label.expose_secret().as_slice(),
            "the KEK's two uses share a derivation"
        );

        assert_ne!(hex(wrapping.expose()), hex(envelope.kek.expose_secret()));
        assert!(!hex(wrapping.expose()).contains(&envelope.kek_id().unwrap()));
    }

    /// A stored DEK of the wrong width is refused when it is unwrapped.
    ///
    /// It would otherwise fail later inside AES, as an opaque operation
    /// failure on every seal the realm attempts, rather than at the one place
    /// that knows what a DEK is.
    #[test]
    fn a_stored_dek_of_the_wrong_width_is_refused() {
        let envelope = envelope();
        let wrapping = envelope.wrapping_key().unwrap();

        for width in [0usize, 16, 31, 33, 64] {
            let wrapped = envelope
                .seal_with(wrapping.secret(), 1, &scope(), &vec![0x5a; width])
                .unwrap();

            assert!(
                matches!(
                    envelope.unwrap_dek(&scope(), 1, &wrapped),
                    Err(CryptoError::InvalidKey)
                ),
                "a {width}-byte DEK was accepted"
            );
        }

        // The right width still works, so the check rejects only the wrong one.
        let good = envelope
            .seal_with(wrapping.secret(), 1, &scope(), &[0x5a; DEK_LEN])
            .unwrap();
        assert!(envelope.unwrap_dek(&scope(), 1, &good).is_ok());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Any change to a sealed blob stops it opening, and nothing malformed
    /// panics.
    #[test]
    fn a_blob_that_moved_at_all_is_refused() {
        let envelope = envelope();
        let dek = envelope.generate_dek(1).unwrap();
        let sealed = envelope.seal(&dek, &scope(), b"payload").unwrap();

        for position in 0..sealed.len() {
            let mut moved = sealed.clone();
            moved[position] ^= 1;
            assert!(
                envelope.open(&dek, &scope(), &moved).is_err(),
                "byte {position} could change freely"
            );
        }

        for end in 0..sealed.len() {
            assert!(envelope.open(&dek, &scope(), &sealed[..end]).is_err());
        }

        for junk in [&b""[..], b"SAF", b"SAF1", b"-----BEGIN", b"{}"] {
            assert!(envelope.open(&dek, &scope(), junk).is_err());
        }
    }

    /// The two probes answer different questions, and the difference is what
    /// stops a blob from a newer version being handed back as a plaintext.
    #[test]
    fn a_blob_from_another_version_is_not_mistaken_for_a_plain_value() {
        let envelope = envelope();
        let dek = envelope.generate_dek(1).unwrap();
        let sealed = envelope.seal(&dek, &scope(), b"payload").unwrap();

        assert!(is_sealed(&sealed) && is_sealed_any_version(&sealed));

        // What a later layout would look like to this build.
        let mut future = sealed.clone();
        future[3] = b'9';
        assert!(!is_sealed(&future), "read as this version");
        assert!(is_sealed_any_version(&future), "read as a plain value");
        assert_eq!(dek_version(&future), None);
        assert!(envelope.open(&dek, &scope(), &future).is_err());

        for plain in [
            &b""[..],
            b"-----BEGIN PRIVATE KEY-----",
            b"{\"kty\":\"RSA\"}",
        ] {
            assert!(!is_sealed(plain));
            assert!(!is_sealed_any_version(plain));
            assert_eq!(dek_version(plain), None);
        }
    }

    /// A KEK short enough to have no secret behind it is refused.
    #[test]
    fn a_kek_too_short_to_be_a_secret_is_refused() {
        let provider = Arc::new(OpenSslProvider::new(&CryptoConfig::default()).unwrap());

        for kek in ["", "a", "short"] {
            assert!(
                matches!(
                    Envelope::new(provider.clone(), kek),
                    Err(CryptoError::InvalidKey)
                ),
                "{kek:?} was accepted"
            );
        }

        assert!(Envelope::new(provider, &"k".repeat(MIN_KEK_LEN)).is_ok());
    }

    /// Neither the KEK nor a DEK can reach a log through a formatter.
    #[test]
    fn nothing_secret_renders() {
        let envelope = envelope();
        let dek = envelope.generate_dek(3).unwrap();

        let rendered = format!("{envelope:?} {dek:?}");
        assert!(rendered.contains("version: 3"));
        assert!(!rendered.contains(KEK));
        assert!(!rendered.contains(&hex(dek.key.expose())));
    }
}
