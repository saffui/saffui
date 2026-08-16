//! The `CryptoProvider` seam.
//!
//! Every crypto operation goes through one of the traits below, so the rest of
//! the workspace holds a trait object and never a backend type. Nothing in this
//! module names OpenSSL: an algorithm is an identifier here, and mapping it to
//! a cipher or a digest is the backend's job alone.
//!
//! The vendored JOSE layer is the standing exception. It calls OpenSSL
//! directly, and routing it through this seam would mean rewriting third-party
//! code we want to keep diffable against upstream (see THIRD-PARTY.md).

pub mod openssl;

use async_trait::async_trait;
use secrecy::SecretBox;
use thiserror::Error;

/// Result specialised to [`CryptoError`].
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Runtime configuration for building a provider.
///
/// Not `Clone`, and built once: it is meant to hold secret material as the
/// backend grows (an HSM PIN, a KMS credential), and those must not be copied.
#[derive(Debug, Default)]
pub struct CryptoConfig {
    /// Require the backend's FIPS mode. A build that asks for it and cannot get
    /// it fails rather than falling back.
    pub fips_required: bool,
}

/// Errors a provider surfaces.
///
/// Deliberately coarse: a caller learns that an operation failed, never which
/// step failed or on what byte. A finer error here is a padding oracle.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid key material")]
    InvalidKey,
    #[error("cryptographic operation failed")]
    OperationFailed,
    #[error("invalid parameters")]
    InvalidParams,
    #[error("key store operation failed")]
    KeyStore,
    #[error("FIPS mode not available despite config requirement")]
    FipsUnavailable,
    #[error("attestation is not supported by this key store")]
    AttestationUnsupported,
}

// Algorithm identifiers
//
// Names and sizes only. What digest or cipher implements them belongs to the
// backend, which is the whole point of this seam.

/// A message-digest algorithm.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashAlg {
    /// Digest length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }
}

/// An HMAC algorithm; the digest is what distinguishes them.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HmacAlg {
    Hs256,
    Hs384,
    Hs512,
}

impl HmacAlg {
    pub fn hash(self) -> HashAlg {
        match self {
            Self::Hs256 => HashAlg::Sha256,
            Self::Hs384 => HashAlg::Sha384,
            Self::Hs512 => HashAlg::Sha512,
        }
    }
}

/// An AEAD algorithm. ChaCha20-Poly1305 sits behind its feature because it is
/// not FIPS-validated.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AeadAlg {
    A128Gcm,
    A192Gcm,
    A256Gcm,
    #[cfg(feature = "chacha20")]
    ChaCha20Poly1305,
}

impl AeadAlg {
    /// Required key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Self::A128Gcm => 16,
            Self::A192Gcm => 24,
            Self::A256Gcm => 32,
            #[cfg(feature = "chacha20")]
            Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Nonce length in bytes; 12 for every AEAD here.
    pub fn nonce_len(self) -> usize {
        12
    }

    /// Authentication tag length in bytes; 16 for every AEAD here.
    pub fn tag_len(self) -> usize {
        16
    }
}

/// A signature algorithm, named as JWS `alg` values.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SignAlg {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    Es512,
    EdDsa,
}

impl SignAlg {
    /// The digest paired with this algorithm. `None` for EdDSA, which hashes
    /// internally and must not be pre-hashed.
    pub fn hash(self) -> Option<HashAlg> {
        match self {
            Self::Rs256 | Self::Ps256 | Self::Es256 => Some(HashAlg::Sha256),
            Self::Rs384 | Self::Ps384 | Self::Es384 => Some(HashAlg::Sha384),
            Self::Rs512 | Self::Ps512 | Self::Es512 => Some(HashAlg::Sha512),
            Self::EdDsa => None,
        }
    }

    /// Whether this algorithm uses RSASSA-PSS padding rather than PKCS#1 v1.5.
    pub fn is_pss(self) -> bool {
        matches!(self, Self::Ps256 | Self::Ps384 | Self::Ps512)
    }

    /// Whether this algorithm produces ECDSA signatures.
    pub fn is_ecdsa(self) -> bool {
        matches!(self, Self::Es256 | Self::Es384 | Self::Es512)
    }
}

// Key material

/// A private key, carried as DER so this module names no backend type.
///
/// The backend parses on use. That is a cost per operation, and it is what buys
/// a seam an OpenSSL type never crosses.
#[derive(Clone)]
pub struct PrivateKey(Vec<u8>);

impl PrivateKey {
    /// From a PKCS#8 DER encoding.
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self {
        Self(der.into())
    }

    pub fn der(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A derived Debug would print the key into whatever log took it.
        f.write_str("PrivateKey(<redacted>)")
    }
}

/// A public key, carried as SubjectPublicKeyInfo DER.
#[derive(Clone, Debug)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self {
        Self(der.into())
    }

    pub fn der(&self) -> &[u8] {
        &self.0
    }
}

/// A reference to a key held by a [`KeyStoreProvider`].
///
/// One variant for now. A hardware store adds its own rather than reusing this
/// one, so a software id can never be mistaken for a slot handle.
#[derive(Debug, Clone)]
pub enum KeyHandle {
    Software { id: String },
}

/// What to generate when asking a store for a new key.
#[derive(Debug, Clone)]
pub struct KeyGenSpec {
    pub alg: SignAlg,
    /// Human-readable label, and the store's own label where it has one.
    pub label: String,
    /// Whether the private key may leave the store. A hardware store is free to
    /// refuse and always answer no.
    pub extractable: bool,
}

/// An opaque attestation blob from a store that can prove where a key lives.
#[derive(Debug, Clone)]
pub struct Attestation {
    /// Format identifier, so a caller knows how to read `data`.
    pub format: String,
    pub data: Vec<u8>,
}

/// The `OtherInfo` fields the NIST SP 800-56A concatenation KDF binds into the
/// derivation. Grouped rather than passed flat: they are one structure in the
/// specification, and ECDH-ES fills all four together.
#[derive(Debug, Clone, Default)]
pub struct ConcatKdfInfo<'a> {
    pub alg_id: &'a [u8],
    pub party_u: &'a [u8],
    pub party_v: &'a [u8],
    pub supp_pub: &'a [u8],
}

// Provider traits
//
// One trait per concern. A caller that only verifies a password does not get
// handed key derivation, and a caller deriving keys does not get password
// storage.

/// The provider itself: one accessor per primitive family.
pub trait CryptoProvider: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn is_fips_enabled(&self) -> bool;

    fn hmac(&self) -> &dyn HmacProvider;
    fn aead(&self) -> &dyn AeadProvider;
    fn signer(&self) -> &dyn SignerProvider;
    fn kdf(&self) -> &dyn KdfProvider;
    fn rand(&self) -> &dyn RandProvider;
    fn password(&self) -> &dyn PasswordProvider;
    fn key_store(&self) -> &dyn KeyStoreProvider;
    fn legacy_digest(&self) -> &dyn LegacyDigestProvider;
}

pub trait HmacProvider: Send + Sync {
    /// HMAC under a bare hash.
    ///
    /// `HmacAlg` names the three hashes JWS allows; HMAC itself is defined over
    /// any hash, and RFC 4226 one-time passwords are specified over SHA-1.
    /// Reaching SHA-1 only through here keeps it out of `HmacAlg`, where it
    /// would become selectable as a signature algorithm.
    fn hmac_with_hash(
        &self,
        hash: HashAlg,
        key: &SecretBox<Vec<u8>>,
        data: &[u8],
    ) -> Result<Vec<u8>>;

    fn hmac(&self, alg: HmacAlg, key: &SecretBox<Vec<u8>>, data: &[u8]) -> Result<Vec<u8>> {
        self.hmac_with_hash(alg.hash(), key, data)
    }

    /// Compares in constant time. A caller must not recompute and use `==`.
    fn verify(
        &self,
        alg: HmacAlg,
        key: &SecretBox<Vec<u8>>,
        data: &[u8],
        tag: &[u8],
    ) -> Result<bool>;
}

/// A digest that exists only to read a password format this crate inherited.
///
/// Deliberately not part of [`HashAlg`]. MD5 belongs on no path but this one,
/// and a type that cannot name it anywhere else says so more reliably than a
/// comment does. The overlap with `HashAlg` on SHA-1 and above is the price of
/// that, and a cheap one: these four are a fixed list that will only ever
/// shrink.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LegacyDigest {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

/// Bare digests, for reading legacy password formats and nothing else.
///
/// Under a FIPS build MD5 is not available and this reports the failure rather
/// than substituting anything. A credential that cannot be checked is a login
/// that fails, which is the correct outcome: the alternative is a FIPS
/// deployment quietly verifying passwords with a broken digest.
pub trait LegacyDigestProvider: Send + Sync {
    fn digest(&self, alg: LegacyDigest, data: &[u8]) -> Result<Vec<u8>>;
}

pub trait AeadProvider: Send + Sync {
    /// Returns ciphertext with the tag appended.
    fn encrypt(
        &self,
        alg: AeadAlg,
        key: &SecretBox<Vec<u8>>,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>>;

    /// Expects ciphertext with the tag appended, as `encrypt` produces.
    fn decrypt(
        &self,
        alg: AeadAlg,
        key: &SecretBox<Vec<u8>>,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;
}

pub trait SignerProvider: Send + Sync {
    /// ECDSA signatures come out DER-encoded. A JOSE caller wanting fixed-width
    /// R‖S transcodes them itself.
    fn sign(&self, alg: SignAlg, key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, alg: SignAlg, key: &PublicKey, data: &[u8], sig: &[u8]) -> Result<bool>;
}

/// Key derivation. Produces key material from key material, never from a stored
/// credential — that is [`PasswordProvider`]'s side.
pub trait KdfProvider: Send + Sync {
    /// HKDF, RFC 5869.
    fn hkdf(
        &self,
        hash: HashAlg,
        ikm: &SecretBox<Vec<u8>>,
        salt: Option<&[u8]>,
        info: &[u8],
        len: usize,
    ) -> Result<SecretBox<Vec<u8>>>;

    /// The NIST SP 800-56A concatenation KDF, which ECDH-ES uses.
    fn concat_kdf(
        &self,
        hash: HashAlg,
        z: &SecretBox<Vec<u8>>,
        info: ConcatKdfInfo<'_>,
        len: usize,
    ) -> Result<SecretBox<Vec<u8>>>;

    /// PBKDF2-HMAC. Key derivation from a passphrase — JWE's PBES2 needs it.
    /// Storing a user credential is [`PasswordProvider`]'s job, not this one.
    fn pbkdf2_hmac(
        &self,
        hash: HashAlg,
        passphrase: &SecretBox<String>,
        salt: &[u8],
        iterations: u32,
        len: usize,
    ) -> Result<SecretBox<Vec<u8>>>;
}

pub trait RandProvider: Send + Sync {
    fn fill(&self, buf: &mut [u8]) -> Result<()>;
}

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Time cost, in iterations.
    pub t_cost: u32,
    /// Parallelism, in lanes.
    pub p_cost: u32,
    /// Derived key length in bytes.
    pub output_len: usize,
}

impl Default for Argon2Params {
    fn default() -> Self {
        // OWASP 2024 baseline for Argon2id: 19 MiB, 2 iterations, 1 lane.
        Self {
            m_cost: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
            output_len: 32,
        }
    }
}

/// Storing and checking user credentials. Separate from [`KdfProvider`]
/// because the two answer different questions: this one decides whether a
/// presented password matches a stored record, and it owns the record's format.
pub trait PasswordProvider: Send + Sync {
    /// Hash to a self-contained Argon2id PHC string, salt included and freshly
    /// drawn. This is the form to store; [`Self::verify`] reads it back,
    /// parameters and all, so raising the cost later does not invalidate what
    /// is already stored.
    fn hash(&self, password: &SecretBox<String>, params: Argon2Params) -> Result<String>;

    /// Verify against a stored PHC string.
    fn verify(&self, password: &SecretBox<String>, encoded: &str) -> Result<bool>;

    /// Verify against a bcrypt hash imported from an older system. Verification
    /// only: nothing here mints bcrypt.
    fn verify_bcrypt(&self, password: &SecretBox<String>, hash: &str) -> Result<bool>;
}

/// A key store. Async because a store may answer over I/O — a hardware token,
/// a remote KMS — even though the software one does not.
#[async_trait]
pub trait KeyStoreProvider: Send + Sync {
    async fn list_keys(&self) -> Result<Vec<KeyHandle>>;
    async fn create_key(&self, spec: KeyGenSpec) -> Result<KeyHandle>;
    async fn delete_key(&self, handle: &KeyHandle) -> Result<()>;
    async fn sign_with_key(&self, handle: &KeyHandle, alg: SignAlg, data: &[u8])
    -> Result<Vec<u8>>;

    /// Whether [`Self::attest`] can answer. A store that cannot says so here
    /// rather than returning something that looks like an attestation.
    fn supports_attestation(&self) -> bool;
    async fn attest(&self, handle: &KeyHandle) -> Result<Attestation>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest each JWS algorithm is paired with is spec, not preference:
    /// RS256 signing over SHA-384 produces something no verifier accepts, and
    /// nothing downstream would catch it.
    #[test]
    fn signature_algorithms_carry_their_specified_digest() {
        for (alg, hash) in [
            (SignAlg::Rs256, Some(HashAlg::Sha256)),
            (SignAlg::Rs384, Some(HashAlg::Sha384)),
            (SignAlg::Rs512, Some(HashAlg::Sha512)),
            (SignAlg::Ps256, Some(HashAlg::Sha256)),
            (SignAlg::Ps384, Some(HashAlg::Sha384)),
            (SignAlg::Ps512, Some(HashAlg::Sha512)),
            (SignAlg::Es256, Some(HashAlg::Sha256)),
            (SignAlg::Es384, Some(HashAlg::Sha384)),
            (SignAlg::Es512, Some(HashAlg::Sha512)),
            (SignAlg::EdDsa, None),
        ] {
            assert_eq!(alg.hash(), hash, "{alg:?}");
        }
    }

    /// EdDSA hashes internally. A caller that pre-hashes because `hash()`
    /// handed it a digest signs the wrong thing, so the `None` is load-bearing.
    #[test]
    fn eddsa_asks_for_no_external_digest() {
        assert!(SignAlg::EdDsa.hash().is_none());
    }

    /// `is_pss` and `is_ecdsa` choose the padding and the signature encoding.
    /// A false negative on `is_pss` silently signs PKCS#1 v1.5 instead.
    #[test]
    fn padding_and_encoding_predicates_select_the_right_algorithms() {
        let all = [
            SignAlg::Rs256,
            SignAlg::Rs384,
            SignAlg::Rs512,
            SignAlg::Ps256,
            SignAlg::Ps384,
            SignAlg::Ps512,
            SignAlg::Es256,
            SignAlg::Es384,
            SignAlg::Es512,
            SignAlg::EdDsa,
        ];
        let pss: Vec<_> = all.iter().filter(|a| a.is_pss()).copied().collect();
        let ecdsa: Vec<_> = all.iter().filter(|a| a.is_ecdsa()).copied().collect();

        assert_eq!(pss, [SignAlg::Ps256, SignAlg::Ps384, SignAlg::Ps512]);
        assert_eq!(ecdsa, [SignAlg::Es256, SignAlg::Es384, SignAlg::Es512]);
        assert!(all.iter().all(|a| !(a.is_pss() && a.is_ecdsa())));
    }

    /// The AEAD key length is what the backend checks a caller's key against,
    /// so a wrong value here accepts a key the cipher cannot use.
    #[test]
    fn aead_sizes_match_their_ciphers() {
        assert_eq!(AeadAlg::A128Gcm.key_len(), 16);
        assert_eq!(AeadAlg::A192Gcm.key_len(), 24);
        assert_eq!(AeadAlg::A256Gcm.key_len(), 32);
        #[cfg(feature = "chacha20")]
        assert_eq!(AeadAlg::ChaCha20Poly1305.key_len(), 32);

        for alg in [AeadAlg::A128Gcm, AeadAlg::A192Gcm, AeadAlg::A256Gcm] {
            assert_eq!(alg.nonce_len(), 12);
            assert_eq!(alg.tag_len(), 16);
        }
    }

    #[test]
    fn hmac_algorithms_carry_their_digest() {
        assert_eq!(HmacAlg::Hs256.hash(), HashAlg::Sha256);
        assert_eq!(HmacAlg::Hs384.hash(), HashAlg::Sha384);
        assert_eq!(HmacAlg::Hs512.hash(), HashAlg::Sha512);
    }

    /// `PrivateKey` overrides `Debug` so a key cannot be printed into a log by
    /// a struct that happens to derive it. This asserts the override holds.
    #[test]
    fn a_private_key_never_renders_its_bytes() {
        let key = PrivateKey::from_der(b"SECRET-KEY-MATERIAL".to_vec());
        let rendered = format!("{key:?}");

        assert!(!rendered.contains("SECRET"));
        assert!(!rendered.contains("83"), "no byte listing either");
        assert_eq!(rendered, "PrivateKey(<redacted>)");
        assert_eq!(key.der(), b"SECRET-KEY-MATERIAL");
    }

    /// The default cost is the OWASP 2024 baseline. Written down as a test so
    /// lowering it is a decision someone makes on purpose.
    #[test]
    fn argon2_defaults_are_the_owasp_baseline() {
        let p = Argon2Params::default();
        assert_eq!(p.m_cost, 19 * 1024);
        assert_eq!(p.t_cost, 2);
        assert_eq!(p.p_cost, 1);
        assert_eq!(p.output_len, 32);
    }

    #[test]
    fn a_public_key_round_trips_its_der() {
        let key = PublicKey::from_der(vec![1, 2, 3]);
        assert_eq!(key.der(), &[1, 2, 3]);
    }
}
