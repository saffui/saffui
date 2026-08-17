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
use serde::{Deserialize, Serialize};
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

    /// Where to find a PKCS#11 token, when the key store should be one.
    ///
    /// Absent means the software store. There is no automatic discovery: a
    /// deployment that meant to use a token and silently got the software store
    /// would hold its private keys in process memory while believing otherwise.
    ///
    /// Present whether or not the backend can honour it. A configuration type
    /// that changes shape with a feature makes every caller carry the same
    /// `cfg`, and a caller that gets it wrong builds a provider that ignores the
    /// token instead of failing to compile.
    pub pkcs11: Option<Pkcs11Config>,
}

/// How to reach a PKCS#11 token. Data only — nothing here needs the backend
/// that would use it.
#[derive(Debug)]
pub struct Pkcs11Config {
    /// Path to the module to load.
    pub module: String,
    /// Which slot to use. Absent takes the first slot holding a token, which is
    /// right for a single-token host and wrong for anything else.
    pub slot: Option<u64>,
    pub pin: SecretBox<String>,
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
///
/// The rename on each variant is the same spelling [`SignAlg::name`] returns, so
/// a stored document, a token header and this enum cannot disagree about which
/// algorithm a record names. A test holds the two in step.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum SignAlg {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "RS384")]
    Rs384,
    #[serde(rename = "RS512")]
    Rs512,
    #[serde(rename = "PS256")]
    Ps256,
    #[serde(rename = "PS384")]
    Ps384,
    #[serde(rename = "PS512")]
    Ps512,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES384")]
    Es384,
    #[serde(rename = "ES512")]
    Es512,
    #[serde(rename = "EdDSA")]
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

    /// Every algorithm this build can sign with.
    ///
    /// The one list. Discovery metadata, a stored catalogue and any database
    /// constraint all read it, so none of them can advertise an algorithm the
    /// signer would refuse.
    pub const ALL: [SignAlg; 10] = [
        Self::Rs256,
        Self::Rs384,
        Self::Rs512,
        Self::Ps256,
        Self::Ps384,
        Self::Ps512,
        Self::Es256,
        Self::Es384,
        Self::Es512,
        Self::EdDsa,
    ];

    /// The JWS `alg` name (RFC 7518 §3.1), as it appears in a token header and
    /// in a JWKS.
    pub fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::EdDsa => "EdDSA",
        }
    }

    /// The JWK `kty` this algorithm implies: `EC`, `RSA` or `OKP`.
    ///
    /// Derived rather than stored beside the algorithm, so the pair cannot be
    /// written down disagreeing.
    pub fn key_type(self) -> &'static str {
        match self {
            Self::Es256 | Self::Es384 | Self::Es512 => "EC",
            Self::Rs256 | Self::Rs384 | Self::Rs512 => "RSA",
            Self::Ps256 | Self::Ps384 | Self::Ps512 => "RSA",
            Self::EdDsa => "OKP",
        }
    }
}

impl std::str::FromStr for SignAlg {
    type Err = CryptoError;

    /// Parse a requested or stored `alg`.
    ///
    /// Case-sensitive, because `alg` is case-sensitive in RFC 7515 and accepting
    /// `es256` would mean emitting a header some verifiers reject. Anything
    /// unregistered is refused here rather than surfacing later as a signing
    /// failure or, worse, as a silent choice of something else.
    fn from_str(name: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|alg| alg.name() == name)
            .ok_or(CryptoError::UnsupportedAlgorithm)
    }
}

impl std::fmt::Display for SignAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
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
/// A hardware store names its keys its own way rather than reusing the software
/// variant, so an id can never be mistaken for a token label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyHandle {
    Software {
        id: String,
    },
    /// A key living inside a PKCS#11 token, named by its label.
    ///
    /// The label rather than an object handle: handles are per-session and mean
    /// nothing once the session closes, so one stored in a database would refer
    /// to whatever occupies that slot next time.
    Token {
        label: String,
    },
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
    fn digest(&self) -> &dyn DigestProvider;

    #[cfg(feature = "pq-hybrid")]
    fn pq_signature(&self) -> &dyn PqSignatureProvider;
    #[cfg(feature = "pq-hybrid")]
    fn pq_kem(&self) -> &dyn PqKemProvider;
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

/// ML-DSA parameter sets (FIPS 204).
///
/// Deliberately not a [`SignAlg`]. That type answers `hash`, `is_pss` and
/// `is_ecdsa`, and none of the three means anything here: ML-DSA signs a
/// message directly with no external digest and belongs to neither family.
/// Folding them together would make those methods lie for three variants.
#[cfg(feature = "pq-hybrid")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MlDsaAlg {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// Post-quantum signatures.
///
/// Separate from [`SignerProvider`] because the two share no algorithm and no
/// key shape. Keys cross here as DER like everywhere else in this seam, so a
/// caller holds bytes rather than a backend handle.
///
/// Every operation needs libcrypto 3.5 or newer. On an older library the
/// algorithm cannot be fetched at all and these report
/// [`CryptoError::UnsupportedAlgorithm`], which is the honest answer: a
/// post-quantum signature that silently became something else would be worse
/// than none.
#[cfg(feature = "pq-hybrid")]
pub trait PqSignatureProvider: Send + Sync {
    /// A fresh key pair, private as PKCS#8 DER and public as SPKI DER.
    fn generate(&self, alg: MlDsaAlg) -> Result<(PrivateKey, PublicKey)>;

    /// Sign a message. ML-DSA hashes internally, so there is no digest to pick
    /// and nothing for a caller to get wrong.
    fn sign(&self, key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>>;

    fn verify(&self, key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<bool>;
}

/// ML-KEM parameter sets (FIPS 203).
#[cfg(feature = "pq-hybrid")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MlKemAlg {
    MlKem512,
    MlKem768,
    MlKem1024,
}

/// What an encapsulation produces: the ciphertext for the holder of the private
/// key, and the shared secret to keep.
///
/// The two travel together because they are only meaningful together, and
/// because the secret is the half that must not be logged — separating them
/// invites a struct where one field is protected and the other is not.
#[cfg(feature = "pq-hybrid")]
pub struct Encapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: SecretBox<Vec<u8>>,
}

#[cfg(feature = "pq-hybrid")]
impl std::fmt::Debug for Encapsulation {
    /// Renders the ciphertext's length and never the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encapsulation")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// Post-quantum key encapsulation.
///
/// A KEM is not a cipher and not a key agreement: encapsulating produces a
/// fresh shared secret *and* the ciphertext that lets one particular private
/// key recover it. There is no plaintext to choose, which is why this has no
/// resemblance to [`AeadProvider`] and needs its own trait.
///
/// Like [`PqSignatureProvider`], every operation needs libcrypto 3.5 or newer
/// and reports [`CryptoError::UnsupportedAlgorithm`] when the algorithm cannot
/// be fetched.
#[cfg(feature = "pq-hybrid")]
pub trait PqKemProvider: Send + Sync {
    /// A fresh key pair, private as PKCS#8 DER and public as SPKI DER.
    fn generate(&self, alg: MlKemAlg) -> Result<(PrivateKey, PublicKey)>;

    /// Draw a shared secret and the ciphertext that recovers it.
    fn encapsulate(&self, key: &PublicKey) -> Result<Encapsulation>;

    /// Recover the shared secret from a ciphertext.
    fn decapsulate(&self, key: &PrivateKey, ciphertext: &[u8]) -> Result<SecretBox<Vec<u8>>>;
}

/// An extendable-output function, which produces as many bytes as it is asked
/// for rather than a fixed digest.
///
/// Deliberately not a [`HashAlg`]. That type promises `output_len`, and a XOF
/// has no length of its own — the caller names one. Folding the two together
/// would make that method a lie for two of its variants.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum XofAlg {
    Shake128,
    Shake256,
}

impl XofAlg {
    /// The security strength in bits, which is what bounds a useful output
    /// length rather than the length itself.
    ///
    /// Squeezing more than this buys nothing: the extra bytes are determined by
    /// the same state, so a longer output is longer, not stronger.
    pub fn strength_bits(self) -> usize {
        match self {
            Self::Shake128 => 128,
            Self::Shake256 => 256,
        }
    }
}

/// Hashing under any algorithm the seam names.
///
/// Separate from [`LegacyDigestProvider`], which exists to read inherited
/// password records and names MD5. Merging them would put MD5 within one enum
/// variant of everything that hashes.
pub trait DigestProvider: Send + Sync {
    fn hash(&self, alg: HashAlg, data: &[u8]) -> Result<Vec<u8>>;

    /// Squeeze `len` bytes out of an extendable-output function.
    ///
    /// A zero-length squeeze is refused. It is a well-defined operation that
    /// returns nothing, which is never what a caller meant and is exactly what
    /// an uninitialised length parameter produces.
    fn xof(&self, alg: XofAlg, data: &[u8], len: usize) -> Result<Vec<u8>>;
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
///
/// Serialisable because a realm stores the cost it mints passwords at, and a
/// second copy of these four numbers somewhere else is a second place for them
/// to disagree with what the hasher is given.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
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

    /// Verify against an Argon2 string of any variant.
    ///
    /// [`Self::verify`] accepts argon2id alone, which is right for what this
    /// crate writes. A credential imported as argon2i or argon2d has to verify
    /// exactly once all the same, or the account can never be migrated —
    /// migration happens during a successful login, and that is the login.
    fn verify_legacy_argon2(&self, password: &SecretBox<String>, encoded: &str) -> Result<bool>;

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
        let all = SignAlg::ALL;
        let pss: Vec<_> = all.iter().filter(|a| a.is_pss()).copied().collect();
        let ecdsa: Vec<_> = all.iter().filter(|a| a.is_ecdsa()).copied().collect();

        assert_eq!(pss, [SignAlg::Ps256, SignAlg::Ps384, SignAlg::Ps512]);
        assert_eq!(ecdsa, [SignAlg::Es256, SignAlg::Es384, SignAlg::Es512]);
        assert!(all.iter().all(|a| !(a.is_pss() && a.is_ecdsa())));
    }

    /// Whatever `name` emits, `from_str` accepts, and `Display` agrees with
    /// both. A break here is a key row written one way and read back as
    /// unknown.
    #[test]
    fn every_algorithm_round_trips_through_its_jws_name() {
        for alg in SignAlg::ALL {
            assert_eq!(
                alg.name().parse::<SignAlg>().expect("its own name parses"),
                alg,
                "{alg} must parse back"
            );
            assert_eq!(alg.to_string(), alg.name(), "{alg}: Display must be name");
        }
    }

    /// `alg` is case-sensitive in RFC 7515. Accepting `es256` would mean
    /// emitting a header some verifiers reject, so the leniency is refused at
    /// the parse rather than papered over.
    #[test]
    fn parsing_an_algorithm_is_case_sensitive_and_refuses_the_unknown() {
        for bad in [
            "es256", "ES-256", "ES256 ", " ES256", "eddsa", "EDDSA", "RS", "", "null",
        ] {
            assert!(bad.parse::<SignAlg>().is_err(), "{bad:?} must not parse");
        }
    }

    /// The exclusions are decisions, not omissions, so they are asserted rather
    /// than left to whoever next edits the enum.
    ///
    /// `HS*` is symmetric: a realm signing key is published in a JWKS, so an
    /// HMAC key there would publish the secret itself. `ES256K` is not
    /// registered for id token signing and sits outside the FIPS set. `none` is
    /// never a signing algorithm.
    #[test]
    fn the_excluded_algorithms_stay_excluded() {
        for excluded in ["HS256", "HS384", "HS512", "ES256K", "none", "None"] {
            assert!(
                excluded.parse::<SignAlg>().is_err(),
                "{excluded} must never enter the catalogue"
            );
        }
    }

    /// Each algorithm implies exactly one registered JWK key type. Derived here
    /// rather than stored beside the algorithm, which is what stops a record
    /// from naming a curve its algorithm does not use.
    #[test]
    fn every_algorithm_implies_a_registered_key_type() {
        for alg in SignAlg::ALL {
            assert!(
                matches!(alg.key_type(), "EC" | "RSA" | "OKP"),
                "{alg} implies unregistered kty {}",
                alg.key_type()
            );
        }
        assert_eq!(SignAlg::Es256.key_type(), "EC");
        assert_eq!(SignAlg::Rs512.key_type(), "RSA");
        assert_eq!(SignAlg::Ps384.key_type(), "RSA");
        assert_eq!(SignAlg::EdDsa.key_type(), "OKP");
    }

    /// The encoded spelling is the one `name` returns, in both directions. A
    /// rename that drifted from the table would store a document naming an
    /// algorithm the header never carries.
    #[test]
    fn the_encoded_spelling_is_the_jws_name() {
        for alg in SignAlg::ALL {
            let encoded = serde_json::to_string(&alg).expect("an algorithm encodes");
            assert_eq!(encoded, format!("\"{}\"", alg.name()), "{alg}");
            assert_eq!(
                serde_json::from_str::<SignAlg>(&encoded).expect("it decodes back"),
                alg
            );
        }
    }

    /// A duplicate name would make `from_str` resolve to whichever variant
    /// comes first, silently shadowing the other — and `ALL` is what discovery
    /// advertises.
    #[test]
    fn the_algorithm_catalogue_has_no_duplicates() {
        let mut names: Vec<&str> = SignAlg::ALL.iter().map(|alg| alg.name()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate name in ALL");
        assert_eq!(count, 10);
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
