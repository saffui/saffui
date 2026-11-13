//! The cryptographic ports. The heart links no cryptographic library: it
//! says what must be done, and an adapter does it.

use async_trait::async_trait;
use uuid::Uuid;

use crate::secret::Secret;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a cryptographic operation failed")]
pub struct CryptoFailure;

/// The digests the heart computes. The adapter is the only one that knows
/// which library does it.
pub trait Digester: Send + Sync {
    /// SHA-256 of `data`. It does not fail: an adapter whose library stops
    /// answering abandons the request rather than return a value that is not
    /// the digest, since every link compared with it would then match.
    fn sha256(&self, data: &[u8]) -> [u8; 32];

    /// Compares without telling, by the time it takes, where the two differ.
    fn equal_in_constant_time(&self, left: &[u8], right: &[u8]) -> bool;
}

/// Where a sealed value lives. The place is bound into the seal: a value
/// copied to another tenant, realm, purpose or row does not open there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealPlace {
    pub tenant: Uuid,
    pub realm: Uuid,
    pub purpose: &'static str,
    pub row: Uuid,
}

/// The data key of a realm, wrapped under the key of the deployment. It is
/// stored: rotating the deployment key rewrites one row per realm, and
/// destroying this row makes everything the realm sealed unreadable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedDataKey {
    pub generation: u32,
    pub wrapped: Vec<u8>,
}

pub trait Sealer: Send + Sync {
    /// Makes a fresh data key for a realm, wrapped under the deployment key.
    ///
    /// # Errors
    ///
    /// Fails when the library cannot draw or wrap the key.
    fn make_data_key(
        &self,
        tenant: Uuid,
        realm: Uuid,
        generation: u32,
    ) -> Result<WrappedDataKey, CryptoFailure>;

    /// Seals a value for one place. The result carries the generation of the
    /// data key in its header.
    ///
    /// # Errors
    ///
    /// Fails when the data key does not unwrap under the deployment key.
    fn seal(
        &self,
        data_key: &WrappedDataKey,
        place: &SealPlace,
        plaintext: &Secret,
    ) -> Result<Vec<u8>, CryptoFailure>;

    /// Opens a value sealed for exactly this place under exactly this data key.
    ///
    /// # Errors
    ///
    /// Fails for any other place or key, and for a value that was altered.
    fn open(
        &self,
        data_key: &WrappedDataKey,
        place: &SealPlace,
        sealed: &[u8],
    ) -> Result<Secret, CryptoFailure>;

    /// Digests what a person typed as their name, under a key derived from
    /// the root key and bound to the realm. People type passwords into the
    /// wrong field: whoever reads the table must not be able to try guesses.
    ///
    /// # Errors
    ///
    /// Fails when the key cannot be used.
    fn digest_typed_name(
        &self,
        tenant: Uuid,
        realm: Uuid,
        typed: &[u8],
    ) -> Result<Vec<u8>, CryptoFailure>;
}

/// The signature algorithms of the product. One is listed only once the
/// adapter generates, signs and verifies with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    Es256,
    Es384,
    Rs256,
    Ps256,
    /// On Ed25519.
    EdDsa,
}

impl SignatureAlgorithm {
    pub const ALL: [Self; 5] = [
        Self::Es256,
        Self::Es384,
        Self::Rs256,
        Self::Ps256,
        Self::EdDsa,
    ];

    /// The name the algorithm has in a token header and in a published key.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Rs256 => "RS256",
            Self::Ps256 => "PS256",
            Self::EdDsa => "EdDSA",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.name() == name)
    }
}

/// A key pair just made: the private half in clear, for as long as it takes
/// to seal it, and the public half as it is published.
pub struct GeneratedSigningKey {
    pub algorithm: SignatureAlgorithm,
    /// The RFC 7638 thumbprint of the public key, in base64url without padding.
    pub key_id: String,
    /// The private key, as PKCS#8 DER.
    pub private_key: Secret,
    /// The public key as a JWK carrying `kid`, `use` and `alg`.
    pub public_jwk: serde_json::Value,
}

/// What the caller of a key holds while it is made, such as the share of its
/// tenant: kept with the work and dropped when the key is made, not when the
/// caller gives up.
pub type KeyMakingGuard = Box<dyn Send>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyMakingFailure {
    /// Every key maker of the node is at work: the request is refused at
    /// once, instead of waiting behind the keys of other tenants.
    #[error("every key maker is at work")]
    Busy,
    #[error("the key could not be made")]
    Failed,
}

#[async_trait]
pub trait Signer: Send + Sync {
    /// Whether this build signs in `algorithm`. One it does not is neither
    /// offered, made, published nor read.
    fn signs_in(&self, algorithm: SignatureAlgorithm) -> bool;

    /// Generates a key pair for `algorithm`, away from the threads that
    /// serve requests: an RSA key takes a while to find. `guard` is kept
    /// until the key is made.
    ///
    /// # Errors
    ///
    /// Returns [`KeyMakingFailure::Busy`] when every maker is at work, and
    /// fails when the library cannot generate or encode the key, or for an
    /// algorithm this build does not sign in.
    async fn generate_key(
        &self,
        algorithm: SignatureAlgorithm,
        guard: KeyMakingGuard,
    ) -> Result<GeneratedSigningKey, KeyMakingFailure>;

    /// Signs `message`. The signature is in the form a JWS carries: for
    /// ES256, the 64 bytes of `r` then `s`.
    ///
    /// # Errors
    ///
    /// Fails when the private key cannot be read or is not of this algorithm.
    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        private_key: &Secret,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoFailure>;

    /// Tells whether `signature` is the one of `message` under the public
    /// key. A signature that does not verify is `Ok(false)`.
    ///
    /// # Errors
    ///
    /// Fails for a key that cannot be read or that is not of this algorithm.
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        public_jwk: &serde_json::Value,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoFailure>;
}

/// What a person's authenticator application needs to enroll a secret: a
/// URI to scan, and the same secret as text to type. Both carry the secret:
/// it is shown once, and never copied or printed.
pub struct TotpEnrollmentText {
    pub uri: String,
    pub typed_secret: String,
}

// Written by hand: both fields are the secret.
impl std::fmt::Debug for TotpEnrollmentText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TotpEnrollmentText")
            .field("uri", &"..")
            .field("typed_secret", &"..")
            .finish()
    }
}

/// The one-time codes of an authenticator application (RFC 6238).
pub trait OneTimeCodes: Send + Sync {
    /// Makes the secret a person's application and the realm will share.
    ///
    /// # Errors
    ///
    /// Fails when the random source does.
    fn make_totp_secret(&self) -> Result<Secret, CryptoFailure>;

    /// Tells which time step `code` is the code of, among the step of
    /// `unix_seconds` and the one on each side of it. A code that is the
    /// code of none of them, or that is not six digits, is `None`.
    ///
    /// # Errors
    ///
    /// Fails when the secret cannot be used.
    fn find_totp_step(
        &self,
        secret: &Secret,
        code: &str,
        unix_seconds: u64,
    ) -> Result<Option<u64>, CryptoFailure>;

    /// Writes what the application of `account` enrolls the secret from.
    ///
    /// # Errors
    ///
    /// Fails when the secret cannot be written.
    fn write_totp_enrollment(
        &self,
        issuer: &str,
        account: &str,
        secret: &Secret,
    ) -> Result<TotpEnrollmentText, CryptoFailure>;
}

/// A ceremony with a security key, between its two requests.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyCeremony {
    /// What the page hands to the browser, as the browser's interface takes it.
    pub options: serde_json::Value,
    /// What the realm keeps to finish the ceremony. Only the adapter reads it.
    pub state: Vec<u8>,
}

/// A key that finished its enrollment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolledKey {
    pub credential_id: Vec<u8>,
    /// What the realm keeps of the key. Only the adapter reads it.
    pub record: Vec<u8>,
}

/// A key that proved itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyProof {
    pub credential_id: Vec<u8>,
    /// The record to keep in place of the one that was held, when the key
    /// moved its counter: a copy of the key is told by a counter that goes back.
    pub record: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyRefusal {
    /// The answer does not prove the key: wrong challenge, wrong origin,
    /// wrong signature, a key that is not held.
    #[error("the answer of the security key is refused")]
    Refused,
    /// The counter did not move forward: a copy of the key answered. A key
    /// that counts nothing answers zero forever, and is not suspected.
    #[error("the counter of the security key did not move forward")]
    CopySuspected,
    #[error("the ceremony cannot be carried out")]
    Failed,
}

/// Security keys (WebAuthn): a key proves itself by signing a challenge of
/// the realm, for the origin the browser stands on.
pub trait SecurityKeys: Send + Sync {
    /// Whether keys are served here. Where they are not, every ceremony fails.
    fn are_served(&self) -> bool;

    /// Starts the enrollment of a key for a person who holds `held` already.
    ///
    /// # Errors
    ///
    /// Fails when the ceremony cannot be started.
    fn start_enrollment(
        &self,
        person: Uuid,
        username: &str,
        held: &[Vec<u8>],
    ) -> Result<KeyCeremony, CryptoFailure>;

    /// Finishes an enrollment with what the browser handed back.
    ///
    /// # Errors
    ///
    /// Returns why the key is not enrolled.
    fn finish_enrollment(
        &self,
        state: &[u8],
        answer: &serde_json::Value,
    ) -> Result<EnrolledKey, KeyRefusal>;

    /// Starts a proof by one of the keys a person holds.
    ///
    /// # Errors
    ///
    /// Fails when the ceremony cannot be started.
    fn start_proof(&self, held: &[Vec<u8>]) -> Result<KeyCeremony, CryptoFailure>;

    /// Finishes a proof with what the browser handed back.
    ///
    /// # Errors
    ///
    /// Returns why the key proved nothing.
    fn finish_proof(
        &self,
        state: &[u8],
        answer: &serde_json::Value,
        held: &[Vec<u8>],
    ) -> Result<KeyProof, KeyRefusal>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PasswordHashingFailure {
    /// Too many hashes are already running: the request is refused quickly
    /// instead of queueing memory-hard work without bound.
    #[error("too many passwords are being hashed")]
    Busy,
    #[error("the password could not be hashed")]
    Failed,
}

/// Hashing is slow on purpose. An adapter runs it away from the threads that
/// serve requests, on a bounded number of workers.
#[async_trait]
pub trait PasswordHasher: Send + Sync {
    /// Returns the hash as a PHC string, which names its own parameters.
    async fn hash_password(&self, password: Secret) -> Result<String, PasswordHashingFailure>;

    /// Tells whether `password` is the one `stored` was made from. A stored
    /// value that is not a PHC string of a known algorithm is `Ok(false)`.
    async fn verify_password(
        &self,
        password: Secret,
        stored: String,
    ) -> Result<bool, PasswordHashingFailure>;
}
