//! The cryptographic ports. The heart links no cryptographic library: it
//! says what must be done, and an adapter does it.

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
}

/// The signature algorithms of the product. One is listed only once the
/// adapter generates, signs and verifies with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    Es256,
}

impl SignatureAlgorithm {
    pub const ALL: [Self; 1] = [Self::Es256];

    /// The name the algorithm has in a token header and in a published key.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
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

pub trait Signer: Send + Sync {
    /// Generates a key pair for `algorithm`.
    ///
    /// # Errors
    ///
    /// Fails when the library cannot generate or encode the key.
    fn generate_key(
        &self,
        algorithm: SignatureAlgorithm,
    ) -> Result<GeneratedSigningKey, CryptoFailure>;

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
