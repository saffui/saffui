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
