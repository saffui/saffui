//! The cryptographic ports. The heart links no cryptographic library: it
//! says what must be done, and an adapter does it.

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
