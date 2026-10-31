//! The cryptographic ports. The heart links no cryptographic library: it
//! says what must be done, and an adapter does it.

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a cryptographic operation failed")]
pub struct CryptoFailure;
