//! The ports of the core, served by this crate. New code, kept apart from
//! the JOSE layer and from the provider: it binds them to the core and adds
//! no cryptography of its own.

pub mod random;

use std::sync::Arc;

use saffui_core::ports::crypto::CryptoFailure;

use crate::provider::openssl::OpenSslProvider;
use crate::provider::{CryptoConfig, CryptoProvider, HashAlg};

/// The provider every adapter of a process shares.
pub type SharedProvider = Arc<dyn CryptoProvider>;

/// SHA-256 of `abc` (FIPS 180-2, appendix B.1).
const DIGEST_OF_ABC: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

/// Opens the provider, and refuses one that does not answer a known digest:
/// a library that fails its own vector signs and seals nothing.
///
/// # Errors
///
/// Fails when the library cannot be loaded or answers wrongly.
pub fn open_provider() -> Result<SharedProvider, CryptoFailure> {
    let provider = OpenSslProvider::new(&CryptoConfig::default()).map_err(|_| CryptoFailure)?;
    let answered = provider
        .digest()
        .hash(HashAlg::Sha256, b"abc")
        .map_err(|_| CryptoFailure)?;
    if answered != DIGEST_OF_ABC {
        return Err(CryptoFailure);
    }
    Ok(Arc::new(provider))
}

#[cfg(test)]
mod tests {
    use super::open_provider;

    #[test]
    fn the_provider_of_this_machine_opens_and_passes_its_vector() {
        assert!(open_provider().is_ok());
    }
}
