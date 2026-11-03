use saffui_core::ports::crypto::Digester;

use super::SharedProvider;
use crate::constant_time;
use crate::provider::HashAlg;

/// The digests of the provider.
pub struct ProviderDigester {
    provider: SharedProvider,
}

impl ProviderDigester {
    #[must_use]
    pub fn new(provider: SharedProvider) -> Self {
        Self { provider }
    }
}

impl Digester for ProviderDigester {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let digest = self
            .provider
            .digest()
            .hash(HashAlg::Sha256, data)
            .ok()
            .and_then(|digest| <[u8; 32]>::try_from(digest).ok());
        // The provider answered this digest when it was opened. Should it stop,
        // no value may stand in for a digest: every link compared with it
        // would then match. The request is abandoned.
        digest.unwrap_or_else(|| panic!("the provider no longer computes SHA-256"))
    }

    fn equal_in_constant_time(&self, left: &[u8], right: &[u8]) -> bool {
        constant_time::eq(left, right)
    }
}

#[cfg(test)]
mod tests {
    use saffui_core::ports::crypto::Digester;

    use super::ProviderDigester;
    use crate::adapters::{DIGEST_OF_ABC, open_provider};

    #[test]
    fn sha256_answers_its_published_vectors() {
        let digester = ProviderDigester::new(open_provider().expect("a provider"));

        // FIPS 180-2, appendix B.1 and B.2.
        assert_eq!(digester.sha256(b"abc"), DIGEST_OF_ABC);
        assert_eq!(
            data_encoding::HEXLOWER.encode(
                &digester.sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
            ),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn equality_is_told_for_equal_bytes_only() {
        let digester = ProviderDigester::new(open_provider().expect("a provider"));

        assert!(digester.equal_in_constant_time(b"same", b"same"));
        assert!(!digester.equal_in_constant_time(b"same", b"sane"));
        assert!(!digester.equal_in_constant_time(b"same", b"same "));
    }
}
