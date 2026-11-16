use saffui_core::ports::crypto::{CryptoFailure, Digester};
use saffui_core::secret::Secret;
use secrecy::SecretBox;

use super::SharedProvider;
use crate::constant_time;
use crate::provider::{HashAlg, HmacAlg};

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

    fn hmac_sha256(&self, key: &Secret, data: &[u8]) -> Result<[u8; 32], CryptoFailure> {
        let key = SecretBox::new(Box::new(key.expose().to_vec()));
        let tag = self
            .provider
            .hmac()
            .hmac(HmacAlg::Hs256, &key, data)
            .map_err(|_| CryptoFailure)?;
        <[u8; 32]>::try_from(tag).map_err(|_| CryptoFailure)
    }

    fn equal_in_constant_time(&self, left: &[u8], right: &[u8]) -> bool {
        constant_time::eq(left, right)
    }
}

#[cfg(test)]
mod tests {
    use saffui_core::ports::crypto::Digester;
    use saffui_core::secret::Secret;

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
    fn hmac_sha256_answers_its_published_vectors() {
        let digester = ProviderDigester::new(open_provider().expect("a provider"));
        let hex = |bytes: &[u8]| data_encoding::HEXLOWER.encode(bytes);

        // RFC 4231, test cases 1 and 2.
        let first = digester
            .hmac_sha256(&Secret::new(vec![0x0b; 20]), b"Hi There")
            .expect("a tag");
        let second = digester
            .hmac_sha256(
                &Secret::new(b"Jefe".to_vec()),
                b"what do ya want for nothing?",
            )
            .expect("a tag");

        assert_eq!(
            hex(&first),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&second),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
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
