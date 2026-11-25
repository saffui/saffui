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

    fn sha384(&self, data: &[u8]) -> Result<[u8; 48], CryptoFailure> {
        let digest = self
            .provider
            .digest()
            .hash(HashAlg::Sha384, data)
            .map_err(|_| CryptoFailure)?;
        <[u8; 48]>::try_from(digest).map_err(|_| CryptoFailure)
    }

    fn sha512(&self, data: &[u8]) -> Result<[u8; 64], CryptoFailure> {
        let digest = self
            .provider
            .digest()
            .hash(HashAlg::Sha512, data)
            .map_err(|_| CryptoFailure)?;
        <[u8; 64]>::try_from(digest).map_err(|_| CryptoFailure)
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
    fn sha384_and_sha512_answer_their_published_vectors() {
        let digester = ProviderDigester::new(open_provider().expect("a provider"));
        let hex = |bytes: &[u8]| data_encoding::HEXLOWER.encode(bytes);

        // FIPS 180-2, appendix D.1 and C.1.
        assert_eq!(
            hex(&digester.sha384(b"abc").expect("a digest")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            hex(&digester.sha512(b"abc").expect("a digest")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    /// The example of OpenID Connect Core 1.0, section 3.2.2.9: the left half
    /// of the SHA-256 of that access token. A right half or a whole digest
    /// would answer something else.
    #[test]
    fn the_half_hash_of_an_identity_token_signed_in_rs256_is_the_one_openid_connect_publishes() {
        use saffui_core::ports::crypto::SignatureAlgorithm;
        use saffui_core::tokens::mint::write_half_hash;

        let digester = ProviderDigester::new(open_provider().expect("a provider"));

        assert_eq!(
            write_half_hash(
                &digester,
                SignatureAlgorithm::Rs256,
                "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
            )
            .expect("a hash"),
            "77QmUPtjPfzWtF2AnpK9RQ"
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
