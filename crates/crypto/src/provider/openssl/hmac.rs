//! HMAC over OpenSSL.

use openssl::memcmp;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use secrecy::{ExposeSecret, SecretBox};

use crate::provider::openssl::digest::message_digest;
use crate::provider::{CryptoError, HashAlg, HmacAlg, HmacProvider, Result};

pub struct OpenSslHmac;

impl OpenSslHmac {
    fn compute(hash: HashAlg, key: &SecretBox<Vec<u8>>, data: &[u8]) -> Result<Vec<u8>> {
        let pkey = PKey::hmac(key.expose_secret()).map_err(|_| CryptoError::InvalidKey)?;
        let mut signer =
            Signer::new(message_digest(hash), &pkey).map_err(|_| CryptoError::OperationFailed)?;
        signer
            .update(data)
            .map_err(|_| CryptoError::OperationFailed)?;
        signer
            .sign_to_vec()
            .map_err(|_| CryptoError::OperationFailed)
    }
}

impl HmacProvider for OpenSslHmac {
    fn hmac_with_hash(
        &self,
        hash: HashAlg,
        key: &SecretBox<Vec<u8>>,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        Self::compute(hash, key, data)
    }

    fn verify(
        &self,
        alg: HmacAlg,
        key: &SecretBox<Vec<u8>>,
        data: &[u8],
        tag: &[u8],
    ) -> Result<bool> {
        let expected = Self::compute(alg.hash(), key, data)?;
        // `memcmp::eq` is constant time but reads both slices to the same
        // length, so the lengths are compared first and separately. A length
        // mismatch is not secret; which byte differs is.
        Ok(expected.len() == tag.len() && memcmp::eq(&expected, tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(bytes: &[u8]) -> SecretBox<Vec<u8>> {
        SecretBox::new(Box::new(bytes.to_vec()))
    }

    /// RFC 4231 test case 1, for the three digests this provider offers.
    ///
    /// A known answer rather than a round trip: an implementation that HMACs
    /// with the wrong digest, or that keys it wrongly, round-trips against
    /// itself perfectly and still interoperates with nobody.
    #[test]
    fn rfc4231_case_1() {
        let key = secret(&[0x0b; 20]);
        let data = b"Hi There";

        let cases = [
            (
                HmacAlg::Hs256,
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                HmacAlg::Hs384,
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
                 faea9ea9076ede7f4af152e8b2fa9cb6",
            ),
            (
                HmacAlg::Hs512,
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
                 daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            ),
        ];

        for (alg, expected) in cases {
            let tag = OpenSslHmac.hmac(alg, &key, data).unwrap();
            assert_eq!(hex(&tag), expected, "{alg:?}");
            assert!(OpenSslHmac.verify(alg, &key, data, &tag).unwrap());
        }
    }

    /// Verification must reject a tag that is wrong, truncated, or extended.
    /// The truncated case is the one a naive prefix comparison would accept.
    #[test]
    fn verify_rejects_a_tag_that_does_not_match() {
        let key = secret(b"0123456789abcdef0123456789abcdef");
        let data = b"payload";
        let tag = OpenSslHmac.hmac(HmacAlg::Hs256, &key, data).unwrap();

        let mut flipped = tag.clone();
        flipped[0] ^= 1;
        assert!(
            !OpenSslHmac
                .verify(HmacAlg::Hs256, &key, data, &flipped)
                .unwrap()
        );

        assert!(
            !OpenSslHmac
                .verify(HmacAlg::Hs256, &key, data, &tag[..16])
                .unwrap()
        );

        let mut longer = tag.clone();
        longer.push(0);
        assert!(
            !OpenSslHmac
                .verify(HmacAlg::Hs256, &key, data, &longer)
                .unwrap()
        );

        let other = secret(b"fedcba9876543210fedcba9876543210");
        assert!(
            !OpenSslHmac
                .verify(HmacAlg::Hs256, &other, data, &tag)
                .unwrap()
        );
        assert!(
            !OpenSslHmac
                .verify(HmacAlg::Hs256, &key, b"other payload", &tag)
                .unwrap()
        );
    }

    /// RFC 2202 test case 1, the SHA-1 counterpart of the vectors above.
    ///
    /// SHA-1 is reachable only through `hmac_with_hash`, so nothing else in the
    /// crate covers it — and it is what RFC 4226 one-time passwords are built
    /// on, where a wrong digest yields codes that no authenticator agrees with.
    #[test]
    fn rfc2202_case_1() {
        let key = secret(&[0x0b; 20]);
        let tag = OpenSslHmac
            .hmac_with_hash(HashAlg::Sha1, &key, b"Hi There")
            .unwrap();

        assert_eq!(hex(&tag), "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    /// The `HmacAlg` entry point is the hash one, so the two cannot disagree.
    #[test]
    fn the_named_algorithms_agree_with_their_hashes() {
        let key = secret(b"0123456789abcdef0123456789abcdef");
        let data = b"payload";

        for alg in [HmacAlg::Hs256, HmacAlg::Hs384, HmacAlg::Hs512] {
            assert_eq!(
                OpenSslHmac.hmac(alg, &key, data).unwrap(),
                OpenSslHmac.hmac_with_hash(alg.hash(), &key, data).unwrap(),
                "{alg:?}"
            );
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
