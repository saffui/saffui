//! Bare digests for legacy password formats.

use openssl::hash::{Hasher, MessageDigest};

use crate::provider::{CryptoError, LegacyDigest, LegacyDigestProvider, Result};

pub struct OpenSslLegacyDigest;

/// The only place a legacy digest name becomes an OpenSSL digest.
///
/// Separate from the table in `digest`, which maps the algorithms the rest of
/// the crate is allowed to use. Merging them would put MD5 one enum variant
/// away from every signature and MAC in the workspace.
fn message_digest(alg: LegacyDigest) -> MessageDigest {
    match alg {
        LegacyDigest::Md5 => MessageDigest::md5(),
        LegacyDigest::Sha1 => MessageDigest::sha1(),
        LegacyDigest::Sha256 => MessageDigest::sha256(),
        LegacyDigest::Sha512 => MessageDigest::sha512(),
    }
}

impl LegacyDigestProvider for OpenSslLegacyDigest {
    fn digest(&self, alg: LegacyDigest, data: &[u8]) -> Result<Vec<u8>> {
        // Under FIPS the MD5 fetch fails here, which is the point: a digest
        // this build refuses to compute must not come back as anything else.
        let mut hasher =
            Hasher::new(message_digest(alg)).map_err(|_| CryptoError::UnsupportedAlgorithm)?;
        hasher
            .update(data)
            .map_err(|_| CryptoError::OperationFailed)?;

        hasher
            .finish()
            .map(|digest| digest.to_vec())
            .map_err(|_| CryptoError::OperationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The published digest of "abc" for each algorithm.
    ///
    /// A known answer, because these exist to agree with hashes another system
    /// wrote years ago. An implementation that quietly substituted one digest
    /// for another would round-trip with itself and verify nobody's password.
    #[test]
    fn the_digests_of_abc() {
        let cases = [
            (LegacyDigest::Md5, "900150983cd24fb0d6963f7d28e17f72"),
            (
                LegacyDigest::Sha1,
                "a9993e364706816aba3e25717850c26c9cd0d89d",
            ),
            (
                LegacyDigest::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                LegacyDigest::Sha512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
        ];

        for (alg, expected) in cases {
            let digest = OpenSslLegacyDigest.digest(alg, b"abc").unwrap();
            assert_eq!(hex(&digest), expected, "{alg:?}");
        }
    }

    /// Each algorithm produces its own width, and the empty input is a digest
    /// like any other rather than an error.
    #[test]
    fn each_algorithm_has_its_own_width() {
        for (alg, width) in [
            (LegacyDigest::Md5, 16),
            (LegacyDigest::Sha1, 20),
            (LegacyDigest::Sha256, 32),
            (LegacyDigest::Sha512, 64),
        ] {
            assert_eq!(
                OpenSslLegacyDigest.digest(alg, b"").unwrap().len(),
                width,
                "{alg:?}"
            );
        }
    }

    /// The data reaches the digest.
    #[test]
    fn different_input_digests_differently() {
        let first = OpenSslLegacyDigest
            .digest(LegacyDigest::Sha256, b"abc")
            .unwrap();
        let second = OpenSslLegacyDigest
            .digest(LegacyDigest::Sha256, b"abd")
            .unwrap();

        assert_ne!(first, second);
    }
}
