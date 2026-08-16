//! Hashing over OpenSSL.

use openssl::hash::Hasher;

use crate::provider::openssl::digest::message_digest;
use crate::provider::{CryptoError, DigestProvider, HashAlg, Result};

pub struct OpenSslDigest;

impl DigestProvider for OpenSslDigest {
    fn hash(&self, alg: HashAlg, data: &[u8]) -> Result<Vec<u8>> {
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

    /// The published digest of "abc" under every algorithm the seam names.
    ///
    /// SHA-2 and SHA-3 are unrelated constructions that agree on output width,
    /// so a table that swapped them would be invisible to any test that only
    /// measured length.
    #[test]
    fn the_digests_of_abc() {
        let cases = [
            (HashAlg::Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                HashAlg::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                HashAlg::Sha384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                 8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                HashAlg::Sha512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                HashAlg::Sha3_256,
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            ),
            (
                HashAlg::Sha3_384,
                "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2\
                 98d88cea927ac7f539f1edf228376d25",
            ),
            (
                HashAlg::Sha3_512,
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
                 10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
            ),
        ];

        for (alg, expected) in cases {
            assert_eq!(
                hex(&OpenSslDigest.hash(alg, b"abc").unwrap()),
                expected,
                "{alg:?}"
            );
        }
    }

    /// Every algorithm produces the width the seam promises, and the empty
    /// input is a digest like any other.
    #[test]
    fn each_algorithm_produces_its_declared_width() {
        for alg in [
            HashAlg::Sha1,
            HashAlg::Sha256,
            HashAlg::Sha384,
            HashAlg::Sha512,
            HashAlg::Sha3_256,
            HashAlg::Sha3_384,
            HashAlg::Sha3_512,
        ] {
            assert_eq!(
                OpenSslDigest.hash(alg, b"").unwrap().len(),
                alg.output_len(),
                "{alg:?}"
            );
        }
    }

    /// The data reaches the digest.
    #[test]
    fn different_input_hashes_differently() {
        assert_ne!(
            OpenSslDigest.hash(HashAlg::Sha256, b"abc").unwrap(),
            OpenSslDigest.hash(HashAlg::Sha256, b"abd").unwrap()
        );
    }
}
