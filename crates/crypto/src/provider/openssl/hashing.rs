use openssl::hash::{Hasher, MessageDigest};

use crate::provider::openssl::digest::message_digest;
use crate::provider::{CryptoError, DigestProvider, HashAlg, Result, XofAlg};

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

    fn xof(&self, alg: XofAlg, data: &[u8], len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Err(CryptoError::InvalidParams);
        }

        let digest = match alg {
            XofAlg::Shake128 => MessageDigest::shake_128(),
            XofAlg::Shake256 => MessageDigest::shake_256(),
        };

        let mut hasher = Hasher::new(digest).map_err(|_| CryptoError::UnsupportedAlgorithm)?;
        hasher
            .update(data)
            .map_err(|_| CryptoError::OperationFailed)?;

        // The squeeze length is the buffer's length, not a parameter, so the
        // buffer is sized first and filled in place.
        let mut squeezed = vec![0u8; len];
        hasher
            .finish_xof(&mut squeezed)
            .map_err(|_| CryptoError::OperationFailed)?;

        Ok(squeezed)
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

    /// The published SHAKE outputs for the empty input.
    ///
    /// A XOF has no natural length, so nothing about its shape pins it: any
    /// implementation returns the number of bytes asked for. Only a known
    /// answer says they are the right ones.
    #[test]
    fn the_shake_outputs_of_the_empty_input() {
        assert_eq!(
            hex(&OpenSslDigest.xof(XofAlg::Shake128, b"", 32).unwrap()),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
        assert_eq!(
            hex(&OpenSslDigest.xof(XofAlg::Shake256, b"", 64).unwrap()),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
    }

    /// A longer squeeze extends a shorter one rather than replacing it.
    ///
    /// This is what makes it extendable-output rather than a family of
    /// digests: the stream is one, and the length only says where to stop. An
    /// implementation that re-hashed per length would pass every other test
    /// here and interoperate with nothing.
    #[test]
    fn a_longer_squeeze_extends_a_shorter_one() {
        for alg in [XofAlg::Shake128, XofAlg::Shake256] {
            let short = OpenSslDigest.xof(alg, b"saffui", 16).unwrap();
            let long = OpenSslDigest.xof(alg, b"saffui", 200).unwrap();

            assert_eq!(&long[..16], short.as_slice(), "{alg:?}");
            assert_eq!(long.len(), 200);
        }
    }

    /// The requested length is what comes back, including lengths that are not
    /// multiples of the sponge's rate.
    #[test]
    fn the_requested_length_is_what_comes_back() {
        for len in [1usize, 7, 31, 32, 168, 169, 1000] {
            for alg in [XofAlg::Shake128, XofAlg::Shake256] {
                assert_eq!(
                    OpenSslDigest.xof(alg, b"data", len).unwrap().len(),
                    len,
                    "{alg:?} at {len}"
                );
            }
        }
    }

    /// A zero-length squeeze is refused rather than answered with nothing.
    #[test]
    fn a_zero_length_squeeze_is_refused() {
        for alg in [XofAlg::Shake128, XofAlg::Shake256] {
            assert!(
                matches!(
                    OpenSslDigest.xof(alg, b"data", 0),
                    Err(CryptoError::InvalidParams)
                ),
                "{alg:?}"
            );
        }
    }

    /// The two functions are different, and so are two inputs.
    ///
    /// SHAKE128 and SHAKE256 differ in capacity, not in output length, so
    /// asking both for the same number of bytes must not give the same bytes.
    #[test]
    fn the_two_functions_and_two_inputs_stay_apart() {
        let one = OpenSslDigest.xof(XofAlg::Shake128, b"data", 32).unwrap();
        let other = OpenSslDigest.xof(XofAlg::Shake256, b"data", 32).unwrap();
        assert_ne!(one, other);

        assert_ne!(
            OpenSslDigest.xof(XofAlg::Shake256, b"data", 32).unwrap(),
            OpenSslDigest.xof(XofAlg::Shake256, b"dat", 32).unwrap()
        );
    }

    /// A XOF is not the fixed digest of the same family.
    ///
    /// SHA3-256 and SHAKE256 pad the same permutation differently, so a
    /// 32-byte squeeze is not the SHA3-256 digest. Mapping one to the other
    /// would look plausible and agree with nobody.
    #[test]
    fn a_squeeze_is_not_the_fixed_digest_of_its_family() {
        assert_ne!(
            OpenSslDigest.xof(XofAlg::Shake256, b"abc", 32).unwrap(),
            OpenSslDigest.hash(HashAlg::Sha3_256, b"abc").unwrap()
        );
    }

    /// The declared strength is the one NIST gives each function.
    #[test]
    fn each_function_declares_its_own_strength() {
        assert_eq!(XofAlg::Shake128.strength_bits(), 128);
        assert_eq!(XofAlg::Shake256.strength_bits(), 256);
    }
}
