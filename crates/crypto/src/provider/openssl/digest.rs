//! The one place a [`HashAlg`] becomes an OpenSSL digest.
//!
//! Three of the sub-providers need this mapping. Written once so the three
//! cannot drift apart, and kept out of the seam so `HashAlg` stays a name.

use openssl::hash::MessageDigest;

use crate::provider::HashAlg;

pub fn message_digest(alg: HashAlg) -> MessageDigest {
    match alg {
        HashAlg::Sha1 => MessageDigest::sha1(),
        HashAlg::Sha256 => MessageDigest::sha256(),
        HashAlg::Sha384 => MessageDigest::sha384(),
        HashAlg::Sha512 => MessageDigest::sha512(),
        HashAlg::Sha3_256 => MessageDigest::sha3_256(),
        HashAlg::Sha3_384 => MessageDigest::sha3_384(),
        HashAlg::Sha3_512 => MessageDigest::sha3_512(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `HashAlg::output_len` is declared in the seam, where no OpenSSL type is
    /// in reach to check it against. This is the join: the length the seam
    /// promises callers is the length the digest actually produces.
    #[test]
    fn declared_output_lengths_match_the_digests() {
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
                message_digest(alg).size(),
                alg.output_len(),
                "{alg:?} disagrees with its digest"
            );
        }
    }
}
