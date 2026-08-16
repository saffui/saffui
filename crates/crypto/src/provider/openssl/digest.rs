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

    use openssl::nid::Nid;

    const ALGORITHMS: [(HashAlg, Nid); 7] = [
        (HashAlg::Sha1, Nid::SHA1),
        (HashAlg::Sha256, Nid::SHA256),
        (HashAlg::Sha384, Nid::SHA384),
        (HashAlg::Sha512, Nid::SHA512),
        (HashAlg::Sha3_256, Nid::SHA3_256),
        (HashAlg::Sha3_384, Nid::SHA3_384),
        (HashAlg::Sha3_512, Nid::SHA3_512),
    ];

    /// `HashAlg::output_len` is declared in the seam, where no OpenSSL type is
    /// in reach to check it against. This is the join: the length the seam
    /// promises callers is the length the digest actually produces.
    #[test]
    fn declared_output_lengths_match_the_digests() {
        for (alg, _) in ALGORITHMS {
            assert_eq!(
                message_digest(alg).size(),
                alg.output_len(),
                "{alg:?} disagrees with its digest"
            );
        }
    }

    /// Each name maps to the digest it names, checked by identity.
    ///
    /// The length test above cannot see this: SHA-256 and SHA3-256 both produce
    /// 32 bytes, as do the 384 and 512 pairs, so the whole SHA-2/SHA-3 half of
    /// the table could be swapped without moving a single assertion. The two
    /// families are unrelated constructions, and callers asking for SHA-3 are
    /// usually asking for the one that is not Merkle-Damgard.
    #[test]
    fn each_name_maps_to_the_digest_it_names() {
        for (alg, nid) in ALGORITHMS {
            assert_eq!(
                message_digest(alg).type_(),
                nid,
                "{alg:?} is not mapped to {nid:?}"
            );
        }
    }
}
