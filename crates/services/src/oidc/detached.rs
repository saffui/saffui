use crypto::provider::{CryptoProvider, HashAlg, SignAlg};
use data_encoding::BASE64URL_NOPAD;

/// Not a choice: whoever verifies reads the algorithm off the token's header,
/// so a hash taken with anything else is one they compute differently.
fn paired_with(algorithm: SignAlg) -> HashAlg {
    match algorithm {
        SignAlg::Rs256 | SignAlg::Ps256 | SignAlg::Es256 => HashAlg::Sha256,
        SignAlg::Rs384 | SignAlg::Ps384 | SignAlg::Es384 => HashAlg::Sha384,
        SignAlg::Rs512 | SignAlg::Ps512 | SignAlg::Es512 => HashAlg::Sha512,
        // Ed25519 signs over SHA-512; the rule follows the curve.
        SignAlg::EdDsa => HashAlg::Sha512,
    }
}

/// The left half, base64url. Half because the claim proves the pairing and is
/// not the value: a whole digest confirms a guess at what it names.
pub fn half_hash(provider: &dyn CryptoProvider, algorithm: SignAlg, value: &str) -> Option<String> {
    let whole = provider
        .digest()
        .hash(paired_with(algorithm), value.as_bytes())
        .ok()?;
    Some(BASE64URL_NOPAD.encode(&whole[..whole.len() / 2]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::provider::CryptoConfig;
    use crypto::provider::openssl::OpenSslProvider;

    fn provider() -> OpenSslProvider {
        OpenSslProvider::new(&CryptoConfig {
            fips_required: false,
            pkcs11: None,
        })
        .expect("a software provider")
    }

    /// The example in §3.2.2.9: `jHyJmcnCtHfyHapWJIyGKQ` is the left half of
    /// the SHA-256 of that access token, and an implementation that took the
    /// right half or the whole thing would answer something else.
    #[test]
    fn the_left_half_is_what_the_specification_names() {
        assert_eq!(
            half_hash(
                &provider(),
                SignAlg::Rs256,
                "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
            )
            .as_deref(),
            Some("77QmUPtjPfzWtF2AnpK9RQ")
        );
    }

    /// The algorithm decides the digest, and a longer one is a longer half.
    #[test]
    fn a_longer_algorithm_takes_a_longer_half() {
        let hashed = |algorithm| half_hash(&provider(), algorithm, "a-token").expect("a hash");
        assert_eq!(hashed(SignAlg::Es256).len(), 22);
        assert_eq!(hashed(SignAlg::Es384).len(), 32);
        assert_eq!(hashed(SignAlg::Es512).len(), 43);
        assert_eq!(hashed(SignAlg::EdDsa), hashed(SignAlg::Es512));
        assert_ne!(hashed(SignAlg::Es256), hashed(SignAlg::Es384));
    }
}
