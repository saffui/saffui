//! Proof Key for Code Exchange (RFC 7636), S256 only: the plain method lets
//! whoever saw the request redeem the code.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::ports::crypto::Digester;

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)
}

/// Tells whether a challenge has the shape of an S256 challenge: the 43
/// characters of 32 bytes in base64url.
#[must_use]
pub fn is_well_formed_challenge(challenge: &str) -> bool {
    challenge.len() == 43
        && URL_SAFE_NO_PAD
            .decode(challenge)
            .is_ok_and(|bytes| bytes.len() == 32)
}

/// Tells whether `verifier` is the secret `challenge` was made from.
#[must_use]
pub fn matches_challenge(digester: &dyn Digester, verifier: &str, challenge: &str) -> bool {
    if !(43..=128).contains(&verifier.len()) || !verifier.bytes().all(is_unreserved) {
        return false;
    }
    let computed = URL_SAFE_NO_PAD.encode(digester.sha256(verifier.as_bytes()));
    digester.equal_in_constant_time(computed.as_bytes(), challenge.as_bytes())
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::{is_well_formed_challenge, matches_challenge};
    use crate::ports::crypto::Digester;
    use crate::testkit::digest::WeakDigester;

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn challenge_of(verifier: &str) -> String {
        URL_SAFE_NO_PAD.encode(WeakDigester.sha256(verifier.as_bytes()))
    }

    #[test]
    fn a_verifier_matches_the_challenge_made_from_it_and_no_other() {
        let challenge = challenge_of(VERIFIER);

        assert!(matches_challenge(&WeakDigester, VERIFIER, &challenge));
        assert!(!matches_challenge(
            &WeakDigester,
            &VERIFIER.replace('d', "e"),
            &challenge
        ));
        assert!(!matches_challenge(
            &WeakDigester,
            VERIFIER,
            &challenge_of("another-verifier-of-the-right-length-0123456789")
        ));
    }

    #[test]
    fn a_verifier_too_short_too_long_or_with_a_reserved_character_never_matches() {
        for verifier in ["short", &"a".repeat(129), &format!("{}+", &VERIFIER[1..])] {
            assert!(
                !matches_challenge(&WeakDigester, verifier, &challenge_of(verifier)),
                "{verifier}"
            );
        }
    }

    #[test]
    fn a_challenge_is_43_characters_of_base64url() {
        assert!(is_well_formed_challenge(&challenge_of(VERIFIER)));
        assert!(!is_well_formed_challenge("plain-text-challenge"));
        assert!(!is_well_formed_challenge(&"=".repeat(43)));
    }
}
