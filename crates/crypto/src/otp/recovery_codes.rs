use data_encoding::BASE32_NOPAD;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::provider::{RandProvider, Result};

/// Random bytes per code: ten, which is exactly sixteen base32 characters and
/// eighty bits — no padding to strip and nothing to explain to the user.
const ENTROPY_BYTES: usize = 10;

/// Characters between dashes, for reading a code off paper.
const GROUP: usize = 4;

/// Generate `count` codes, each dash-separated lowercase base32.
///
/// A count of zero yields no codes rather than an error: a policy with no
/// recovery path is unwise, not malformed, and that is the caller's call.
pub fn generate_recovery_codes(
    rand: &dyn RandProvider,
    count: usize,
) -> Result<Vec<Zeroizing<String>>> {
    (0..count).map(|_| generate_one(rand)).collect()
}

fn generate_one(rand: &dyn RandProvider) -> Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new([0u8; ENTROPY_BYTES]);
    rand.fill(raw.as_mut())?;

    let encoded = Zeroizing::new(BASE32_NOPAD.encode(raw.as_ref()).to_lowercase());

    // Grouped a character at a time. Chunking the bytes would need a fallible
    // UTF-8 conversion whose failure branch could only ever drop part of a code
    // silently; base32 is ASCII, so there is nothing to convert.
    let mut grouped = String::with_capacity(encoded.len() + encoded.len() / GROUP);
    for (index, character) in encoded.chars().enumerate() {
        if index > 0 && index % GROUP == 0 {
            grouped.push('-');
        }
        grouped.push(character);
    }

    Ok(Zeroizing::new(grouped))
}

/// Strip the formatting a user will not reproduce: dashes, spaces, and case.
fn normalise(code: &str) -> Zeroizing<String> {
    Zeroizing::new(
        code.chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .flat_map(char::to_lowercase)
            .collect(),
    )
}

/// Compare two codes, ignoring formatting, without leaking which byte differs.
///
/// `ct_eq` on slices is documented to short-circuit on a length mismatch and to
/// be content-independent otherwise, which is the behaviour wanted here: how
/// long a code is happens to be fixed and public, which byte of it is wrong is
/// not.
fn code_eq(candidate: &str, valid: &str) -> Choice {
    normalise(candidate)
        .as_bytes()
        .ct_eq(normalise(valid).as_bytes())
}

/// Whether a candidate matches a known-valid code.
pub fn verify_recovery_code(candidate: &str, valid: &str) -> bool {
    code_eq(candidate, valid).into()
}

/// Find which of `valid` a candidate matches, so the caller can mark that one
/// used.
///
/// The whole set is scanned and the index is moved into place by a constant-time
/// select. Neither the position of the match nor its presence changes the work
/// done — an early return would tell anyone timing it how far down the list
/// their guess landed, which is a map of the set drawn one attempt at a time.
pub fn find_matching_code(candidate: &str, valid: &[impl AsRef<str>]) -> Option<usize> {
    let mut hit = Choice::from(0u8);
    let mut found = 0u64;

    for (index, code) in valid.iter().enumerate() {
        let eq = code_eq(candidate, code.as_ref());
        found = u64::conditional_select(&found, &(index as u64), eq);
        hit |= eq;
    }

    bool::from(hit).then_some(found as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::provider::openssl::rand::OpenSslRand;

    fn codes(count: usize) -> Vec<Zeroizing<String>> {
        generate_recovery_codes(&OpenSslRand, count).unwrap()
    }

    /// Every code is sixteen base32 characters, grouped in fours, and no two of
    /// them repeat.
    #[test]
    fn codes_are_well_formed_and_distinct() {
        let generated = codes(12);
        assert_eq!(generated.len(), 12);

        for code in &generated {
            let code = code.as_str();
            assert_eq!(code.len(), 16 + 3, "{code} is not four groups of four");
            assert_eq!(code.matches('-').count(), 3, "{code}");

            let bare = code.replace('-', "");
            assert_eq!(bare.len(), 16);
            assert!(
                BASE32_NOPAD.decode(bare.to_uppercase().as_bytes()).is_ok(),
                "{code} is not base32"
            );
        }

        let mut seen: Vec<&str> = generated.iter().map(|c| c.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 12, "two codes repeated");
    }

    /// A count of zero is a short list, not an error.
    #[test]
    fn no_codes_were_asked_for_and_none_were_made() {
        assert!(codes(0).is_empty());
    }

    /// The user will retype a code without its dashes, in capitals, with a
    /// space where a dash was. All of that still matches.
    #[test]
    fn formatting_the_user_will_not_reproduce_is_ignored() {
        let code = codes(1).pop().unwrap();

        for variant in [
            code.to_uppercase(),
            code.replace('-', ""),
            code.replace('-', " "),
            format!("  {}  ", code.replace('-', "\t")),
        ] {
            assert!(
                verify_recovery_code(&variant, &code),
                "{variant:?} did not match its own code"
            );
        }
    }

    /// A code that is not the one, or not the length of one, does not match.
    #[test]
    fn anything_else_is_refused() {
        let generated = codes(2);
        let code = &generated[0];

        assert!(!verify_recovery_code(&generated[1], code));
        assert!(!verify_recovery_code("", code));
        assert!(!verify_recovery_code(&code[..code.len() - 1], code));
        assert!(!verify_recovery_code(&format!("{}a", code.as_str()), code));

        // One character off, at both ends, where a prefix or suffix comparison
        // would still agree.
        let bare = code.replace('-', "");
        let mut first = bare.clone().into_bytes();
        first[0] ^= 1;
        assert!(!verify_recovery_code(
            &String::from_utf8(first).unwrap(),
            code
        ));

        let mut last = bare.into_bytes();
        *last.last_mut().unwrap() ^= 1;
        assert!(!verify_recovery_code(
            &String::from_utf8(last).unwrap(),
            code
        ));
    }

    /// The match is reported by index, including at both ends of the set.
    #[test]
    fn the_matching_code_is_reported_by_index() {
        let generated = codes(5);

        for (index, code) in generated.iter().enumerate() {
            assert_eq!(find_matching_code(code, &generated), Some(index));
            assert_eq!(
                find_matching_code(&code.to_uppercase(), &generated),
                Some(index),
                "a retyped code at {index} was not found"
            );
        }

        assert_eq!(find_matching_code("not-a-real-code", &generated), None);
        assert_eq!(find_matching_code(&generated[0], &[] as &[String]), None);
    }
}
