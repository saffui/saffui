//! Compiling a pattern an administrator wrote, under the bounds that make it
//! safe to keep.
//!
//! A pattern reaches this crate from two places: the regular expression a
//! policy matches a claim against, and the one a realm holds its passwords to.
//! Both are written by an administrator and run against a value somebody else
//! supplied, so both are compiled once, when they are written, and refused
//! there if they will not compile.
//!
//! The engine backing this has no backtracking, so the peril is not a pattern
//! that runs forever on a crafted input. It is a pattern whose compiled program
//! or lazy automaton is large enough to matter, which is what the two limits
//! below bound. The length bound is separate and comes first: it refuses the
//! input before anything is built from it.

use regex::{Regex, RegexBuilder};

/// The longest pattern accepted, in bytes.
pub const MAX_PATTERN_LEN: usize = 512;

/// Ceiling on the compiled program.
const PROGRAM_LIMIT: usize = 64 * 1024;

/// Ceiling on the lazy automaton's cache.
const AUTOMATON_LIMIT: usize = 256 * 1024;

/// Why a pattern was refused.
///
/// Neither variant carries the pattern. What is refused is written by an
/// administrator and read back by whoever can see the error, and a rejected
/// value echoed into a message is a value that has left the field it was
/// submitted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    #[error("the pattern is {length} bytes, and {MAX_PATTERN_LEN} is the most that is accepted")]
    TooLong { length: usize },
    /// It is not a pattern, or it is one whose compiled form exceeds a limit.
    #[error("the pattern does not compile within the limits")]
    Malformed,
}

/// Compile a pattern, or say why not.
///
/// Called on the write path. A caller that compiles at match time instead pays
/// the cost per decision and discovers a bad pattern in the middle of one,
/// where the only answers left are to refuse or to permit.
pub fn compile(pattern: &str) -> Result<Regex, PatternError> {
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(PatternError::TooLong {
            length: pattern.len(),
        });
    }

    RegexBuilder::new(pattern)
        .size_limit(PROGRAM_LIMIT)
        .dfa_size_limit(AUTOMATON_LIMIT)
        .build()
        .map_err(|_| PatternError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pattern_that_compiles_comes_back_usable() {
        let compiled = compile(r"^[a-z]+@example\.test$").expect("a pattern");
        assert!(compiled.is_match("ada@example.test"));
        assert!(!compiled.is_match("ada@elsewhere.test"));
    }

    #[test]
    fn what_is_not_a_pattern_is_refused() {
        assert_eq!(compile("([a-z").err(), Some(PatternError::Malformed));
    }

    /// The length is read before anything is built, so an enormous pattern is
    /// refused without being compiled to find that out.
    #[test]
    fn a_pattern_longer_than_the_bound_is_refused_for_its_length() {
        let long = "a".repeat(MAX_PATTERN_LEN + 1);
        assert_eq!(
            compile(&long).err(),
            Some(PatternError::TooLong {
                length: MAX_PATTERN_LEN + 1
            })
        );
        assert!(compile(&"a".repeat(MAX_PATTERN_LEN)).is_ok());
    }

    /// Within the length bound and still too big to keep. A repetition count is
    /// three characters and the program it expands to is not, which is why the
    /// length bound cannot be the only one.
    #[test]
    fn a_short_pattern_that_expands_past_the_limit_is_refused() {
        let expanding = r"(?:\p{L}\p{N}\p{P}\p{S}){5000}";
        assert!(expanding.len() <= MAX_PATTERN_LEN);
        assert_eq!(compile(expanding).err(), Some(PatternError::Malformed));
    }

    /// The refusal says what is wrong with the pattern and does not repeat it.
    #[test]
    fn a_refusal_does_not_echo_what_was_submitted() {
        let submitted = "([a-z";
        let refused = compile(submitted).expect_err("a refusal");
        assert!(!refused.to_string().contains(submitted));
    }
}
