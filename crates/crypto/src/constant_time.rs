//! Comparing a secret without reporting how far off it was.
//!
//! A comparison that stops at the first differing byte answers faster for a
//! wrong guess that shares a prefix, and a caller who can measure that recovers
//! the secret one byte at a time.

use subtle::ConstantTimeEq;

/// Equal, in time that does not depend on where they differ.
///
/// A length mismatch does short-circuit, and that is wanted: the length of a
/// stored secret is not what is being protected, its contents are.
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_answers_what_a_plain_comparison_would() {
        assert!(eq(b"s3cr3t", b"s3cr3t"));
        assert!(!eq(b"s3cr3t", b"s3cr3T"));
        assert!(!eq(b"s3cr3t", b"s3cr3t "));
        assert!(!eq(b"", b"x"));
        assert!(eq(b"", b""));
    }
}
