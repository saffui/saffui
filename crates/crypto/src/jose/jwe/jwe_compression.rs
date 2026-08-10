// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

use std::cmp::Eq;
use std::fmt::Debug;
use std::io;

/// Represent a algorithm of JWE zip header claim.
pub trait JweCompression: Debug + Send + Sync {
    /// Return the "zip" (compression algorithm) header parameter value of JWE.
    fn name(&self) -> &str;

    fn compress(&self, message: &[u8]) -> Result<Vec<u8>, io::Error>;

    fn decompress(&self, message: &[u8]) -> Result<Vec<u8>, io::Error>;

    fn box_clone(&self) -> Box<dyn JweCompression>;
}

impl PartialEq for Box<dyn JweCompression> {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl Eq for Box<dyn JweCompression> {}

impl Clone for Box<dyn JweCompression> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jose::jwe::zip::deflate::DeflateJweCompression;

    /// Comparing two boxed compressions must return, not recurse.
    ///
    /// Upstream wrote `self == other` in this impl, which resolves to the impl
    /// itself: every comparison of two `Box<dyn JweCompression>` recursed until
    /// the stack ran out. The same shape sits in the JWE and JWS algorithm
    /// traits, the content encryption trait, and `KeyPair`. Nothing caught it
    /// because a test that compares would take the process down with it, so
    /// there was no test.
    ///
    /// The equality is over the `zip` header parameter, which is what names a
    /// compression in a JWE header.
    /// `assert!` and not `assert_eq!`: the macro compares `*left == *right`,
    /// which tries to move the value out of the box.
    #[test]
    fn boxed_compressions_compare_by_name() {
        let a: Box<dyn JweCompression> = Box::new(DeflateJweCompression::Def);
        let b: Box<dyn JweCompression> = Box::new(DeflateJweCompression::Def);
        assert!(a == b);
        assert!(a == a.clone());
        assert_eq!(a.name(), "DEF");
    }
}
