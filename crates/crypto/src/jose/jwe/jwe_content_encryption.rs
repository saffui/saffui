// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

use std::cmp::Eq;
use std::fmt::Debug;

use crate::jose::JoseError;

/// Represent a algorithm of JWE enc header claim.
pub trait JweContentEncryption: Debug + Send + Sync {
    /// Return the "enc" (encryption) header parameter value of JWE.
    fn name(&self) -> &str;

    fn key_len(&self) -> usize;

    fn iv_len(&self) -> usize;

    fn encrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        message: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), JoseError>;

    fn decrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypted_message: &[u8],
        aad: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<Vec<u8>, JoseError>;

    fn box_clone(&self) -> Box<dyn JweContentEncryption>;
}

impl PartialEq for Box<dyn JweContentEncryption> {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl Eq for Box<dyn JweContentEncryption> {}

impl Clone for Box<dyn JweContentEncryption> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
