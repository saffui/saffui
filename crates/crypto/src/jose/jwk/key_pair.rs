// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

use std::fmt::Debug;

use crate::jose::jwk::Jwk;

pub trait KeyPair: Debug + Send + Sync {
    /// Return the applicatable algorithm.
    fn algorithm(&self) -> Option<&str>;

    /// Return the applicatable key ID.
    fn key_id(&self) -> Option<&str>;

    fn to_der_private_key(&self) -> Vec<u8>;
    fn to_der_public_key(&self) -> Vec<u8>;
    fn to_pem_private_key(&self) -> Vec<u8>;
    fn to_pem_public_key(&self) -> Vec<u8>;
    fn to_jwk_private_key(&self) -> Jwk;
    fn to_jwk_public_key(&self) -> Jwk;
    fn to_jwk_key_pair(&self) -> Jwk;

    fn box_clone(&self) -> Box<dyn KeyPair>;
}

impl PartialEq for Box<dyn KeyPair> {
    // On the public encoding, not the private one: the public key identifies the
    // pair just as well, and comparing secret material byte by byte is both
    // unnecessary here and not constant time.
    fn eq(&self, other: &Self) -> bool {
        self.to_der_public_key() == other.to_der_public_key()
    }
}

impl Eq for Box<dyn KeyPair> {}

impl Clone for Box<dyn KeyPair> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
