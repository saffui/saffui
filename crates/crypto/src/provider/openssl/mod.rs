//! The OpenSSL backend.
//!
//! One file per trait the seam declares, so a change to how HMAC is computed
//! cannot reach the code that signs. `digest` is the exception: three of them
//! need the same hash-to-digest mapping, and one copy cannot drift.

pub mod aead;
pub mod digest;
pub mod hmac;
pub mod kdf;
pub mod password;
pub mod rand;
pub mod signer;
