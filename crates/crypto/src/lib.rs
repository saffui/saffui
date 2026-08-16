//! Cryptographic primitives for saffui, backed by OpenSSL.

// A binary that claims FIPS while linking ChaCha20 is a contradiction, and the
// place to catch it is the build rather than an audit reading the feature list.
#[cfg(all(feature = "fips-strict", feature = "chacha20"))]
compile_error!("feature 'fips-strict' is incompatible with the non-FIPS 'chacha20' cipher");

pub mod envelope;
pub mod jose;
pub mod otp;
pub mod password;
pub mod provider;
pub mod thumbprint;
