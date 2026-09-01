// A binary that claims FIPS while linking ChaCha20 is a contradiction, and the
// place to catch it is the build rather than an audit reading the feature list.
#[cfg(all(feature = "fips-strict", feature = "chacha20"))]
compile_error!("feature 'fips-strict' is incompatible with the non-FIPS 'chacha20' cipher");

// ML-DSA and ML-KEM live in OpenSSL's default provider, not the validated one,
// so a build cannot claim FIPS and link them. Same reasoning as ChaCha20 above,
// and the same place to catch it.
#[cfg(all(feature = "fips-strict", feature = "pq-hybrid"))]
compile_error!(
    "feature 'fips-strict' is incompatible with 'pq-hybrid': ML-DSA and ML-KEM are not FIPS-validated"
);

/// Re-exported because this crate's API hands back secrets in its types, and
/// a consumer that pulled its own copy could hold a different version of them.
pub use secrecy;

pub mod constant_time;
pub mod envelope;
pub mod jose;
pub mod otp;
pub mod password;
pub mod provider;
pub mod secret;
pub mod thumbprint;
pub mod x509;

/// The optional capabilities this build of the crypto crate carries, by the
/// registry slugs. Spelled here because only this crate sees its own cfg.
pub fn compiled_features() -> &'static [&'static str] {
    const CARRIED: &[&str] = &[
        #[cfg(feature = "chacha20")]
        "chacha20",
        #[cfg(feature = "pq-hybrid")]
        "pq-hybrid",
        #[cfg(feature = "fips-strict")]
        "fips-strict",
        #[cfg(feature = "pkcs11")]
        "pkcs11",
    ];
    CARRIED
}
