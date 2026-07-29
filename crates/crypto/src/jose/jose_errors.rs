use thiserror::Error;

/// Typed error contract for the JOSER layer.
///
/// Sesign rules (crypto-grade, for CSPN/CC auditability):
/// - Every failure maps to a NAMED, exhaustive variant — an auditor reads the
///   whole error surface at a glance and a caller can `match` on it.
/// - The `String` detail is always a message the crate itself controls.
///   Underlying errors (OpenSSL, serde, base64, ...) are NEVER propagated
///   verbatim, so no internal detail (key material hints, library internals)
///   leaks through the error path.
/// - `InvalidSignature` deliberately carries NO detail: a verification failure
///   must not hand an attacker an oracle. One generic variant, nothing more.

#[derive(Error, Debug)]
pub enum JoseError {
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),

    #[error("invalid JWT format: {0}")]
    InvalidJwtFormat(String),

    #[error("invalid JWK format: {0}")]
    InvalidJwkFormat(String),

    #[error("invalid JWS format: {0}")]
    InvalidJwsFormat(String),

    #[error("invalid JWE format: {0}")]
    InvalidJweFormat(String),

    #[error("invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("invalid JSON: {0}")]
    InvalidJson(String),

    #[error("invalid claim: {0}")]
    InvalidJClaim(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),
}