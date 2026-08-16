// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum JoseError {
    #[error("Unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(#[source] anyhow::Error),

    #[error("Invalid JWT format: {0}")]
    InvalidJwtFormat(#[source] anyhow::Error),

    #[error("Invalid JWK format: {0}")]
    InvalidJwkFormat(#[source] anyhow::Error),

    #[error("Invalid JWS format: {0}")]
    InvalidJwsFormat(#[source] anyhow::Error),

    #[error("Invalid JWE format: {0}")]
    InvalidJweFormat(#[source] anyhow::Error),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(#[source] anyhow::Error),

    #[error("Invalid json: {0}")]
    InvalidJson(#[source] anyhow::Error),

    #[error("Invalid claim: {0}")]
    InvalidClaim(#[source] anyhow::Error),

    #[error("Invalid signature: {0}")]
    InvalidSignature(#[source] anyhow::Error),
}
