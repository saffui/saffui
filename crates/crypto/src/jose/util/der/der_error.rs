// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DerError {
    #[error("Unexpected end of input.")]
    UnexpectedEndOfInput,

    #[error("Invalid tag: {0}")]
    InvalidTag(String),

    #[error("Invalid length: {0}")]
    InvalidLength(String),

    #[error("Invalid contents: {0}")]
    InvalidContents(String),

    #[error("Overflow length.")]
    Overflow,

    #[error("Failed to read: {0}")]
    ReadFailure(#[source] std::io::Error),
}
