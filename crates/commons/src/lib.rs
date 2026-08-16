//! Shared types and error definitions used across all saffui crates.

pub mod error;
#[cfg(feature = "http")]
pub mod http;
pub mod observability;
pub mod secret;
