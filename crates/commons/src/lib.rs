//! Shared types and error definitions used across all saffui crates.

pub mod error;
pub mod feature;
#[cfg(feature = "http")]
pub mod http;
pub mod observability;
pub mod secret;
