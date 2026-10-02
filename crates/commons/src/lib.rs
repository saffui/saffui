// The tests write process-wide environment variables, which is unsafe in
// this edition. Nothing the crate ships does.
#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod address;
pub mod error;
pub mod feature;
#[cfg(feature = "http")]
pub mod http;
pub mod observability;
pub mod pattern;
#[cfg(feature = "qr")]
pub mod qr;
pub mod secret;
pub mod walk;
