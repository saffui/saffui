//! The heart of the product: what it knows and decides, with no web framework,
//! no SQL driver and no cryptographic library linked.

pub mod app;
pub mod ports;
pub mod readiness;
#[cfg(feature = "testkit")]
pub mod testkit;
