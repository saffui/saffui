//! The heart of the product: what it knows and decides, with no web framework,
//! no SQL driver and no cryptographic library linked.

pub mod app;
pub mod error;
pub mod ids;
pub mod oidc;
pub mod ports;
pub mod readiness;
pub mod settings;
pub mod tenancy;
#[cfg(feature = "testkit")]
pub mod testkit;
