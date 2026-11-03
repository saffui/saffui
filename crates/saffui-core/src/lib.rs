//! The heart of the product: what it knows and decides, with no web framework,
//! no SQL driver and no cryptographic library linked.

pub mod app;
pub mod audit;
pub mod authz;
pub mod clients;
pub mod error;
pub mod ids;
pub mod keys;
pub mod oidc;
pub mod ports;
pub mod readiness;
pub mod secret;
pub mod settings;
pub mod tenancy;
#[cfg(feature = "testkit")]
pub mod testkit;
pub mod tokens;
