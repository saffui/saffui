//! The realm as the verifier of what a digital identity wallet presents.

pub use jsonld::base58;
pub mod certificates;
pub mod did;
pub mod identity;
pub mod issuers;
mod linked_data;
pub mod presentation;
pub mod revocation;
pub mod status;
