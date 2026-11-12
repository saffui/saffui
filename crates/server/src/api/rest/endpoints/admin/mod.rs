//! The administration plane, under `/admin/v1`. Every handler declares the
//! capability it requires in its macro: `tests/capabilities.rs` reads them.

pub mod audit;
pub mod client;
pub mod group;
mod listing;
pub mod mapper;
pub mod policy;
pub mod realm;
pub mod relation;
pub mod role;
pub mod user;
mod views;
