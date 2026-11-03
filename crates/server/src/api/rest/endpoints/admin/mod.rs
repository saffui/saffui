//! The administration plane, under `/admin/v1`. Every handler declares the
//! capability it requires in its macro: `tests/capabilities.rs` reads them.

pub mod audit;
pub mod realm;
mod views;
