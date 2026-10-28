//! What tests use in place of the adapters: doubles that never touch a
//! network, and a way to drive a future that never has to wait.

pub mod drive;
pub mod memory;
