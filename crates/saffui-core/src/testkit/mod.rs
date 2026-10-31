//! What tests use in place of the adapters: doubles that never touch a
//! network, a way to drive a future that never has to wait, and the contract
//! every storage adapter must pass.

pub mod clock;
pub mod contract;
pub mod drive;
pub mod memory;
pub mod random;
