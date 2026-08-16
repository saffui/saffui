//! Password storage policy, over the provider's primitives.

pub mod legacy;
pub mod phc;
pub mod storage;

pub use legacy::{LegacyHash, RehashUrgency, WeaknessLevel};
pub use phc::{Argon2Variant, PhcArgon2, argon2id_below_policy};
pub use storage::StoredPassword;
