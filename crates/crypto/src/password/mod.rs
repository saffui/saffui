//! Password storage policy, over the provider's primitives.

pub mod legacy;
pub mod migration;
pub mod phc;
pub mod storage;

pub use legacy::{LegacyHash, RehashUrgency, WeaknessLevel};
pub use migration::{
    VerifyPlan, burn_verification_time, verify_and_plan, verify_and_plan_with_policy,
};
pub use phc::{Argon2Variant, PhcArgon2, argon2id_below_policy};
pub use storage::StoredPassword;
