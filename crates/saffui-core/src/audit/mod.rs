//! The audit chain. Every event of a realm is linked to the one before by a
//! hash, so that none can be removed, altered or reordered without the chain
//! saying so.

pub mod canonical;
