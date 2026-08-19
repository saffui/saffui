//! The protocol plane: what a client speaks to, rather than what an
//! administrator drives.
//!
//! Unversioned by design. These paths are published by discovery, so they can
//! move without a client having written one down, and the one string that cannot
//! move, the issuer, carries no version for exactly that reason.

pub mod basic;
pub mod dto;
pub mod token;
