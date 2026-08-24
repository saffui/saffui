//! The protocol plane: what a client speaks to, rather than what an
//! administrator drives.
//!
//! Unversioned by design. These paths are published by discovery, so they can
//! move without a client having written one down, and the one string that cannot
//! move, the issuer, carries no version for exactly that reason.

pub mod answering;
pub mod authorize;
pub mod backchannel;
pub mod basic;
pub mod binding;
pub mod caller;
pub mod discovery;
pub mod dto;
pub mod introspect;
pub mod keys;
pub mod login;
pub mod logout;
pub mod mail;
pub mod page;
pub mod par;
pub mod registration;
pub mod revoke;
pub mod token;
pub mod userinfo;
