//! The domain vocabulary.
//!
//! A type here says what something *is*. How it is stored belongs to the store
//! and who may see it to the API layer; a model that knew either would put that
//! answer within reach of every caller.

pub mod auditable;
pub mod broker;
pub mod entities;
pub mod paging;
pub mod representation;
pub mod search;
pub mod sessions;
pub mod str_enum;
