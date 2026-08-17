//! Sessions: what a login produced, and what a login attempt is still doing.
//!
//! The records only. What holds a live session in memory, with its locks and its
//! loaded realm and client, belongs to whatever runs sessions. A model that
//! carried those would put a concurrency primitive in the vocabulary every layer
//! shares.

pub mod compound_id;
pub mod records;
