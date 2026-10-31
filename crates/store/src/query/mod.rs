//! The statements of this crate are built here, so that what must never be
//! forgotten cannot be: a table and a column are constants of the schema,
//! a column travels with its value, and the scope opens every `WHERE`.
//!
//! An atomic operation that this does not express stays constant SQL written
//! by hand in `stores/`, under the same rules.

pub(crate) mod bind;
pub(crate) mod ident;
pub(crate) mod insert;
pub(crate) mod select;
