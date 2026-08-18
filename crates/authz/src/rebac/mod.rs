//! The other engine's language: what a realm's relationships mean.
//!
//! A schema names types, the relations that store edges between them, and the
//! permissions computed from those edges. It is written by an administrator,
//! compiled once, and stored in both forms, because recompiling what was
//! imported would make a realm decide by something nobody exported.

pub mod ast;
pub mod compile;
pub mod parse;

pub use ast::Schema;
pub use compile::{CompiledSchema, FORMAT, Faults, Parts, Rule, SubjectType, compile};
pub use parse::{ParseError, Unreadable, parse};
