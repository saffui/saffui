//! What a policy set answers, and what it refuses to answer.
//!
//! # Three outcomes
//!
//! A decision is `Permit`, `Deny` or `Indeterminate`. The third is not a
//! nicety. Negative logic exists, it swaps the first two, and a policy layer
//! with two outcomes therefore turns every inability into an unconditional
//! grant: a claim nobody collected, a pattern that would not compile, a binding
//! a deletion elsewhere emptied, each becomes a permit for everybody the moment
//! somebody writes `logic: negative`. Here `Indeterminate` is a fixed point of
//! negation, and it survives every fold until it meets the one place a decision
//! has to become an answer.
//!
//! # Pure
//!
//! No database, no clock, no async. The instant is an argument, the policies
//! are an argument, the facts are an argument. Two consequences: the same
//! question gives the same answer twice, so a recorded decision can be replayed
//! against the policies as they stand and the two compared; and the surface
//! that lets an administrator test a policy and the surface that decides a real
//! request call the same function with the same facts, so there is no second
//! evaluator to disagree with the first.
//!
//! # Every fact is stated
//!
//! Nothing in [`Request`] is optional and nothing defaults. A dimension the
//! caller could not establish is said so by name, and a rule that reads it
//! answers `Indeterminate`. An empty set is a caller who holds nothing; it is
//! never a set nobody filled in, because that shape cannot be built.

mod compare;
mod decide;
mod fold;
mod policies;
mod request;
mod rule;
mod verdict;
mod window;

pub use decide::{permission, policy};
pub use fold::{apply, fold};
pub use policies::Evaluable;
pub use request::{Caller, Declared, Membership, Presented, Request, Resolved, Target, Through};
pub use verdict::{Reason, Verdict};
