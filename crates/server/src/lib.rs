//! The HTTP boundary, and nothing that decides anything.
//!
//! Handlers extract and delegate. What a request means is established in
//! `services`, what a policy answers is `authz`, and what reaches a row is
//! `store`; this crate turns those into a socket and back.

pub mod api;
pub mod error;
pub mod middleware;
