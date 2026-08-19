//! The admin plane.
//!
//! What a request is allowed to do is decided by four questions asked in order,
//! and by an action the route declares rather than one derived from its path.

pub mod admin;
pub mod app;
pub mod enforce;
pub mod error;
pub mod guard;
pub mod realms;
pub mod routes;
