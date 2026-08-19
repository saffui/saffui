//! What an orchestrator asks, and nothing a caller does.
//!
//! On a listener of its own, outside every scope, every guard and every limit.
//! A probe that has to authenticate is a probe that fails when authentication
//! fails, which is the moment it is most needed; and one behind a rate limiter
//! gets a pod killed by its own traffic.

pub mod health;
