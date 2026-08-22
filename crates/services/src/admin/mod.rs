//! What an administrator writes, behind the plane that checked who they are.
//!
//! Every write here is one the provisioning also makes on first boot, so the
//! two share a function rather than a shape: a client born at the console and
//! one born at the command line are the same client.

pub mod clients;
pub mod users;
