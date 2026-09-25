//! What this deployment says to the outside: calls under the egress policy, the
//! directories it asks, the messages it sends and the tellings it pushes. None
//! of it needs a request to run in, which is why it sits below the server.

pub mod delivery;
pub mod directory;
pub mod egress;
pub mod pushes;
mod sealing;
pub mod senders;
pub mod smtp;
pub mod smtp_probe;

pub use sealing::Sealing;
