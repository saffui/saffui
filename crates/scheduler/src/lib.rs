//! The passes that run on a timer: expired rows swept, the outbox walked,
//! directories synced and security notices sent. None of it answers a request.

pub mod jobs;
pub mod notices;
pub mod outbox;
