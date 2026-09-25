//! What a sign-in and the protocol keep while they run: logins in progress
//! and their failures, sessions, codes, pushed requests, spent proofs, and the
//! logout notices an ended login owes.

pub mod backchannel;
pub mod devices;
pub mod dpop;
pub mod form_post;
pub mod login;
pub mod logout_notices;
pub mod oidc;
pub mod pushed;
pub mod replay;
pub mod sessions;
pub mod source_failures;
