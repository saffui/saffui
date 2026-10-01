//! The wallet verifier, in a process that runs it. The verifier is
//! experimental and off unless the process turns it on, which a process does
//! once: its cases share a binary of their own, and each turns it on first.
mod support;

#[path = "grouped/credential_status.rs"]
mod credential_status;
#[path = "grouped/verifier_certificate.rs"]
mod verifier_certificate;
#[path = "grouped/wallet.rs"]
mod wallet;
#[path = "grouped/wallet_login.rs"]
mod wallet_login;
