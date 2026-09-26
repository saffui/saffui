//! The wallet verifier, in a process that runs it. The verifier is
//! experimental and off unless the process turns it on, which a process does
//! once: its cases share a binary of their own, and each turns it on first.
mod support;

#[path = "grouped/wallet.rs"]
mod wallet;
