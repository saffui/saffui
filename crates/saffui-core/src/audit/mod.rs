//! The audit chain. Every event of a realm is linked to the one before by a
//! hash, so that none can be removed, altered or reordered without the chain
//! saying so. An event is appended in the transaction of the change it
//! records: there is no change without its event, and no event without its
//! change.

pub mod append;
pub mod canonical;
pub mod store;
pub mod verify;

use crate::ports::crypto::Digester;

/// What happened, by a name that never changes once written in a chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    RealmCreated,
}

impl EventKind {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::RealmCreated => "realm.created",
        }
    }
}

/// The hash of the first link: there is nothing before it.
pub const GENESIS_HASH: [u8; 32] = [0; 32];

/// The hash that links an event to the chain: the previous hash, the
/// sequence number on 8 big-endian bytes, then the stored bytes of the
/// envelope, exactly as stored.
#[must_use]
pub fn hash_link(digester: &dyn Digester, previous: &[u8], seq: i64, envelope: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(previous.len() + 8 + envelope.len());
    preimage.extend_from_slice(previous);
    preimage.extend_from_slice(&seq.to_be_bytes());
    preimage.extend_from_slice(envelope);
    digester.sha256(&preimage)
}
