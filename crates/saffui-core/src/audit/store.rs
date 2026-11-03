use async_trait::async_trait;

use crate::ports::storage::StorageError;

/// Where an event sits in the chain of its realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainPosition {
    pub seq: i64,
    pub hash: Vec<u8>,
}

/// An event as the chain keeps it: its bytes, and its two links.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainedEvent {
    pub seq: i64,
    pub previous_hash: Vec<u8>,
    pub hash: Vec<u8>,
    pub envelope: Vec<u8>,
}

#[async_trait]
pub trait AuditStore {
    /// Appends an envelope to the chain of the scope. One operation: the
    /// head is read, the event linked and the head advanced without another
    /// append slipping in between, whatever node it comes from.
    async fn append_audit_event(&mut self, envelope: &[u8]) -> Result<ChainPosition, StorageError>;

    /// The events after `after_seq`, in order, at most `limit` of them.
    async fn read_audit_events(
        &mut self,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<ChainedEvent>, StorageError>;

    /// The last position of the chain, or nothing for a realm without events.
    async fn read_audit_head(&mut self) -> Result<Option<ChainPosition>, StorageError>;
}
