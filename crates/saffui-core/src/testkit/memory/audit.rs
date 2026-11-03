use async_trait::async_trait;

use super::super::digest::WeakDigester;
use super::MemoryUnitOfWork;
use crate::audit::store::{AuditStore, ChainPosition, ChainedEvent};
use crate::audit::{GENESIS_HASH, hash_link};
use crate::ports::storage::StorageError;

impl MemoryUnitOfWork {
    fn link_event(&mut self, envelope: &[u8]) -> Result<ChainPosition, StorageError> {
        self.refuse_in_snapshot()?;
        // As the database does: an envelope that names another scope is refused.
        let read: serde_json::Value =
            serde_json::from_slice(envelope).map_err(|_| StorageError::Failed)?;
        let names = |member: &str, id: uuid::Uuid| read[member] == id.to_string();
        if !names("tenant_id", self.scope.tenant().as_uuid())
            || !names("realm_id", self.scope.realm().as_uuid())
        {
            return Err(StorageError::Failed);
        }

        let chain = self
            .working
            .audit
            .entry(self.scope.realm().as_uuid())
            .or_default();
        let (seq, previous_hash) = chain.last().map_or((1, GENESIS_HASH.to_vec()), |last| {
            (last.seq + 1, last.hash.clone())
        });
        let hash = hash_link(&WeakDigester, &previous_hash, seq, envelope).to_vec();
        chain.push(ChainedEvent {
            seq,
            previous_hash,
            hash: hash.clone(),
            envelope: envelope.to_vec(),
        });
        Ok(ChainPosition { seq, hash })
    }
}

#[async_trait]
impl AuditStore for MemoryUnitOfWork {
    async fn append_audit_event(&mut self, envelope: &[u8]) -> Result<ChainPosition, StorageError> {
        let outcome = self.link_event(envelope);
        self.record_refusal(outcome)
    }

    async fn read_audit_events(
        &mut self,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<ChainedEvent>, StorageError> {
        let chain = self.working.audit.get(&self.scope.realm().as_uuid());
        Ok(chain
            .into_iter()
            .flatten()
            .filter(|event| event.seq > after_seq)
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .cloned()
            .collect())
    }

    async fn read_audit_head(&mut self) -> Result<Option<ChainPosition>, StorageError> {
        let chain = self.working.audit.get(&self.scope.realm().as_uuid());
        Ok(chain
            .and_then(|chain| chain.last())
            .map(|last| ChainPosition {
                seq: last.seq,
                hash: last.hash.clone(),
            }))
    }
}
