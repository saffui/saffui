use std::sync::atomic::Ordering;

use async_trait::async_trait;
use uuid::Uuid;

use super::MemoryUnitOfWork;
use crate::keys::store::KeyStore;
use crate::keys::{KeyStatus, SealedSigningKey, SigningKey};
use crate::ports::crypto::{SignatureAlgorithm, WrappedDataKey};
use crate::ports::storage::StorageError;

impl MemoryUnitOfWork {
    fn keep_data_key(&mut self, key: &WrappedDataKey) -> Result<(), StorageError> {
        self.refuse_in_snapshot()?;
        let realm = self.scope.realm().as_uuid();
        // As the primary key does: a generation is written once.
        let newer = self
            .working
            .data_keys
            .get(&realm)
            .is_none_or(|known| known.generation < key.generation);
        if !newer {
            return Err(StorageError::Failed);
        }
        self.working.data_keys.insert(realm, key.clone());
        Ok(())
    }

    fn keep_signing_key(&mut self, sealed: &SealedSigningKey) -> Result<(), StorageError> {
        self.refuse_in_snapshot()?;
        let key = &sealed.key;
        let keys = self
            .working
            .signing_keys
            .entry(self.scope.realm().as_uuid())
            .or_default();
        // As the schema does: one active key per algorithm.
        let active = |known: &SigningKey| {
            key.status == KeyStatus::Active
                && known.status == KeyStatus::Active
                && known.algorithm == key.algorithm
        };
        if keys.iter().any(|known| {
            known.key.id == key.id || known.key.key_id == key.key_id || active(&known.key)
        }) {
            return Err(StorageError::Failed);
        }
        keys.push(sealed.clone());
        Ok(())
    }

    fn held_keys(&self) -> &[SealedSigningKey] {
        self.working
            .signing_keys
            .get(&self.scope.realm().as_uuid())
            .map_or(&[], Vec::as_slice)
    }

    fn retire_kept_key(&mut self, id: Uuid) -> Result<bool, StorageError> {
        self.refuse_in_snapshot()?;
        let realm = self.scope.realm().as_uuid();
        let active = self.working.signing_keys.get_mut(&realm).and_then(|keys| {
            keys.iter_mut()
                .find(|sealed| sealed.key.id == id && sealed.key.status == KeyStatus::Active)
        });
        let Some(sealed) = active else {
            return Ok(false);
        };
        sealed.key.status = KeyStatus::Retired;
        Ok(true)
    }

    fn delete_kept_key(&mut self, id: Uuid) -> Result<bool, StorageError> {
        self.refuse_in_snapshot()?;
        let realm = self.scope.realm().as_uuid();
        let Some(keys) = self.working.signing_keys.get_mut(&realm) else {
            return Ok(false);
        };
        let before = keys.len();
        keys.retain(|sealed| !(sealed.key.id == id && sealed.key.status == KeyStatus::Retired));
        Ok(keys.len() < before)
    }
}

#[async_trait]
impl KeyStore for MemoryUnitOfWork {
    async fn insert_data_key(&mut self, key: &WrappedDataKey) -> Result<(), StorageError> {
        let outcome = self.keep_data_key(key);
        self.record_refusal(outcome)
    }

    async fn read_data_key(&mut self) -> Result<Option<WrappedDataKey>, StorageError> {
        self.reads.data_keys.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .working
            .data_keys
            .get(&self.scope.realm().as_uuid())
            .cloned())
    }

    async fn insert_signing_key(&mut self, key: &SealedSigningKey) -> Result<(), StorageError> {
        let outcome = self.keep_signing_key(key);
        self.record_refusal(outcome)
    }

    async fn list_signing_keys(&mut self) -> Result<Vec<SigningKey>, StorageError> {
        Ok(self
            .held_keys()
            .iter()
            .map(|sealed| sealed.key.clone())
            .collect())
    }

    async fn read_signing_key(&mut self, key_id: &str) -> Result<Option<SigningKey>, StorageError> {
        Ok(self
            .held_keys()
            .iter()
            .find(|sealed| sealed.key.key_id == key_id)
            .map(|sealed| sealed.key.clone()))
    }

    async fn count_signing_keys(&mut self) -> Result<usize, StorageError> {
        Ok(self.held_keys().len())
    }

    async fn read_active_keys(
        &mut self,
        algorithms: &[SignatureAlgorithm],
    ) -> Result<Vec<SealedSigningKey>, StorageError> {
        let active: Vec<SealedSigningKey> = self
            .held_keys()
            .iter()
            .filter(|sealed| {
                sealed.key.status == KeyStatus::Active && algorithms.contains(&sealed.key.algorithm)
            })
            .cloned()
            .collect();
        self.reads
            .private_keys
            .fetch_add(active.len(), Ordering::Relaxed);
        Ok(active)
    }

    async fn lock_signing_keys(&mut self) -> Result<Option<WrappedDataKey>, StorageError> {
        // A unit of work of the double sees no other until it commits.
        self.refuse_in_snapshot()?;
        Ok(self
            .working
            .data_keys
            .get(&self.scope.realm().as_uuid())
            .cloned())
    }

    async fn retire_signing_key(&mut self, id: Uuid) -> Result<bool, StorageError> {
        let outcome = self.retire_kept_key(id);
        self.record_refusal(outcome)
    }

    async fn delete_retired_key(&mut self, id: Uuid) -> Result<bool, StorageError> {
        let outcome = self.delete_kept_key(id);
        self.record_refusal(outcome)
    }
}
