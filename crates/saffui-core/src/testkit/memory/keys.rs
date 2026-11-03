use async_trait::async_trait;

use super::MemoryUnitOfWork;
use crate::keys::SigningKey;
use crate::keys::store::KeyStore;
use crate::ports::crypto::WrappedDataKey;
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

    fn keep_signing_key(&mut self, key: &SigningKey) -> Result<(), StorageError> {
        self.refuse_in_snapshot()?;
        let keys = self
            .working
            .signing_keys
            .entry(self.scope.realm().as_uuid())
            .or_default();
        if keys
            .iter()
            .any(|known| known.id == key.id || known.key_id == key.key_id)
        {
            return Err(StorageError::Failed);
        }
        keys.push(key.clone());
        Ok(())
    }
}

#[async_trait]
impl KeyStore for MemoryUnitOfWork {
    async fn insert_data_key(&mut self, key: &WrappedDataKey) -> Result<(), StorageError> {
        let outcome = self.keep_data_key(key);
        self.record_refusal(outcome)
    }

    async fn read_data_key(&mut self) -> Result<Option<WrappedDataKey>, StorageError> {
        Ok(self
            .working
            .data_keys
            .get(&self.scope.realm().as_uuid())
            .cloned())
    }

    async fn insert_signing_key(&mut self, key: &SigningKey) -> Result<(), StorageError> {
        let outcome = self.keep_signing_key(key);
        self.record_refusal(outcome)
    }

    async fn list_signing_keys(&mut self) -> Result<Vec<SigningKey>, StorageError> {
        Ok(self
            .working
            .signing_keys
            .get(&self.scope.realm().as_uuid())
            .cloned()
            .unwrap_or_default())
    }
}
