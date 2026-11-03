use async_trait::async_trait;

use super::SigningKey;
use crate::ports::crypto::WrappedDataKey;
use crate::ports::storage::StorageError;

#[async_trait]
pub trait KeyStore {
    async fn insert_data_key(&mut self, key: &WrappedDataKey) -> Result<(), StorageError>;

    /// The data key of the realm, at its latest generation.
    async fn read_data_key(&mut self) -> Result<Option<WrappedDataKey>, StorageError>;

    async fn insert_signing_key(&mut self, key: &SigningKey) -> Result<(), StorageError>;

    /// Every signing key of the realm, oldest first. A realm holds a handful.
    async fn list_signing_keys(&mut self) -> Result<Vec<SigningKey>, StorageError>;
}
