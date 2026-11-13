use async_trait::async_trait;
use uuid::Uuid;

use super::{SealedSigningKey, SigningKey};
use crate::ports::crypto::{SignatureAlgorithm, WrappedDataKey};
use crate::ports::storage::StorageError;

#[async_trait]
pub trait KeyStore {
    async fn insert_data_key(&mut self, key: &WrappedDataKey) -> Result<(), StorageError>;

    /// The data key of the realm, at its latest generation.
    async fn read_data_key(&mut self) -> Result<Option<WrappedDataKey>, StorageError>;

    /// Refused for a second active key of one algorithm.
    async fn insert_signing_key(&mut self, key: &SealedSigningKey) -> Result<(), StorageError>;

    /// The public half of every signing key of the realm, oldest first. A
    /// realm holds a handful.
    async fn list_signing_keys(&mut self) -> Result<Vec<SigningKey>, StorageError>;

    /// The public half of the key of that `kid`.
    async fn read_signing_key(&mut self, key_id: &str) -> Result<Option<SigningKey>, StorageError>;

    async fn count_signing_keys(&mut self) -> Result<usize, StorageError>;

    /// The active key of each of `algorithms` the realm has, with its sealed
    /// private half: the one read that carries one, made to sign.
    async fn read_active_keys(
        &mut self,
        algorithms: &[SignatureAlgorithm],
    ) -> Result<Vec<SealedSigningKey>, StorageError>;

    /// Takes the keys of the realm until the commit, and returns the latest
    /// generation of its data key: two rotations take turns, and the second
    /// counts what the first kept.
    async fn lock_signing_keys(&mut self) -> Result<Option<WrappedDataKey>, StorageError>;

    /// Retires an active key: it signs nothing more and still verifies.
    /// Answers whether it was active.
    async fn retire_signing_key(&mut self, id: Uuid) -> Result<bool, StorageError>;

    /// Removes a retired key. Answers whether there was one: an active key
    /// is never removed.
    async fn delete_retired_key(&mut self, id: Uuid) -> Result<bool, StorageError>;
}
