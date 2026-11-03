use async_trait::async_trait;

use super::Client;
use crate::ports::storage::StorageError;

#[async_trait]
pub trait ClientStore {
    /// Fails with `Taken("client identifier")` when the realm has a client
    /// of that identifier already.
    async fn insert_client(&mut self, client: &Client) -> Result<(), StorageError>;

    async fn read_client(&mut self, client_id: &str) -> Result<Option<Client>, StorageError>;
}
