use async_trait::async_trait;

use super::MemoryUnitOfWork;
use crate::clients::Client;
use crate::clients::store::ClientStore;
use crate::ports::storage::StorageError;

impl MemoryUnitOfWork {
    fn keep_client(&mut self, client: &Client) -> Result<(), StorageError> {
        self.refuse_in_snapshot()?;
        let clients = self
            .working
            .clients
            .entry(self.scope.realm().as_uuid())
            .or_default();
        if clients
            .iter()
            .any(|known| known.client_id == client.client_id)
        {
            return Err(StorageError::Taken("client identifier"));
        }
        clients.push(client.clone());
        Ok(())
    }
}

#[async_trait]
impl ClientStore for MemoryUnitOfWork {
    async fn insert_client(&mut self, client: &Client) -> Result<(), StorageError> {
        let outcome = self.keep_client(client);
        self.record_refusal(outcome)
    }

    async fn read_client(&mut self, client_id: &str) -> Result<Option<Client>, StorageError> {
        Ok(self
            .working
            .clients
            .get(&self.scope.realm().as_uuid())
            .and_then(|clients| clients.iter().find(|client| client.client_id == client_id))
            .cloned())
    }
}
