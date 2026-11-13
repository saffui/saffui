use std::sync::atomic::Ordering;

use async_trait::async_trait;

use super::MemoryUnitOfWork;
use crate::authz::capability::Capability;
use crate::clients::Client;
use crate::clients::store::{ClientStore, ListWindow};
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

    fn change_capabilities(
        &mut self,
        client_id: &str,
        capabilities: &[Capability],
    ) -> Result<bool, StorageError> {
        self.refuse_in_snapshot()?;
        let held = self
            .working
            .clients
            .get_mut(&self.scope.realm().as_uuid())
            .and_then(|clients| {
                clients
                    .iter_mut()
                    .find(|client| client.client_id == client_id)
            });
        let Some(client) = held else {
            return Ok(false);
        };
        // As the schema does: an application holds no capability.
        if client.allows_authorization_code && !capabilities.is_empty() {
            return Err(StorageError::Failed);
        }
        client.capabilities = capabilities.to_vec();
        Ok(true)
    }
}

#[async_trait]
impl ClientStore for MemoryUnitOfWork {
    async fn insert_client(&mut self, client: &Client) -> Result<(), StorageError> {
        let outcome = self.keep_client(client);
        self.record_refusal(outcome)
    }

    async fn read_client(&mut self, client_id: &str) -> Result<Option<Client>, StorageError> {
        self.reads.clients.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .working
            .clients
            .get(&self.scope.realm().as_uuid())
            .and_then(|clients| clients.iter().find(|client| client.client_id == client_id))
            .cloned())
    }

    async fn list_clients(&mut self, window: ListWindow) -> Result<Vec<Client>, StorageError> {
        let mut clients = self
            .working
            .clients
            .get(&self.scope.realm().as_uuid())
            .cloned()
            .unwrap_or_default();
        clients.sort_by(|left, right| left.client_id.cmp(&right.client_id));
        Ok(clients
            .into_iter()
            .skip(usize::try_from(window.first).unwrap_or(usize::MAX))
            .take(usize::try_from(window.max).unwrap_or(usize::MAX))
            .collect())
    }

    async fn count_clients(&mut self) -> Result<u64, StorageError> {
        let held = self
            .working
            .clients
            .get(&self.scope.realm().as_uuid())
            .map_or(0, Vec::len);
        u64::try_from(held).map_err(|_| StorageError::Failed)
    }

    async fn write_client_capabilities(
        &mut self,
        client_id: &str,
        capabilities: &[Capability],
    ) -> Result<bool, StorageError> {
        let outcome = self.change_capabilities(client_id, capabilities);
        self.record_refusal(outcome)
    }
}
