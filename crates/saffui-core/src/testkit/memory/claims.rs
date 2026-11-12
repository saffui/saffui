use std::sync::atomic::Ordering;

use async_trait::async_trait;
use serde_json::{Map, Value};
use uuid::Uuid;

use super::MemoryUnitOfWork;
use crate::claims::store::ClaimStore;
use crate::claims::{LockedClient, Mapper};
use crate::ports::storage::StorageError;

impl MemoryUnitOfWork {
    fn holds_person(&self, person: Uuid) -> bool {
        self.working
            .persons
            .get(&self.scope.realm().as_uuid())
            .is_some_and(|persons| persons.iter().any(|known| known.id == person))
    }

    fn find_person_attributes(&self, person: Uuid) -> Option<Map<String, Value>> {
        let realm = self.scope.realm().as_uuid();
        self.holds_person(person).then(|| {
            self.working
                .attributes
                .get(&(realm, person))
                .cloned()
                .unwrap_or_default()
        })
    }

    fn list_mappers_of(&self, client_id: &str) -> Vec<Mapper> {
        let mut mappers: Vec<Mapper> = self
            .working
            .mappers
            .get(&self.scope.realm().as_uuid())
            .map(|mappers| {
                mappers
                    .iter()
                    .filter(|mapper| mapper.client_id == client_id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        mappers.sort_by(|one, other| one.name.as_bytes().cmp(other.name.as_bytes()));
        mappers
    }
}

#[async_trait]
impl ClaimStore for MemoryUnitOfWork {
    async fn lock_client(&mut self, client_id: &str) -> Result<Option<LockedClient>, StorageError> {
        // One unit of work at a time: nothing else counts meanwhile.
        Ok(self
            .working
            .clients
            .get(&self.scope.realm().as_uuid())
            .and_then(|clients| clients.iter().find(|client| client.client_id == client_id))
            .map(|client| LockedClient {
                scopes: client.scopes.clone(),
                capabilities: client.capabilities.clone(),
            }))
    }

    async fn insert_mapper(&mut self, mapper: &Mapper) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let mappers = self
            .working
            .mappers
            .entry(self.scope.realm().as_uuid())
            .or_default();
        if mappers
            .iter()
            .any(|known| known.client_id == mapper.client_id && known.name == mapper.name)
        {
            return Ok(false);
        }
        mappers.push(mapper.clone());
        Ok(true)
    }

    async fn list_mappers(&mut self, client_id: &str) -> Result<Vec<Mapper>, StorageError> {
        Ok(self.list_mappers_of(client_id))
    }

    async fn delete_mapper(&mut self, client_id: &str, id: Uuid) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let Some(mappers) = self.working.mappers.get_mut(&self.scope.realm().as_uuid()) else {
            return Ok(false);
        };
        let before = mappers.len();
        mappers.retain(|mapper| !(mapper.client_id == client_id && mapper.id == id));
        Ok(mappers.len() < before)
    }

    async fn read_person_attributes(
        &mut self,
        person: Uuid,
    ) -> Result<Option<Map<String, Value>>, StorageError> {
        self.reads.attributes.fetch_add(1, Ordering::Relaxed);
        Ok(self.find_person_attributes(person))
    }

    async fn lock_person_attributes(
        &mut self,
        person: Uuid,
    ) -> Result<Option<Map<String, Value>>, StorageError> {
        Ok(self.find_person_attributes(person))
    }

    async fn write_person_attributes(
        &mut self,
        person: Uuid,
        attributes: &Map<String, Value>,
    ) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot().and_then(|()| {
            if self.holds_person(person) {
                Ok(())
            } else {
                Err(StorageError::Failed)
            }
        });
        self.record_refusal(outcome)?;
        let realm = self.scope.realm().as_uuid();
        self.working
            .attributes
            .insert((realm, person), attributes.clone());
        Ok(())
    }
}
