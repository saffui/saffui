use async_trait::async_trait;
use serde_json::{Map, Value};
use uuid::Uuid;

use super::{LockedClient, Mapper};
use crate::ports::storage::StorageError;

#[async_trait]
pub trait ClaimStore {
    /// Takes the row of a client until the commit: two writers of its
    /// mappers take turns. None for a client the realm does not have.
    async fn lock_client(&mut self, client_id: &str) -> Result<Option<LockedClient>, StorageError>;

    /// Answers false, and writes nothing, when the client has a mapper of
    /// that name.
    async fn insert_mapper(&mut self, mapper: &Mapper) -> Result<bool, StorageError>;

    /// The mappers of a client, in the byte order of their names.
    async fn list_mappers(&mut self, client_id: &str) -> Result<Vec<Mapper>, StorageError>;

    /// Answers whether the client had that mapper.
    async fn delete_mapper(&mut self, client_id: &str, id: Uuid) -> Result<bool, StorageError>;

    /// The attributes of a person. None for a person the realm does not have.
    async fn read_person_attributes(
        &mut self,
        person: Uuid,
    ) -> Result<Option<Map<String, Value>>, StorageError>;

    /// As `read_person_attributes`, and the person stays taken until the
    /// commit: a second writer waits, then reads what the first kept.
    async fn lock_person_attributes(
        &mut self,
        person: Uuid,
    ) -> Result<Option<Map<String, Value>>, StorageError>;

    /// Replaces the attributes of a person taken by `lock_person_attributes`.
    async fn write_person_attributes(
        &mut self,
        person: Uuid,
        attributes: &Map<String, Value>,
    ) -> Result<(), StorageError>;
}
