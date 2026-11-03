use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::Person;
use crate::clients::store::ListWindow;
use crate::ports::storage::StorageError;

#[async_trait]
pub trait PersonStore {
    /// Fails with `Taken("username")` or `Taken("email")`.
    async fn insert_person(&mut self, person: &Person) -> Result<(), StorageError>;

    async fn read_person(&mut self, id: Uuid) -> Result<Option<Person>, StorageError>;

    async fn read_person_by_username(
        &mut self,
        username: &str,
    ) -> Result<Option<Person>, StorageError>;

    /// The people of the realm in the order of their usernames, within the window.
    async fn list_persons(&mut self, window: ListWindow) -> Result<Vec<Person>, StorageError>;

    async fn count_persons(&mut self) -> Result<u64, StorageError>;

    /// Keeps the first password of a person. Nothing replaces it yet.
    async fn insert_password(
        &mut self,
        person: Uuid,
        phc: &str,
        changed_at: OffsetDateTime,
    ) -> Result<(), StorageError>;

    async fn read_password(&mut self, person: Uuid) -> Result<Option<String>, StorageError>;
}
