use async_trait::async_trait;
use uuid::Uuid;

use super::{Consent, ListedConsent};
use crate::ports::storage::StorageError;

#[async_trait]
pub trait ConsentStore {
    async fn read_consent(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<Option<Consent>, StorageError>;

    /// Adds the scopes of `consent` after those the person allowed the client
    /// before, and writes when, in one statement: of two answers at once,
    /// neither loses what the other allowed.
    async fn add_consent(&mut self, consent: &Consent) -> Result<(), StorageError>;

    /// The consents of a person with the names of their clients, by client,
    /// `most` at most.
    async fn list_consents(
        &mut self,
        person: Uuid,
        most: u32,
    ) -> Result<Vec<ListedConsent>, StorageError>;

    /// Answers whether there was one.
    async fn delete_consent(&mut self, person: Uuid, client_id: &str)
    -> Result<bool, StorageError>;
}
