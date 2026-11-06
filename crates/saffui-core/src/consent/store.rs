use async_trait::async_trait;
use uuid::Uuid;

use super::{Consent, ConsentTerms, ListedConsent};
use crate::ports::storage::StorageError;

#[async_trait]
pub trait ConsentStore {
    async fn read_consent(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<Option<Consent>, StorageError>;

    /// The scopes the person allowed the client, held until the commit: a
    /// withdrawal waits for the unit of work that holds them. One that came
    /// first leaves nothing to hold.
    async fn hold_consent(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<Option<Vec<String>>, StorageError>;

    /// Whether the client requires consent and what the person allowed it,
    /// in one statement. `None` when the realm has no such client.
    async fn read_consent_terms(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<Option<ConsentTerms>, StorageError>;

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
