use async_trait::async_trait;
use uuid::Uuid;

use super::{Allowance, Consent, ConsentHold, ConsentTerms, ListedConsent};
use crate::ports::storage::StorageError;

#[async_trait]
pub trait ConsentStore {
    async fn read_consent(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<Option<Consent>, StorageError>;

    /// What the person allowed the client, held until the commit as `hold`
    /// says: a withdrawal waits for the unit of work that holds it, and so
    /// does another that holds it exclusively. One that came first leaves
    /// nothing to hold.
    async fn hold_consent(
        &mut self,
        person: Uuid,
        client_id: &str,
        hold: ConsentHold,
    ) -> Result<Option<Allowance>, StorageError>;

    /// Whether the client requires consent and what the person allowed it,
    /// in one statement. `None` when the realm has no such client.
    async fn read_consent_terms(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<Option<ConsentTerms>, StorageError>;

    /// Adds the scopes and the claims of `consent` after those the person
    /// allowed the client before, and writes when, in one statement: of two
    /// answers at once, neither loses what the other allowed. Returns what
    /// the person allows now, as the statement wrote it and holds it until
    /// the commit: a withdrawal before it left nothing to add to.
    async fn add_consent(&mut self, consent: &Consent) -> Result<Allowance, StorageError>;

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

    /// Removes every consent a client was given, in one statement. Answers
    /// how many there were.
    async fn delete_consents_of_client(&mut self, client_id: &str) -> Result<u64, StorageError>;
}
