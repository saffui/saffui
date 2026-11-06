use std::sync::atomic::Ordering;

use async_trait::async_trait;
use uuid::Uuid;

use super::MemoryUnitOfWork;
use crate::consent::store::ConsentStore;
use crate::consent::{Consent, ConsentTerms, ListedConsent};
use crate::ports::storage::StorageError;

impl MemoryUnitOfWork {
    fn key_consent(&self, person: Uuid, client_id: &str) -> (Uuid, Uuid, String) {
        (self.scope.realm().as_uuid(), person, client_id.to_owned())
    }

    /// The consent of a person to a client, counted as one statement.
    fn find_consent(&self, person: Uuid, client_id: &str) -> Option<&Consent> {
        self.reads.consents.fetch_add(1, Ordering::Relaxed);
        self.working
            .consents
            .get(&self.key_consent(person, client_id))
    }
}

#[async_trait]
impl ConsentStore for MemoryUnitOfWork {
    async fn read_consent(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<Option<Consent>, StorageError> {
        Ok(self.find_consent(person, client_id).cloned())
    }

    async fn hold_consent(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<Option<Vec<String>>, StorageError> {
        // As a read-only transaction refuses `FOR SHARE`. The double
        // serializes nothing: what is held is what is read.
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        Ok(self
            .find_consent(person, client_id)
            .map(|held| held.scopes.clone()))
    }

    async fn read_consent_terms(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<Option<ConsentTerms>, StorageError> {
        let allowed = self
            .find_consent(person, client_id)
            .map(|held| held.scopes.clone());
        let realm = self.scope.realm().as_uuid();
        Ok(self
            .working
            .clients
            .get(&realm)
            .and_then(|clients| clients.iter().find(|client| client.client_id == client_id))
            .map(|client| ConsentTerms {
                requires_consent: client.requires_consent,
                allowed,
            }))
    }

    async fn add_consent(&mut self, consent: &Consent) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let key = self.key_consent(consent.person, &consent.client_id);
        let kept = self.working.consents.entry(key).or_insert_with(|| Consent {
            scopes: Vec::new(),
            ..consent.clone()
        });
        // As the statement does: what is added is compared to what was kept before.
        let before = kept.scopes.clone();
        kept.scopes.extend(
            consent
                .scopes
                .iter()
                .filter(|scope| !before.contains(scope))
                .cloned(),
        );
        kept.granted_at = consent.granted_at;
        Ok(())
    }

    async fn list_consents(
        &mut self,
        person: Uuid,
        most: u32,
    ) -> Result<Vec<ListedConsent>, StorageError> {
        let realm = self.scope.realm().as_uuid();
        let clients = self
            .working
            .clients
            .get(&realm)
            .cloned()
            .unwrap_or_default();
        Ok(self
            .working
            .consents
            .iter()
            .filter(|((of_realm, of_person, _), _)| *of_realm == realm && *of_person == person)
            .filter_map(|((.., client_id), consent)| {
                let client = clients.iter().find(|known| known.client_id == *client_id)?;
                Some(ListedConsent {
                    consent: consent.clone(),
                    client_name: client.name.clone(),
                })
            })
            .take(usize::try_from(most).unwrap_or(usize::MAX))
            .collect())
    }

    async fn delete_consent(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let key = self.key_consent(person, client_id);
        Ok(self.working.consents.remove(&key).is_some())
    }
}
