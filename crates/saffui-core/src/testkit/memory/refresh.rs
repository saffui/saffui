use std::collections::HashMap;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::MemoryUnitOfWork;
use crate::ports::storage::StorageError;
use crate::tokens::store::{RefreshStore, RefreshToken, StoredRefreshToken};

impl MemoryUnitOfWork {
    fn refresh_tokens_of_the_realm(&mut self) -> &mut Vec<StoredRefreshToken> {
        self.working
            .refresh_tokens
            .entry(self.scope.realm().as_uuid())
            .or_default()
    }

    /// The families of the realm with a revoked token, and the first
    /// revocation of each: the family stands revoked from then on.
    fn read_revoked_families(&mut self) -> HashMap<Uuid, OffsetDateTime> {
        let mut families = HashMap::new();
        for stored in self.refresh_tokens_of_the_realm().iter() {
            if let Some(revoked_at) = stored.revoked_at {
                families
                    .entry(stored.token.family)
                    .and_modify(|first: &mut OffsetDateTime| *first = (*first).min(revoked_at))
                    .or_insert(revoked_at);
            }
        }
        families
    }

    fn revoke_refresh_tokens_where(
        &mut self,
        now: OffsetDateTime,
        concerned: impl Fn(&RefreshToken) -> bool,
    ) -> u64 {
        let mut revoked = 0;
        for stored in self.refresh_tokens_of_the_realm() {
            if stored.revoked_at.is_none() && concerned(&stored.token) {
                stored.revoked_at = Some(now);
                revoked += 1;
            }
        }
        revoked
    }
}

#[async_trait]
impl RefreshStore for MemoryUnitOfWork {
    async fn insert_refresh_token(&mut self, token: &RefreshToken) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        self.refresh_tokens_of_the_realm().push(StoredRefreshToken {
            token: token.clone(),
            used_at: None,
            revoked_at: None,
        });
        Ok(())
    }

    async fn spend_refresh_token(
        &mut self,
        token_digest: &[u8],
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<RefreshToken>, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let revoked_families = self.read_revoked_families();
        let spendable = self
            .refresh_tokens_of_the_realm()
            .iter_mut()
            .find(|stored| {
                stored.token.token_digest == token_digest
                    && stored.token.client_id == client_id
                    && stored.is_live(now)
                    && !revoked_families.contains_key(&stored.token.family)
            });
        Ok(spendable.map(|stored| {
            stored.used_at = Some(now);
            stored.token.clone()
        }))
    }

    async fn read_refresh_token(
        &mut self,
        token_digest: &[u8],
    ) -> Result<Option<StoredRefreshToken>, StorageError> {
        let revoked_families = self.read_revoked_families();
        Ok(self
            .refresh_tokens_of_the_realm()
            .iter()
            .find(|stored| stored.token.token_digest == token_digest)
            .map(|stored| StoredRefreshToken {
                revoked_at: stored
                    .revoked_at
                    .or_else(|| revoked_families.get(&stored.token.family).copied()),
                ..stored.clone()
            }))
    }

    async fn revoke_refresh_family(
        &mut self,
        family: Uuid,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        Ok(self.revoke_refresh_tokens_where(now, |token| token.family == family))
    }

    async fn revoke_refresh_tokens_of_session(
        &mut self,
        session: Uuid,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        Ok(self.revoke_refresh_tokens_where(now, |token| token.session == session))
    }
}
