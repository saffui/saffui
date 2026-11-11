use std::collections::{BTreeSet, HashMap};

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::MemoryUnitOfWork;
use crate::login::session::{Session, SessionKind, SessionState};
use crate::ports::storage::StorageError;
use crate::tokens::store::{
    EndedFamily, RefreshStore, RefreshToken, RevokedFamilies, StoredRefreshToken,
};

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

    /// Revokes, as [`Self::revoke_live_family`] does, each family of the
    /// tokens `concerned` names, and returns those it ended with how many
    /// tokens they still held.
    fn revoke_families_where(
        &mut self,
        now: OffsetDateTime,
        concerned: impl Fn(&RefreshToken) -> bool,
    ) -> (BTreeSet<Uuid>, u64) {
        let families: BTreeSet<Uuid> = self
            .refresh_tokens_of_the_realm()
            .iter()
            .filter(|stored| stored.revoked_at.is_none() && concerned(&stored.token))
            .map(|stored| stored.token.family)
            .collect();
        let mut ended = BTreeSet::new();
        let mut tokens = 0;
        for family in families {
            if let Some(told) = self.revoke_live_family(family, now) {
                ended.insert(family);
                tokens += told.tokens;
            }
        }
        (ended, tokens)
    }

    /// Ends the active offline sessions `chosen` names, and returns them.
    fn end_offline_sessions_where(&mut self, chosen: impl Fn(&Session) -> bool) -> Vec<Uuid> {
        let mut ended = Vec::new();
        if let Some(sessions) = self.working.sessions.get_mut(&self.scope.realm().as_uuid()) {
            for session in sessions.iter_mut().filter(|session| {
                session.kind == SessionKind::Offline
                    && session.state == SessionState::Active
                    && chosen(session)
            }) {
                session.state = SessionState::Ended;
                ended.push(session.id);
            }
        }
        ended
    }

    /// The sessions a token of `client_id` lives in, whatever became of it.
    fn list_sessions_of_client(&mut self, client_id: &str) -> BTreeSet<Uuid> {
        self.refresh_tokens_of_the_realm()
            .iter()
            .filter(|stored| stored.token.client_id == client_id)
            .map(|stored| stored.token.session)
            .collect()
    }

    /// Revokes a family no revoked token refuses yet, as Postgres does: its
    /// tokens that could still be spent and its latest are written revoked.
    /// Returns what the family told.
    fn revoke_live_family(&mut self, family: Uuid, now: OffsetDateTime) -> Option<EndedFamily> {
        if self.read_revoked_families().contains_key(&family) {
            return None;
        }
        let live: Vec<StoredRefreshToken> = self
            .refresh_tokens_of_the_realm()
            .iter()
            .filter(|stored| stored.token.family == family && stored.revoked_at.is_none())
            .cloned()
            .collect();
        let latest = live.iter().max_by_key(|stored| stored.token.issued_at)?;
        let ended = EndedFamily {
            tokens: u64::try_from(live.len()).unwrap_or(u64::MAX),
            last_issued_at: latest.token.issued_at,
            last_used_at: live.iter().filter_map(|stored| stored.used_at).max(),
        };
        let latest = latest.token.token_digest.clone();
        for stored in self.refresh_tokens_of_the_realm() {
            if stored.token.family == family
                && stored.revoked_at.is_none()
                && (stored.used_at.is_none() || stored.token.token_digest == latest)
            {
                stored.revoked_at = Some(now);
            }
        }
        Some(ended)
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
    ) -> Result<Option<EndedFamily>, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        Ok(self.revoke_live_family(family, now))
    }

    async fn end_offline_session_of_family(
        &mut self,
        family: Uuid,
    ) -> Result<Option<Uuid>, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let lived_in = self
            .refresh_tokens_of_the_realm()
            .iter()
            .find(|stored| stored.token.family == family && stored.revoked_at.is_none())
            .map(|stored| stored.token.session);
        let Some(lived_in) = lived_in else {
            return Ok(None);
        };
        Ok(self
            .end_offline_sessions_where(|session| session.id == lived_in)
            .into_iter()
            .next())
    }

    async fn end_oldest_offline_sessions(
        &mut self,
        person: Uuid,
        client_id: &str,
        kept: u32,
        now: OffsetDateTime,
    ) -> Result<Vec<Uuid>, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let holding = self.list_sessions_of_client(client_id);
        let mut held: Vec<(OffsetDateTime, Uuid)> = self
            .working
            .sessions
            .get(&self.scope.realm().as_uuid())
            .map(|sessions| {
                sessions
                    .iter()
                    .filter(|session| {
                        session.person == person
                            && session.kind == SessionKind::Offline
                            && session.state == SessionState::Active
                            && session.expires_at > now
                            && holding.contains(&session.id)
                    })
                    .map(|session| (session.expires_at, session.id))
                    .collect()
            })
            .unwrap_or_default();
        held.sort_by(|one, other| other.0.cmp(&one.0).then(one.1.cmp(&other.1)));
        let past: BTreeSet<Uuid> = held
            .into_iter()
            .skip(usize::try_from(kept).unwrap_or(usize::MAX))
            .map(|(_, session)| session)
            .collect();
        let mut ended = self.end_offline_sessions_where(|session| past.contains(&session.id));
        ended.sort_unstable();
        Ok(ended)
    }

    async fn revoke_refresh_families_of_client(
        &mut self,
        person: Uuid,
        client_id: &str,
        now: OffsetDateTime,
        most: u32,
    ) -> Result<RevokedFamilies, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        // The sessions first, as Postgres does.
        let holding = self.list_sessions_of_client(client_id);
        let mut offline_sessions = self.end_offline_sessions_where(|session| {
            session.person == person && holding.contains(&session.id)
        });
        offline_sessions.sort_unstable();
        let (ended, tokens) = self.revoke_families_where(now, |token| {
            token.person == person && token.client_id == client_id
        });
        Ok(RevokedFamilies {
            families: u64::try_from(ended.len()).unwrap_or(u64::MAX),
            tokens,
            named: ended
                .into_iter()
                .take(usize::try_from(most).unwrap_or(usize::MAX))
                .collect(),
            offline_sessions,
        })
    }

    async fn revoke_refresh_tokens_of_session(
        &mut self,
        session: Uuid,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        Ok(self
            .revoke_families_where(now, |token| token.session == session)
            .1)
    }

    async fn revoke_refresh_tokens_of_sessions(
        &mut self,
        sessions: &[Uuid],
        now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        Ok(self
            .revoke_families_where(now, |token| sessions.contains(&token.session))
            .1)
    }
}
