//! Refresh tokens. Opaque, kept by their digest, and spent at each use: the
//! answer carries the next one. A token presented twice was copied by
//! someone, so everything that descends from the same grant is revoked.

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ports::storage::StorageError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshToken {
    pub token_digest: Vec<u8>,
    /// Every token that descends from one grant to one client.
    pub family: Uuid,
    pub client_id: String,
    pub person: Uuid,
    pub session: Uuid,
    /// What was granted at first. A narrower request narrows the access
    /// token it gets, never this.
    pub scopes: Vec<String>,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// A refresh token as it is kept, with what became of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRefreshToken {
    pub token: RefreshToken,
    pub used_at: Option<OffsetDateTime>,
    /// When the token, or the first token of its family, was revoked: a
    /// family revoked stands revoked for a token written while it was.
    pub revoked_at: Option<OffsetDateTime>,
}

impl StoredRefreshToken {
    /// Tells whether the token could still be spent at `now`.
    #[must_use]
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.used_at.is_none() && self.revoked_at.is_none() && self.token.expires_at > now
    }
}

/// What the tokens of a family still told when it was revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndedFamily {
    /// One for the grant, and one for each rotation, counted: only those that
    /// could still be spent, and the latest, are written revoked.
    pub tokens: u64,
    pub last_issued_at: OffsetDateTime,
    /// `None` when none of them was ever spent.
    pub last_used_at: Option<OffsetDateTime>,
}

/// What a revocation of every token of a client for a person took back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokedFamilies {
    /// The families it ended: one with a token revoked before is left alone.
    pub families: u64,
    /// The tokens it wrote revoked: those that could still be spent, and the
    /// latest of each family. One refuses its whole family.
    pub tokens: u64,
    /// The first of the families it ended, by identifier.
    pub named: Vec<Uuid>,
    /// The offline sessions the client held tokens in for the person,
    /// ended before the families.
    pub offline_sessions: u64,
}

#[async_trait]
pub trait RefreshStore {
    async fn insert_refresh_token(&mut self, token: &RefreshToken) -> Result<(), StorageError>;

    /// Spends a token of a client: marks it used and returns it, in one
    /// operation. Of two uses of one token, exactly one gets it. A token
    /// that is used, revoked, expired at `now`, of another client, or of a
    /// family with a revoked token is not returned, and is left as it was.
    async fn spend_refresh_token(
        &mut self,
        token_digest: &[u8],
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<RefreshToken>, StorageError>;

    async fn read_refresh_token(
        &mut self,
        token_digest: &[u8],
    ) -> Result<Option<StoredRefreshToken>, StorageError>;

    /// Ends the active offline session a family lives in, if it lives in
    /// one, and returns it: it lived for that grant alone. Called before the
    /// family is revoked, so that a session is locked before its tokens.
    async fn end_offline_session_of_family(
        &mut self,
        family: Uuid,
    ) -> Result<Option<Uuid>, StorageError>;

    /// Revokes a family no revoked token refuses yet, in one statement. One
    /// revoked token refuses it whole: only those of its tokens that could
    /// still be spent, and its latest, are written. Says what the family
    /// told, or `None` when it was refused already. A token a rotation writes
    /// while this runs is refused all the same.
    async fn revoke_refresh_family(
        &mut self,
        family: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<EndedFamily>, StorageError>;

    /// Ends the offline sessions a client holds tokens in for a person, then
    /// revokes, as [`Self::revoke_refresh_family`] does, each family of that
    /// client in their sessions: two statements, the sessions locked before
    /// their tokens. Counts what it took back, and names `most` families.
    async fn revoke_refresh_families_of_client(
        &mut self,
        person: Uuid,
        client_id: &str,
        now: OffsetDateTime,
        most: u32,
    ) -> Result<RevokedFamilies, StorageError>;

    /// Ends the active offline sessions a client holds tokens in for a
    /// person, but the `kept` that expire last, in one statement on the
    /// sessions alone, and returns those it ended. Expired at `now`, a
    /// session is not counted.
    async fn end_oldest_offline_sessions(
        &mut self,
        person: Uuid,
        client_id: &str,
        kept: u32,
        now: OffsetDateTime,
    ) -> Result<Vec<Uuid>, StorageError>;

    /// Revokes every token of a session that is not revoked yet. Returns how many.
    async fn revoke_refresh_tokens_of_session(
        &mut self,
        session: Uuid,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError>;

    /// Revokes, in one go, every token of these sessions that is not revoked
    /// yet. Returns how many.
    async fn revoke_refresh_tokens_of_sessions(
        &mut self,
        sessions: &[Uuid],
        now: OffsetDateTime,
    ) -> Result<u64, StorageError>;
}
