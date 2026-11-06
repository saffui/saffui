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

/// What the tokens a revocation took back still tell. A family revoked for
/// the first time is revoked whole: this is then the whole family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndedFamily {
    /// One for the grant, and one for each rotation.
    pub tokens: u64,
    pub last_issued_at: OffsetDateTime,
    /// `None` when none of them was ever spent.
    pub last_used_at: Option<OffsetDateTime>,
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

    /// Revokes every token of a family that is not revoked yet, used or not,
    /// and says what they tell, or `None` when none was left. A token a
    /// rotation writes while this runs is not counted, and is refused all the
    /// same: its family has revoked tokens.
    async fn revoke_refresh_family(
        &mut self,
        family: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<EndedFamily>, StorageError>;

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
