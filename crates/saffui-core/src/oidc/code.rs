//! What the authorization code flow keeps between its steps.

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ports::storage::StorageError;

/// An authorization request that waits for its person to sign in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAuthorization {
    pub id: Uuid,
    /// The digest of the secret given to the browser that started the
    /// request: nobody else can finish it.
    pub browser_digest: Vec<u8>,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub expires_at: OffsetDateTime,
}

/// A code, as it is kept: by its digest, with everything the exchange must
/// find unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationCode {
    pub code_digest: Vec<u8>,
    pub client_id: String,
    pub person: Uuid,
    pub session: Uuid,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub authenticated_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[async_trait]
pub trait CodeStore {
    async fn insert_pending_authorization(
        &mut self,
        pending: &PendingAuthorization,
    ) -> Result<(), StorageError>;

    /// A pending request that has not expired at `now`.
    async fn read_pending_authorization(
        &mut self,
        id: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<PendingAuthorization>, StorageError>;

    /// Takes a pending request: returns it and removes it, in one operation.
    /// Of two submissions of one page, exactly one gets it. A request that
    /// expired at `now` is not returned.
    async fn take_pending_authorization(
        &mut self,
        id: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<PendingAuthorization>, StorageError>;

    async fn insert_authorization_code(
        &mut self,
        code: &AuthorizationCode,
    ) -> Result<(), StorageError>;

    /// Spends a code: returns it and removes it, in one operation. Of two
    /// exchanges of one code, exactly one gets it. A code that expired at
    /// `now` is not returned.
    async fn take_authorization_code(
        &mut self,
        code_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<AuthorizationCode>, StorageError>;
}
