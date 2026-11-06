//! What the authorization code flow keeps between its steps.

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ports::storage::StorageError;

/// An authorization request that waits for its person to sign in.
#[derive(Clone, Debug, PartialEq)]
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
    /// The person an identity token hint named: anyone else who signs in
    /// for this request gets no code.
    pub expected_person: Option<Uuid>,
    /// The person who proved their password for this request and owes a
    /// second factor. Nobody yet, when the request is made.
    pub first_factor: Option<Uuid>,
    /// The proof by a security key that person may give next, when they
    /// hold one.
    pub key_proof: Option<PendingKeyProof>,
}

/// A proof by a security key that was started and waits for its answer.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingKeyProof {
    /// What finishes the ceremony. Only the adapter reads it.
    pub state: Vec<u8>,
    /// What the page hands to the browser, kept to show the page again.
    pub options: serde_json::Value,
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

/// What an exchange of a code that was already spent finds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayedCode {
    pub person: Uuid,
    pub session: Uuid,
    /// The refresh tokens the first exchange started. `None` while it has
    /// not finished: it then finds the code replayed and issues nothing.
    pub family: Option<Uuid>,
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

    /// Writes on a pending request who proved their password for it, and the
    /// proof by a security key they may give next. Answers whether the
    /// request was still waiting at `now`.
    async fn mark_first_factor(
        &mut self,
        id: Uuid,
        person: Uuid,
        key_proof: Option<&PendingKeyProof>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

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

    /// Spends a code: marks it spent and returns it, in one operation. Of
    /// two exchanges of one code, exactly one gets it. A code that is spent,
    /// or that expired at `now`, is not returned. A spent code is kept, so
    /// that an exchange that comes after can be told.
    async fn spend_authorization_code(
        &mut self,
        code_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<AuthorizationCode>, StorageError>;

    /// Ties a spent code to the refresh tokens its exchange started. Returns
    /// `false` when the code was presented again meanwhile: the exchange
    /// must then issue nothing.
    async fn bind_code_family(
        &mut self,
        code_digest: &[u8],
        family: Uuid,
    ) -> Result<bool, StorageError>;

    /// Marks a spent code of `client_id` as presented again, and says what
    /// its exchange obtained, once: the replay that marks it takes that back,
    /// and nothing is bound to it after. A code that is unknown, not spent,
    /// of another client, or marked already is left as it was and not returned.
    async fn mark_code_replayed(
        &mut self,
        code_digest: &[u8],
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<ReplayedCode>, StorageError>;
}
