use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::session::{AuthenticationMethod, Session};
use crate::ports::storage::StorageError;

#[async_trait]
pub trait SessionStore {
    async fn insert_session(&mut self, session: &Session) -> Result<(), StorageError>;

    async fn read_session(&mut self, id: Uuid) -> Result<Option<Session>, StorageError>;

    /// Ends a session that is still active, and tells whether it did: of two
    /// endings at once, one ends it. It is kept, ended, until it expires and
    /// retention removes it: what it did stays explainable until then.
    async fn end_session(&mut self, id: Uuid) -> Result<bool, StorageError>;

    /// Ends, in one go, every active session of a person proven by exactly
    /// `methods`, but `kept`. Returns the identifiers of those it ended.
    async fn end_sessions_proven_only_by(
        &mut self,
        person: Uuid,
        methods: &[AuthenticationMethod],
        kept: Option<Uuid>,
    ) -> Result<Vec<Uuid>, StorageError>;
}

#[async_trait]
pub trait ThrottleStore {
    /// What a counter holds in the buckets that start at or after `since`.
    async fn count_login_failures(
        &mut self,
        identifier_digest: &[u8],
        since: OffsetDateTime,
    ) -> Result<u32, StorageError>;

    /// Adds one to the bucket of a counter. One operation: two attempts
    /// recorded at once both count.
    async fn record_login_failure(
        &mut self,
        identifier_digest: &[u8],
        bucket_start: OffsetDateTime,
    ) -> Result<(), StorageError>;

    /// Forgets every bucket of a counter: what was proven need not be
    /// counted against any more.
    async fn forget_login_failures(&mut self, identifier_digest: &[u8])
    -> Result<(), StorageError>;
}

/// The authenticator application of a person, as it is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpAuthenticator {
    pub person: Uuid,
    /// The shared secret, sealed for this person in this realm.
    pub sealed_secret: Vec<u8>,
    /// Empty until a first code proved the application holds the secret.
    pub confirmed_at: Option<OffsetDateTime>,
    /// The last time step a code was accepted for.
    pub last_step: Option<i64>,
    pub created_at: OffsetDateTime,
}

/// What a code is accepted for: the first code of a secret confirms it, the
/// later ones sign in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpUse {
    Confirmation,
    SignIn,
}

#[async_trait]
pub trait AuthenticatorStore {
    /// Keeps an authenticator that is not confirmed yet, in place of one
    /// that never was. Answers whether it was kept: a confirmed one is not
    /// replaced.
    async fn write_pending_totp(
        &mut self,
        authenticator: &TotpAuthenticator,
    ) -> Result<bool, StorageError>;

    async fn read_totp(&mut self, person: Uuid) -> Result<Option<TotpAuthenticator>, StorageError>;

    /// Accepts a time step, in one operation: records it, confirms the
    /// authenticator for a confirmation, and answers `true`, only when the
    /// authenticator still holds `judged`, the sealed secret the code was
    /// judged against, is unconfirmed for a confirmation and confirmed for a
    /// sign-in, and no step at or after it was accepted before. Of two uses
    /// of one code, exactly one is accepted; a secret replaced meanwhile
    /// accepts nothing.
    async fn accept_totp_step(
        &mut self,
        person: Uuid,
        judged: &[u8],
        step: i64,
        used_for: TotpUse,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Removes the authenticator of a person. Answers whether there was one.
    async fn delete_totp(&mut self, person: Uuid) -> Result<bool, StorageError>;

    /// Counts one more code typed by a person, in one operation, and answers
    /// how many that makes since their last right one. Two attempts that run
    /// beside each other are both counted.
    async fn count_code_attempt(
        &mut self,
        person: Uuid,
        now: OffsetDateTime,
    ) -> Result<u32, StorageError>;

    /// Forgets the codes a person typed: they proved a second factor, or an
    /// administrator let them in.
    async fn clear_code_attempts(&mut self, person: Uuid) -> Result<(), StorageError>;
}

/// A browser a person signed in from, as the realm keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownBrowser {
    pub device: Uuid,
    pub person: Uuid,
    pub expires_at: OffsetDateTime,
}

#[async_trait]
pub trait KnownBrowserStore {
    /// Keeps a browser, or makes a kept one live longer. A browser kept for
    /// another person is left as it was. Of the browsers of the person, all
    /// but the `keep` that expire last are forgotten.
    async fn remember_browser(
        &mut self,
        browser: &KnownBrowser,
        keep: u32,
    ) -> Result<(), StorageError>;

    /// The browsers among `devices` that are kept, whoever for, and that have
    /// not expired at `now`, in one read.
    async fn read_live_browsers(
        &mut self,
        devices: &[Uuid],
        now: OffsetDateTime,
    ) -> Result<Vec<KnownBrowser>, StorageError>;
}

/// A security key of a person, as it is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityKey {
    pub credential_id: Vec<u8>,
    pub person: Uuid,
    /// What the adapter keeps of the key: its public half and its counter.
    /// It never leaves in an answer.
    pub record: Vec<u8>,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

#[async_trait]
pub trait SecurityKeyStore {
    /// Keeps a key. Answers whether it was kept: a key is enrolled once in a
    /// realm, and the same credential a second time is kept for nobody.
    async fn insert_security_key(&mut self, key: &SecurityKey) -> Result<bool, StorageError>;

    /// The keys of a person, oldest first.
    async fn list_security_keys(&mut self, person: Uuid) -> Result<Vec<SecurityKey>, StorageError>;

    /// Keeps the record of a key after a use, and when it was, in one
    /// operation that compares: answers `true` only when the person still
    /// holds the key as `judged` read it, its record and the instant of its
    /// last use. Of two uses judged against one reading, one is kept, whether
    /// or not the key moved its counter.
    async fn record_key_use(
        &mut self,
        judged: &SecurityKey,
        record: Option<&[u8]>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Removes every key of a person. Answers how many there were.
    async fn delete_security_keys(&mut self, person: Uuid) -> Result<u64, StorageError>;

    /// Keeps what finishes the enrollment a person started, in place of
    /// what an earlier start left.
    async fn write_key_enrollment(
        &mut self,
        person: Uuid,
        state: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError>;

    /// Takes what finishes the enrollment of a person: returns it and
    /// removes it, in one operation. Expired at `now`, it is not returned.
    async fn take_key_enrollment(
        &mut self,
        person: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, StorageError>;
}
