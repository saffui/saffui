use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::session::Session;
use crate::ports::storage::StorageError;

#[async_trait]
pub trait SessionStore {
    async fn insert_session(&mut self, session: &Session) -> Result<(), StorageError>;

    async fn read_session(&mut self, id: Uuid) -> Result<Option<Session>, StorageError>;

    /// Ends a session that is still active, and tells whether it did: of two
    /// endings at once, one ends it. It is kept, ended, until it expires and
    /// retention removes it: what it did stays explainable until then.
    async fn end_session(&mut self, id: Uuid) -> Result<bool, StorageError>;
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
