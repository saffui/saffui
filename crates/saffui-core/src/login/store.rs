use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::session::Session;
use crate::ports::storage::StorageError;

#[async_trait]
pub trait SessionStore {
    async fn insert_session(&mut self, session: &Session) -> Result<(), StorageError>;

    async fn read_session(&mut self, id: Uuid) -> Result<Option<Session>, StorageError>;
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
}
