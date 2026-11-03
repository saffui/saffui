//! The counters of the brake on guesses, in constant SQL: one statement sums
//! over buckets, one adds to a bucket or opens it, one forgets a counter.

use async_trait::async_trait;
use saffui_core::login::store::ThrottleStore;
use saffui_core::ports::storage::StorageError;
use time::OffsetDateTime;

use crate::work::PgUnitOfWork;

#[async_trait]
impl ThrottleStore for PgUnitOfWork {
    async fn count_login_failures(
        &mut self,
        identifier_digest: &[u8],
        since: OffsetDateTime,
    ) -> Result<u32, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                "SELECT COALESCE(sum(failures), 0)::int4 FROM login_failures
                 WHERE tenant_id = $1 AND realm_id = $2 AND identifier_digest = $3
                   AND bucket_start >= $4",
                &[&tenant, &realm, &identifier_digest, &since],
            )
            .await?;
        let counted: i32 = rows.first().ok_or(StorageError::Failed)?.get(0);
        u32::try_from(counted).map_err(|_| StorageError::Failed)
    }

    async fn record_login_failure(
        &mut self,
        identifier_digest: &[u8],
        bucket_start: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let (tenant, realm) = self.scope_keys();
        // One statement: two attempts recorded at once both count.
        self.execute_raw(
            "INSERT INTO login_failures
                 (tenant_id, realm_id, identifier_digest, bucket_start, failures)
             VALUES ($1, $2, $3, $4, 1)
             ON CONFLICT (tenant_id, realm_id, identifier_digest, bucket_start)
             DO UPDATE SET failures = login_failures.failures + 1",
            &[&tenant, &realm, &identifier_digest, &bucket_start],
        )
        .await
        .map(|_| ())
    }

    async fn forget_login_failures(
        &mut self,
        identifier_digest: &[u8],
    ) -> Result<(), StorageError> {
        let (tenant, realm) = self.scope_keys();
        self.execute_raw(
            "DELETE FROM login_failures
             WHERE tenant_id = $1 AND realm_id = $2 AND identifier_digest = $3",
            &[&tenant, &realm, &identifier_digest],
        )
        .await
        .map(|_| ())
    }
}
