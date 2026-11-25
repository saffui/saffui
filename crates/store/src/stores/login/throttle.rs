//! The counters of the brake on guesses, in constant SQL: one statement sums
//! over buckets, one adds to a bucket or opens it, one does both under a
//! bound, one forgets a counter.

use async_trait::async_trait;
use saffui_core::login::store::ThrottleStore;
use saffui_core::ports::storage::StorageError;
use time::OffsetDateTime;

use crate::work::PgUnitOfWork;

/// Adds to the bucket `$4` of a counter unless the buckets since `$5` hold
/// `$6` already, in one statement. A bound reached and committed is read
/// before any row is written: the attempt adds nothing, and locks nothing
/// another attempt would wait for. The bucket being filled is judged again
/// on its row as the upsert locks it: of two attempts at once, the second
/// waits for the first, then reads what it wrote. Earlier buckets are no
/// longer written.
const RECORD_ATTEMPT_WITHIN: &str = "
    INSERT INTO login_failures (tenant_id, realm_id, identifier_digest, bucket_start, failures)
    SELECT $1::uuid, $2::uuid, $3::bytea, $4::timestamptz, 1
    WHERE (SELECT COALESCE(sum(failures), 0) FROM login_failures
           WHERE tenant_id = $1 AND realm_id = $2 AND identifier_digest = $3
             AND bucket_start >= $5) < $6
    ON CONFLICT (tenant_id, realm_id, identifier_digest, bucket_start)
    DO UPDATE SET failures = login_failures.failures + 1
    WHERE login_failures.failures
        + (SELECT COALESCE(sum(earlier.failures), 0) FROM login_failures AS earlier
           WHERE earlier.tenant_id = $1 AND earlier.realm_id = $2
             AND earlier.identifier_digest = $3
             AND earlier.bucket_start >= $5 AND earlier.bucket_start < $4) < $6
    RETURNING failures";

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

    async fn record_attempt_within(
        &mut self,
        identifier_digest: &[u8],
        bucket_start: OffsetDateTime,
        since: OffsetDateTime,
        most: u32,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let most = i64::from(most);
        let counted = self
            .read_raw(
                RECORD_ATTEMPT_WITHIN,
                &[
                    &tenant,
                    &realm,
                    &identifier_digest,
                    &bucket_start,
                    &since,
                    &most,
                ],
            )
            .await?;
        Ok(!counted.is_empty())
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
