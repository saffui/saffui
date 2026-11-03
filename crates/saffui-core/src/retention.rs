//! Retention: what has no use left is removed. A code or a pending request
//! past its expiry can never be presented again, and a counter of the brake
//! older than every window that reads it counts for nothing.
//!
//! This is one of the rare works across tenants. It runs under a role of
//! its own, never the one that serves, and one node at a time.

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};

use crate::ports::storage::StorageError;

/// How long a counter of the brake is kept after its bucket started: twice
/// the longest window that reads it, the day, so that a purge never frees a
/// name that is still locked.
pub const FAILURE_COUNTERS_KEPT: Duration = Duration::days(2);

/// How many rows one pass removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub pending_requests: u64,
    pub codes: u64,
    pub failure_counters: u64,
}

#[async_trait]
pub trait Retention: Send + Sync {
    /// Removes, in every realm, what expired before `expired_before` and the
    /// counters whose bucket started before `counters_before`. Returns
    /// `None` when another node is doing it: the work is done once.
    async fn purge_expired(
        &self,
        expired_before: OffsetDateTime,
        counters_before: OffsetDateTime,
    ) -> Result<Option<PurgeReport>, StorageError>;
}

/// Runs one pass of retention at `now`.
///
/// # Errors
///
/// Returns the storage failure. Nothing was removed then: the pass is one
/// transaction.
pub async fn run_retention_pass(
    retention: &dyn Retention,
    now: OffsetDateTime,
) -> Result<Option<PurgeReport>, StorageError> {
    retention
        .purge_expired(now, now - FAILURE_COUNTERS_KEPT)
        .await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use time::{Duration, OffsetDateTime};

    use super::{PurgeReport, Retention, run_retention_pass};
    use crate::ports::storage::StorageError;
    use crate::testkit::drive::complete;

    #[derive(Default)]
    struct Recorded(Mutex<Vec<(OffsetDateTime, OffsetDateTime)>>);

    #[async_trait]
    impl Retention for Recorded {
        async fn purge_expired(
            &self,
            expired_before: OffsetDateTime,
            counters_before: OffsetDateTime,
        ) -> Result<Option<PurgeReport>, StorageError> {
            self.0
                .lock()
                .expect("a lock nobody poisoned")
                .push((expired_before, counters_before));
            Ok(Some(PurgeReport::default()))
        }
    }

    #[test]
    fn a_pass_removes_what_expired_and_keeps_the_counters_of_the_brake_two_days() {
        let retention = Recorded::default();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("an instant");

        let report = complete(run_retention_pass(&retention, now));

        assert_eq!(report, Ok(Some(PurgeReport::default())));
        assert_eq!(
            *retention.0.lock().expect("a lock nobody poisoned"),
            [(now, now - Duration::days(2))]
        );
    }
}
