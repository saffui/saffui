//! Retention: what has no use left is removed. A pending request past its
//! expiry can never be finished, a session past its expiry answers nothing,
//! nor do its refresh tokens, a browser kept past its mark proves nothing,
//! and a counter of the brake older than every
//! window that reads it counts for nothing. A spent code is kept while what
//! it obtained could still be taken back.
//!
//! This is one of the rare works across tenants. It runs under a role of
//! its own, never the one that serves, and one node at a time.

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};

use crate::login::session::SESSION_LIFETIME;
use crate::ports::storage::StorageError;

/// How long a counter of the brake is kept after its bucket started: twice
/// the longest window that reads it, the day, so that a purge never frees a
/// name that is still locked.
pub const FAILURE_COUNTERS_KEPT: Duration = Duration::days(2);

/// How long a code is kept after it expired. Presented again, a spent code
/// takes back the refresh tokens it obtained, and none outlives the
/// session it was issued in.
pub const CODES_KEPT: Duration = SESSION_LIFETIME;

/// Where each table of a pass stops: rows older than these go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PurgeCutoffs {
    /// Pending requests, sessions, refresh tokens and known browsers that
    /// expired before this.
    pub expired_before: OffsetDateTime,
    /// Codes that expired before this.
    pub codes_before: OffsetDateTime,
    /// Counters of the brake whose bucket started before this.
    pub counters_before: OffsetDateTime,
}

impl PurgeCutoffs {
    #[must_use]
    pub fn at(now: OffsetDateTime) -> Self {
        Self {
            expired_before: now,
            codes_before: now - CODES_KEPT,
            counters_before: now - FAILURE_COUNTERS_KEPT,
        }
    }
}

/// How many rows one pass removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub pending_requests: u64,
    pub codes: u64,
    pub refresh_tokens: u64,
    pub sessions: u64,
    pub known_browsers: u64,
    pub failure_counters: u64,
}

#[async_trait]
pub trait Retention: Send + Sync {
    /// Removes, in every realm, what is older than `cutoffs` says, in
    /// bounded batches: what one pass leaves, the next removes. Returns
    /// `None` when another node is doing it: the work is done once.
    async fn purge_expired(
        &self,
        cutoffs: PurgeCutoffs,
    ) -> Result<Option<PurgeReport>, StorageError>;
}

/// Runs one pass of retention at `now`.
///
/// # Errors
///
/// Returns the storage failure. The batches removed before it stay removed:
/// each was of no use, and the next pass goes on from there.
pub async fn run_retention_pass(
    retention: &dyn Retention,
    now: OffsetDateTime,
) -> Result<Option<PurgeReport>, StorageError> {
    retention.purge_expired(PurgeCutoffs::at(now)).await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use time::{Duration, OffsetDateTime};

    use super::{PurgeCutoffs, PurgeReport, Retention, run_retention_pass};
    use crate::ports::storage::StorageError;
    use crate::testkit::drive::complete;

    #[derive(Default)]
    struct Recorded(Mutex<Vec<PurgeCutoffs>>);

    #[async_trait]
    impl Retention for Recorded {
        async fn purge_expired(
            &self,
            cutoffs: PurgeCutoffs,
        ) -> Result<Option<PurgeReport>, StorageError> {
            self.0.lock().expect("a lock nobody poisoned").push(cutoffs);
            Ok(Some(PurgeReport::default()))
        }
    }

    #[test]
    fn a_pass_removes_what_expired_keeps_codes_a_session_long_and_counters_two_days() {
        let retention = Recorded::default();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("an instant");

        let report = complete(run_retention_pass(&retention, now));

        assert_eq!(report, Ok(Some(PurgeReport::default())));
        assert_eq!(
            *retention.0.lock().expect("a lock nobody poisoned"),
            [PurgeCutoffs {
                expired_before: now,
                codes_before: now - Duration::hours(12),
                counters_before: now - Duration::days(2),
            }]
        );
    }
}
