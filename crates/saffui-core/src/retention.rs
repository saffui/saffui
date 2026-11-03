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

/// How a table came out of a pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PurgeOutcome {
    /// Its last batch came back short: what the pass may remove is gone.
    #[default]
    Done,
    /// It spent its part of the pass with rows left: the next pass goes on.
    RowsLeft,
    /// A batch failed. The batches before it stay removed.
    Failed,
}

/// What a pass did to one table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TablePurge {
    pub removed: u64,
    pub outcome: PurgeOutcome,
}

/// What one pass did, table by table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub pending_requests: TablePurge,
    pub codes: TablePurge,
    pub refresh_tokens: TablePurge,
    pub sessions: TablePurge,
    pub known_browsers: TablePurge,
    pub failure_counters: TablePurge,
    pub key_enrollments: TablePurge,
}

impl PurgeReport {
    /// Each table under the name the journal gives it, in the order of a pass.
    #[must_use]
    pub fn list_tables(&self) -> [(&'static str, TablePurge); 7] {
        [
            ("pending_requests", self.pending_requests),
            ("codes", self.codes),
            ("refresh_tokens", self.refresh_tokens),
            ("sessions", self.sessions),
            ("known_browsers", self.known_browsers),
            ("failure_counters", self.failure_counters),
            ("key_enrollments", self.key_enrollments),
        ]
    }
}

#[async_trait]
pub trait Retention: Send + Sync {
    /// Removes, in every realm, what is older than `cutoffs` says, in
    /// bounded batches, as long as they come back full and `budget` is not
    /// spent: what one pass leaves, the next removes. A table that fails or
    /// is left with rows is said in the report. Returns `None` when another
    /// node is doing it: the work is done once.
    async fn purge_expired(
        &self,
        cutoffs: PurgeCutoffs,
        budget: std::time::Duration,
    ) -> Result<Option<PurgeReport>, StorageError>;
}

/// Runs one pass of retention at `now`, given `budget` to remove in.
///
/// # Errors
///
/// Returns the storage failure when the pass cannot start, when its link
/// closes on the way, or when every table fails. The batches removed before
/// stay removed: each was of no use, and the next pass goes on from there.
pub async fn run_retention_pass(
    retention: &dyn Retention,
    now: OffsetDateTime,
    budget: std::time::Duration,
) -> Result<Option<PurgeReport>, StorageError> {
    retention.purge_expired(PurgeCutoffs::at(now), budget).await
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
            _budget: std::time::Duration,
        ) -> Result<Option<PurgeReport>, StorageError> {
            self.0.lock().expect("a lock nobody poisoned").push(cutoffs);
            Ok(Some(PurgeReport::default()))
        }
    }

    #[test]
    fn a_pass_removes_what_expired_keeps_codes_a_session_long_and_counters_two_days() {
        let retention = Recorded::default();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("an instant");

        let report = complete(run_retention_pass(
            &retention,
            now,
            std::time::Duration::from_secs(1),
        ));

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
