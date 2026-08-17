//! Failed login attempts, and the lockout they earn.

use serde::{Deserialize, Serialize};

/// What a realm has counted against one user.
///
/// It counts. The shape this replaces could start at zero, be loaded from a row
/// and be reset, and had no way to record a failure, so the arithmetic that
/// decides a lockout lived in whatever called it and this was a bag of getters.
/// A counter that cannot count leaves every caller to agree on how, and they
/// only have to disagree once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserLoginFailure {
    pub tenant: String,
    pub failure_id: String,
    pub realm_id: String,
    pub user_id: String,
    /// Logins before this instant are refused. Zero means no lockout.
    pub failed_login_not_before: i64,
    pub num_failures: i64,
    /// Unix epoch seconds of the most recent failure, zero if there is none.
    pub last_failure: i64,
    pub last_ip_failure: Option<String>,
}

impl UserLoginFailure {
    /// A clean record: nothing counted, nothing locked.
    pub fn new(
        tenant: impl Into<String>,
        failure_id: impl Into<String>,
        realm_id: impl Into<String>,
        user_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant: tenant.into(),
            failure_id: failure_id.into(),
            realm_id: realm_id.into(),
            user_id: user_id.into(),
            failed_login_not_before: 0,
            num_failures: 0,
            last_failure: 0,
            last_ip_failure: None,
        }
    }

    /// Count one failure.
    ///
    /// The address is recorded as the last one seen rather than accumulated. A
    /// lockout is per user, and keeping every address a failure came from turns
    /// a counter into a log that grows without a bound anybody set.
    pub fn record_failure(&mut self, at: i64, ip_address: Option<String>) {
        self.num_failures = self.num_failures.saturating_add(1);
        self.last_failure = at;
        self.last_ip_failure = ip_address;
    }

    /// Refuse logins until `not_before`.
    pub fn lock_until(&mut self, not_before: i64) {
        self.failed_login_not_before = not_before;
    }

    /// Whether a login is refused right now.
    ///
    /// The instant itself is allowed: `not_before` is when logins resume, and
    /// refusing at exactly that second would hold the lock a second longer than
    /// whoever set it asked for.
    pub fn is_locked_at(&self, now: i64) -> bool {
        now < self.failed_login_not_before
    }

    /// Forget everything counted, including the lockout.
    ///
    /// A successful login clears the record, so a user who eventually gets in
    /// does not carry a count towards a lockout they already escaped.
    pub fn clear(&mut self) {
        self.failed_login_not_before = 0;
        self.num_failures = 0;
        self.last_failure = 0;
        self.last_ip_failure = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> UserLoginFailure {
        UserLoginFailure::new("acme", "failure-1", "realm-1", "ada")
    }

    #[test]
    fn a_new_record_counts_nothing_and_locks_nothing() {
        let record = record();
        assert_eq!(record.num_failures, 0);
        assert_eq!(record.last_failure, 0);
        assert_eq!(record.last_ip_failure, None);
        assert!(!record.is_locked_at(0));
        assert!(!record.is_locked_at(i64::MAX));
    }

    /// It counts, which is the whole reason the record exists.
    #[test]
    fn each_failure_is_counted_and_dated() {
        let mut record = record();

        record.record_failure(1_000, Some("198.51.100.7".into()));
        assert_eq!(record.num_failures, 1);
        assert_eq!(record.last_failure, 1_000);
        assert_eq!(record.last_ip_failure.as_deref(), Some("198.51.100.7"));

        record.record_failure(1_060, Some("203.0.113.9".into()));
        assert_eq!(record.num_failures, 2);
        assert_eq!(record.last_failure, 1_060);
        assert_eq!(
            record.last_ip_failure.as_deref(),
            Some("203.0.113.9"),
            "the last address seen, not the first"
        );

        record.record_failure(1_120, None);
        assert_eq!(record.num_failures, 3);
        assert_eq!(
            record.last_ip_failure, None,
            "a failure from nowhere clears the address rather than keeping a stale one"
        );
    }

    /// The count does not wrap. A counter that overflowed would read as a user
    /// with no failures at all.
    #[test]
    fn the_count_saturates_rather_than_wrapping() {
        let mut record = UserLoginFailure {
            num_failures: i64::MAX,
            ..record()
        };
        record.record_failure(1_000, None);
        assert_eq!(record.num_failures, i64::MAX);
    }

    /// The lock runs up to its instant and not past it.
    #[test]
    fn the_lock_ends_at_the_instant_it_names() {
        let mut record = record();
        record.lock_until(2_000);

        assert!(record.is_locked_at(1_999));
        assert!(
            !record.is_locked_at(2_000),
            "the instant logins resume is not itself refused"
        );
        assert!(!record.is_locked_at(2_001));
    }

    /// A successful login clears the lockout too, so a user who gets in does not
    /// keep a count towards one they already escaped.
    #[test]
    fn clearing_forgets_the_lockout_as_well_as_the_count() {
        let mut record = record();
        record.record_failure(1_000, Some("198.51.100.7".into()));
        record.lock_until(9_000);
        assert!(record.is_locked_at(1_000));

        record.clear();
        assert_eq!(record.num_failures, 0);
        assert_eq!(record.last_failure, 0);
        assert_eq!(record.last_ip_failure, None);
        assert!(!record.is_locked_at(1_000));
    }
}
