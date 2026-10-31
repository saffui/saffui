use time::OffsetDateTime;

use crate::ports::clock::Clock;

/// A clock that stands still.
pub struct FixedClock {
    now: OffsetDateTime,
}

impl Default for FixedClock {
    /// Noon on the first day of 2026, with a fraction a database would truncate.
    fn default() -> Self {
        let noon = OffsetDateTime::from_unix_timestamp_nanos(1_767_268_800_123_456_789)
            .expect("an instant in range");
        Self { now: noon }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.now
    }
}
