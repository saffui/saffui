use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use time::OffsetDateTime;

use crate::ports::clock::Clock;

/// A clock that stands still until a test moves it.
pub struct FixedClock {
    now: Mutex<OffsetDateTime>,
}

impl Default for FixedClock {
    /// Noon on the first day of 2026, with a fraction a database would truncate.
    fn default() -> Self {
        let noon = OffsetDateTime::from_unix_timestamp_nanos(1_767_268_800_123_456_789)
            .expect("an instant in range");
        Self {
            now: Mutex::new(noon),
        }
    }
}

impl FixedClock {
    /// Moves the clock forward.
    pub fn advance(&self, by: Duration) {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner) += by;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
