use std::sync::Arc;

use time::OffsetDateTime;

use crate::ports::clock::Clock;
use crate::ports::random::Random;
use crate::ports::storage::Storage;
use crate::settings::Settings;

/// Everything a use case can reach. The binary fills it once.
#[derive(Clone)]
pub struct App {
    pub settings: Settings,
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub random: Arc<dyn Random>,
}

impl App {
    /// The time, at the precision the storage keeps: an instant read back is
    /// equal to the one that was written.
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        let now = self.clock.now();
        now.replace_nanosecond(now.nanosecond() / 1_000 * 1_000)
            .unwrap_or(now)
    }
}
