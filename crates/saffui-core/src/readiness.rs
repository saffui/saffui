//! Whether this instance should receive traffic.

use crate::app::App;
use crate::ports::storage::StorageUnavailable;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Readiness {
    Ready,
    /// Shutdown was requested: traffic must move away.
    Draining,
    StorageUnavailable(StorageUnavailable),
}

/// Decides readiness. A draining instance answers without touching the
/// storage: it is leaving, whatever the database says.
pub async fn check_readiness(app: &App, draining: bool) -> Readiness {
    if draining {
        return Readiness::Draining;
    }
    match app.storage.probe().await {
        Ok(()) => Readiness::Ready,
        Err(reason) => Readiness::StorageUnavailable(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::{Readiness, check_readiness};
    use crate::ports::storage::StorageUnavailable;
    use crate::testkit::drive::complete;
    use crate::testkit::memory::MemoryStorage;

    #[test]
    fn the_reachable_storage_makes_the_instance_ready() {
        let (app, _storage) = MemoryStorage::wire();
        assert_eq!(complete(check_readiness(&app, false)), Readiness::Ready);
    }

    #[test]
    fn the_reason_the_storage_gives_is_passed_on() {
        let (app, storage) = MemoryStorage::wire();
        storage.fail_with(StorageUnavailable::PoolExhausted);

        assert_eq!(
            complete(check_readiness(&app, false)),
            Readiness::StorageUnavailable(StorageUnavailable::PoolExhausted)
        );
    }

    #[test]
    fn a_draining_instance_answers_without_probing_the_storage() {
        let (app, storage) = MemoryStorage::wire();

        assert_eq!(complete(check_readiness(&app, true)), Readiness::Draining);
        assert_eq!(storage.count_probes(), 0, "the storage was not asked");
    }
}
