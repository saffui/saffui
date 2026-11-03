//! The timers of a node. Each calls a pass of the core and says what it did.

use std::sync::Arc;
use std::time::Duration;

use saffui_core::ports::clock::Clock;
use saffui_core::retention::{PurgeOutcome, PurgeReport, Retention, run_retention_pass};
use tracing::{error, info, warn};

/// How often a node offers to run the retention pass. Every node offers;
/// one of them does it.
const RETENTION_PERIOD: Duration = Duration::from_mins(10);

/// How long a pass goes on removing: a tenth of the period, room for millions
/// of rows, and a pass ends long before the next one is offered.
const RETENTION_BUDGET: Duration = Duration::from_mins(1);

/// Starts the timer of retention on the runtime of the caller. The first
/// pass runs at once: a node that restarts often still purges. Each pass
/// runs as a task of its own: one that panics is said, and the next tick
/// runs the next.
pub(crate) fn start_retention(retention: Arc<dyn Retention>, clock: Arc<dyn Clock>) {
    start_retention_every(retention, clock, RETENTION_PERIOD);
}

fn start_retention_every(retention: Arc<dyn Retention>, clock: Arc<dyn Clock>, period: Duration) {
    actix_rt::spawn(async move {
        let mut timer = actix_rt::time::interval(period);
        loop {
            timer.tick().await;
            let pass = {
                let retention = Arc::clone(&retention);
                let now = clock.now();
                actix_rt::spawn(async move {
                    run_retention_pass(retention.as_ref(), now, RETENTION_BUDGET).await
                })
            };
            match pass.await {
                Ok(Ok(Some(report))) => {
                    info!(
                        pending_requests = report.pending_requests.removed,
                        codes = report.codes.removed,
                        refresh_tokens = report.refresh_tokens.removed,
                        sessions = report.sessions.removed,
                        known_browsers = report.known_browsers.removed,
                        failure_counters = report.failure_counters.removed,
                        "retention pass done"
                    );
                    warn_unfinished_tables(&report);
                }
                // Another node holds the lock: the work is being done.
                Ok(Ok(None)) => {}
                // The pass could not start, lost its link, or failed on every
                // table. Tried again at the next tick: serving does not wait on it.
                Ok(Err(_)) => error!("retention pass failed"),
                Err(_) => error!("retention pass panicked"),
            }
        }
    });
}

/// Says each table a pass left unfinished: one that fails at every pass, or
/// never catches up, would otherwise grow unseen.
fn warn_unfinished_tables(report: &PurgeReport) {
    for (table, purged) in report.list_tables() {
        match purged.outcome {
            PurgeOutcome::Done => {}
            PurgeOutcome::RowsLeft => warn!(
                table,
                removed = purged.removed,
                "retention left rows to the next pass"
            ),
            PurgeOutcome::Failed => warn!(
                table,
                removed = purged.removed,
                "retention failed on a table"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use saffui_core::ports::storage::StorageError;
    use saffui_core::retention::{PurgeCutoffs, PurgeReport, Retention};
    use saffui_core::testkit::clock::FixedClock;

    use super::start_retention_every;

    /// A retention whose first pass panics.
    #[derive(Default)]
    struct PanicsFirst(AtomicU32);

    #[async_trait]
    impl Retention for PanicsFirst {
        async fn purge_expired(
            &self,
            _cutoffs: PurgeCutoffs,
            _budget: Duration,
        ) -> Result<Option<PurgeReport>, StorageError> {
            assert!(
                self.0.fetch_add(1, Ordering::SeqCst) > 0,
                "a first pass that panics"
            );
            Ok(None)
        }
    }

    #[test]
    fn a_pass_that_panics_leaves_the_timer_running() {
        let retention = Arc::new(PanicsFirst::default());
        let passes = Arc::clone(&retention);

        actix_rt::System::new().block_on(async move {
            start_retention_every(
                retention,
                Arc::new(FixedClock::default()),
                Duration::from_millis(5),
            );
            for _ in 0..400 {
                if passes.0.load(Ordering::SeqCst) >= 3 {
                    return;
                }
                actix_rt::time::sleep(Duration::from_millis(5)).await;
            }
            panic!("the timer stopped after the pass that panicked");
        });
    }
}
