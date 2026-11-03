//! The timers of a node. Each calls a pass of the core and says what it did.

use std::sync::Arc;
use std::time::Duration;

use saffui_core::ports::clock::Clock;
use saffui_core::retention::{Retention, run_retention_pass};
use tracing::{error, info};

/// How often a node offers to run the retention pass. Every node offers;
/// one of them does it.
const RETENTION_PERIOD: Duration = Duration::from_mins(10);

/// Starts the timer of retention on the runtime of the caller. The first
/// pass runs at once: a node that restarts often still purges.
pub(crate) fn start_retention(retention: Arc<dyn Retention>, clock: Arc<dyn Clock>) {
    actix_rt::spawn(async move {
        let mut timer = actix_rt::time::interval(RETENTION_PERIOD);
        loop {
            timer.tick().await;
            match run_retention_pass(retention.as_ref(), clock.now()).await {
                Ok(Some(report)) => info!(
                    pending_requests = report.pending_requests,
                    codes = report.codes,
                    failure_counters = report.failure_counters,
                    "retention pass done"
                ),
                // Another node holds the lock: the work is being done.
                Ok(None) => {}
                // Said and tried again at the next tick: a pass that fails
                // removed nothing, and serving does not depend on it.
                Err(_) => error!("retention pass failed"),
            }
        }
    });
}
