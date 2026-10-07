//! The journal: plain text on standard error, one line per event.

use std::io;

use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;

/// What the targets of the product start with. A crate of the product named
/// otherwise is added here the day it writes, or its INFO lines are dropped.
const PRODUCT_TARGET_PREFIX: &str = "saffui";

/// Starts the journal for the rest of the process.
pub(crate) fn start_journal() {
    // The product is heard from INFO. What the framework writes through `tracing`
    // is heard from WARN: at INFO it tells of its own workers. What it writes
    // through `log`, as actix-web does, is not heard at all: no bridge is installed.
    let product_from_info = Targets::new()
        .with_default(Level::WARN)
        .with_target(PRODUCT_TARGET_PREFIX, Level::INFO);
    let journal = tracing_subscriber::fmt()
        .with_writer(io::stderr)
        // Said here, so that a dependency turning the color feature on changes nothing.
        .with_ansi(false)
        // The default reports a failed write with a macro that panics when
        // standard error is the very writer that failed.
        .log_internal_errors(false)
        .finish()
        .with(product_from_info);
    // Fails only when a journal is already installed, and then that one stays.
    let _ = tracing::subscriber::set_global_default(journal);
}
