//! The journal: plain text on standard error, one line per event.

use std::io;

use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;

/// What the targets of the product start with, one per crate that writes.
/// A crate that is not named here loses its INFO lines.
const PRODUCT_TARGETS: [&str; 5] = ["saffui", "saffui_core", "server", "store", "pgcore"];

/// Starts the journal for the rest of the process.
pub(crate) fn start_journal() {
    // The product is heard from INFO. What the framework writes through `tracing`
    // is heard from WARN: at INFO it tells of its own workers. What it writes
    // through `log`, as actix-web does, is not heard at all: no bridge is installed.
    let product_from_info = PRODUCT_TARGETS
        .iter()
        .fold(Targets::new().with_default(Level::WARN), |targets, name| {
            targets.with_target(*name, Level::INFO)
        });
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
