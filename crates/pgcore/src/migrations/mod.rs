//! Getting the schema to its current version.
//!
//! Numbered SQL and resumable Rust backfills, applied forward only, under the
//! advisory lock so one process applies at a time.

mod error;
mod migration;
mod runner;

pub use error::MigrationError;
pub use migration::{AppliedRecord, DataMigration, Migration, SqlMigration};
pub use runner::{MigrationOptions, MigrationReport, MigrationRunner};
