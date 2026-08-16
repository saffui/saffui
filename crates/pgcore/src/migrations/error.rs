//! Why a migration run stopped.

/// Each names what is wrong with the set or the history, never how to fix it —
/// these reach a startup log, and the fix depends on which of the two is right.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MigrationError {
    #[error("version {version} appears twice in the embedded set")]
    DuplicateVersion { version: i32 },

    #[error("the database has version {version} applied, which this build does not contain")]
    UnknownApplied { version: i32 },

    #[error("version {version} ({name}) was edited after it was applied")]
    ChecksumDrift { version: i32, name: String },

    #[error("version {version} is new but sorts below one already applied")]
    OutOfOrder { version: i32 },

    #[error("the migration lock could not be taken")]
    Lock,

    #[error("the history table could not be read or written")]
    History,

    #[error("version {version} ({name}) failed to apply")]
    Apply { version: i32, name: String },

    #[error("no database connection")]
    Connect,
}
