//! The `migrate` command: apply what is pending, under the role that owns the
//! schema. A serving node never does this.

use std::io::{self, Write};
use std::process::ExitCode;

use actix_rt::System;
use clap::Args;
use pgcore::migrate::{EMBEDDED, MigrateError, apply_pending};

use crate::cli::serve::read_variable;
use crate::config::database::{
    DATABASE_TLS, DatabaseSettingsError, MIGRATION_DATABASE_URL, resolve_connection,
};

#[derive(Args)]
pub(crate) struct MigrateOptions {
    #[arg(
        long,
        value_name = "MODE",
        help = format!("How the database link is protected: disable, require or verify-full [env: {DATABASE_TLS}]")
    )]
    database_tls: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum MigrateCommandError {
    #[error(transparent)]
    Settings(#[from] DatabaseSettingsError),
    #[error("cannot migrate: {0}")]
    Run(#[from] MigrateError),
}

/// Runs `migrate` to its end and returns the exit code of the process.
pub(crate) fn run_command(options: &MigrateOptions) -> ExitCode {
    match apply_embedded_migrations(options) {
        Ok(told) => {
            if writeln!(io::stdout(), "{told}").is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(io::stderr(), "error: {error}");
            match error {
                MigrateCommandError::Settings(_) => ExitCode::from(2),
                MigrateCommandError::Run(_) => ExitCode::FAILURE,
            }
        }
    }
}

fn apply_embedded_migrations(options: &MigrateOptions) -> Result<String, MigrateCommandError> {
    let connection = resolve_connection(
        MIGRATION_DATABASE_URL,
        options.database_tls.as_deref(),
        read_variable,
    )?;
    let report = System::new().block_on(apply_pending(&connection, EMBEDDED))?;
    Ok(if report.applied.is_empty() {
        format!(
            "schema at version {}: nothing to apply",
            report.schema_version
        )
    } else {
        format!(
            "schema at version {}: applied {:?}",
            report.schema_version, report.applied
        )
    })
}
