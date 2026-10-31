//! The `bootstrap` command: create a tenant and its first realm. What an
//! operator runs once per customer, against a migrated database.

use std::io::{self, Write};
use std::process::ExitCode;

use actix_rt::System;
use clap::Args;
use pgcore::pool::PoolSettings;
use saffui_core::error::{ErrorKind, Failure};
use saffui_core::oidc::discovery::name_issuer;
use saffui_core::settings::Settings;
use saffui_core::tenancy::realm::{NewRealm, Provisioned, provision_first_realm};

use crate::cli::serve::read_variable;
use crate::config::database::{
    DATABASE_TLS, DATABASE_URL, DatabaseSettingsError, resolve_connection,
};
use crate::config::origin::{PUBLIC_ORIGIN, PublicOriginSettingError, resolve_public_origin};
use crate::telemetry;
use crate::wiring::{StartupRefusal, WiringError, wire_product};

#[derive(Args)]
pub(crate) struct BootstrapOptions {
    /// The name of the tenant: the customer that hosts the realm.
    #[arg(long, value_name = "NAME")]
    tenant: String,
    /// The name of the realm, as it will appear in its URLs and its issuer.
    #[arg(long, value_name = "NAME")]
    realm: String,
    #[arg(
        long,
        value_name = "ORIGIN",
        help = format!("Where the public reaches this deployment, as https://host[:port]. Required [env: {PUBLIC_ORIGIN}]")
    )]
    public_origin: Option<String>,
    #[arg(
        long,
        value_name = "MODE",
        help = format!("How the database link is protected: disable, require or verify-full [env: {DATABASE_TLS}]")
    )]
    database_tls: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum BootstrapError {
    #[error(transparent)]
    Origin(#[from] PublicOriginSettingError),
    #[error(transparent)]
    Database(#[from] DatabaseSettingsError),
    #[error(transparent)]
    Wiring(#[from] WiringError),
    #[error("refusing to write: {0}")]
    Refused(#[from] StartupRefusal),
    #[error("{}", .0.code.message())]
    Failed(Failure),
}

impl BootstrapError {
    fn exit_code(&self) -> ExitCode {
        match self {
            Self::Origin(_) | Self::Database(_) => ExitCode::from(2),
            // A name that cannot be used is the caller's to fix, like any argument.
            Self::Failed(failure) if failure.code.kind() == ErrorKind::Invalid => ExitCode::from(2),
            Self::Wiring(_) | Self::Refused(_) | Self::Failed(_) => ExitCode::FAILURE,
        }
    }
}

/// Runs `bootstrap` to its end and returns the exit code of the process.
pub(crate) fn run_command(options: &BootstrapOptions) -> ExitCode {
    match provision_from_options(options) {
        Ok(told) => {
            // What was created is created: a write that fails here still must not pass for success.
            if io::stdout().write_all(told.as_bytes()).is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(io::stderr(), "error: {error}");
            error.exit_code()
        }
    }
}

fn provision_from_options(options: &BootstrapOptions) -> Result<String, BootstrapError> {
    let public_origin = resolve_public_origin(options.public_origin.as_deref(), read_variable)?;
    let database =
        resolve_connection(DATABASE_URL, options.database_tls.as_deref(), read_variable)?;
    // Started after the settings, as for serve: what a failed write tells the
    // journal is the only account of it.
    telemetry::start_journal();
    let one_connection = PoolSettings {
        max_size: 1,
        ..PoolSettings::default()
    };
    let wired = wire_product(Settings { public_origin }, &database, one_connection)?;

    let provisioned: Provisioned = System::new().block_on(async {
        wired.refuse_unfit_database().await?;
        provision_first_realm(
            &wired.app,
            NewRealm {
                tenant_name: &options.tenant,
                realm_name: &options.realm,
            },
        )
        .await
        .map_err(BootstrapError::Failed)
    })?;

    Ok(format!(
        "tenant {}\nrealm {}\nissuer {}\n",
        provisioned.tenant.id.as_uuid(),
        provisioned.realm.id.as_uuid(),
        name_issuer(&wired.app.settings, &provisioned.realm.name)
    ))
}
