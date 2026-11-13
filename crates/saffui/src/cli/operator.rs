//! The `operator` command: what the operator of a deployment does to a realm
//! through its database, as `bootstrap` does, outside the administration
//! plane. A client of the plane hands out only what it holds, so what came
//! after every client of a realm reaches it here: a capability, and a key.

use std::io::{self, Write};
use std::process::ExitCode;

use actix_rt::System;
use clap::{Args, Subcommand};
use pgcore::pool::PoolSettings;
use saffui_core::authz::capability::Capability;
use saffui_core::clients::manage::grant_capabilities_as_operator;
use saffui_core::error::{ErrorKind, Failure};
use saffui_core::keys::rotate::rotate_signing_key_as_operator;
use saffui_core::ports::crypto::SignatureAlgorithm;
use saffui_core::settings::Settings;

use crate::cli::serve::read_variable;
use crate::config::crypto::{ROOT_KEY, RootKeyError, resolve_root_key};
use crate::config::database::{
    DATABASE_TLS, DATABASE_URL, DatabaseSettingsError, resolve_connection,
};
use crate::config::hashing::PASSWORD_HASHERS;
use crate::config::origin::{PUBLIC_ORIGIN, PublicOriginSettingError, resolve_public_origin};
use crate::telemetry;
use crate::wiring::{Sealing, StartupRefusal, Wired, WiringError, wire_product};

#[derive(Args)]
pub(crate) struct OperatorCommand {
    #[command(subcommand)]
    action: OperatorAction,
}

#[derive(Subcommand)]
enum OperatorAction {
    /// Give a client of a realm capabilities beside those it holds.
    Grant(GrantOptions),
    /// Give a realm a new key of an algorithm: it signs at once, and the key
    /// of that algorithm it replaces is retired.
    RotateKey(RotateKeyOptions),
}

/// How the command reaches the deployment: as `bootstrap` does.
#[derive(Args)]
struct DeploymentOptions {
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

#[derive(Args)]
#[command(after_help = format!(
    "It seals nothing: {ROOT_KEY} is not read.\n\
     Exit codes: 2 a setting or a capability written wrong, or a client that holds none, 4 refused, 5 no such realm or client, 1 anything else."
))]
struct GrantOptions {
    /// The name of the realm.
    #[arg(long, value_name = "NAME")]
    realm: String,
    /// The identifier of the client.
    #[arg(long, value_name = "IDENTIFIER")]
    client: String,
    /// A capability to give, as key:write. Repeat it for each one.
    #[arg(long = "capability", value_name = "CAPABILITY", required = true)]
    capabilities: Vec<String>,
    #[command(flatten)]
    deployment: DeploymentOptions,
}

#[derive(Args)]
#[command(after_help = format!(
    "The key is sealed under the root key, named by {ROOT_KEY}: file:///path or env://NAME.\n\
     Exit codes: 2 a setting or an algorithm written wrong, 4 refused, as for a realm that holds as many keys as it may, 5 no such realm, 1 anything else."
))]
struct RotateKeyOptions {
    /// The name of the realm.
    #[arg(long, value_name = "NAME")]
    realm: String,
    #[arg(
        long,
        value_name = "ALGORITHM",
        help = "The algorithm of the key: ES256, ES384, RS256, PS256 or EdDSA"
    )]
    alg: String,
    #[command(flatten)]
    deployment: DeploymentOptions,
}

#[derive(Debug, thiserror::Error)]
enum OperatorError {
    #[error(transparent)]
    Origin(#[from] PublicOriginSettingError),
    #[error(transparent)]
    Database(#[from] DatabaseSettingsError),
    #[error(transparent)]
    RootKey(#[from] RootKeyError),
    #[error("{0}")]
    Argument(&'static str),
    #[error(transparent)]
    Wiring(#[from] WiringError),
    #[error("refusing to write: {0}")]
    Refused(#[from] StartupRefusal),
    #[error("{}", .0.code.message())]
    Failed(Failure),
}

impl OperatorError {
    /// The exit code: 2 for what the caller wrote wrong, 5 for a realm or a
    /// client the deployment does not have, 4 for what it refuses, 1 else.
    fn exit_code(&self) -> ExitCode {
        match self {
            Self::Origin(_) | Self::Database(_) | Self::RootKey(_) | Self::Argument(_) => {
                ExitCode::from(2)
            }
            Self::Failed(failure) => match failure.code.kind() {
                ErrorKind::Invalid => ExitCode::from(2),
                ErrorKind::NotFound => ExitCode::from(5),
                ErrorKind::Forbidden | ErrorKind::Conflict => ExitCode::from(4),
                ErrorKind::Unauthenticated | ErrorKind::Unavailable | ErrorKind::Internal => {
                    ExitCode::FAILURE
                }
            },
            Self::Wiring(_) | Self::Refused(_) => ExitCode::FAILURE,
        }
    }
}

/// Runs `operator` to its end and returns the exit code of the process.
pub(crate) fn run_command(command: &OperatorCommand) -> ExitCode {
    let done = match &command.action {
        OperatorAction::Grant(options) => grant_from_options(options),
        OperatorAction::RotateKey(options) => rotate_from_options(options),
    };
    match done {
        Ok(told) => {
            // What was written is written: a write that fails here still must not pass for success.
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

/// Wires the product on its database, on one connection, as `bootstrap` does.
fn wire_deployment(
    options: &DeploymentOptions,
    sealing: Sealing<'_>,
) -> Result<Wired, OperatorError> {
    let public_origin = resolve_public_origin(options.public_origin.as_deref(), read_variable)?;
    let database =
        resolve_connection(DATABASE_URL, options.database_tls.as_deref(), read_variable)?;
    telemetry::start_journal();
    let one_connection = PoolSettings {
        max_size: 1,
        ..PoolSettings::default()
    };
    Ok(wire_product(
        Settings::reached_directly(public_origin),
        &database,
        one_connection,
        sealing,
        PASSWORD_HASHERS.default,
    )?)
}

fn grant_from_options(options: &GrantOptions) -> Result<String, OperatorError> {
    let capabilities = options
        .capabilities
        .iter()
        .map(|name| Capability::parse(name))
        .collect::<Option<Vec<Capability>>>()
        .ok_or(OperatorError::Argument("--capability: no such capability"))?;
    // A grant seals and opens nothing: it runs without the root key.
    let wired = wire_deployment(&options.deployment, Sealing::Refused)?;
    let client = System::new().block_on(async {
        wired.refuse_unfit_database().await?;
        grant_capabilities_as_operator(&wired.app, &options.realm, &options.client, &capabilities)
            .await
            .map_err(OperatorError::Failed)
    })?;
    let held: Vec<&str> = client
        .capabilities
        .iter()
        .map(|capability| capability.name())
        .collect();
    Ok(format!(
        "client {}\ncapabilities {}\n",
        client.client_id,
        held.join(",")
    ))
}

fn rotate_from_options(options: &RotateKeyOptions) -> Result<String, OperatorError> {
    let algorithm = SignatureAlgorithm::parse(&options.alg)
        .ok_or(OperatorError::Argument("--alg: no such algorithm"))?;
    let root_key = resolve_root_key(read_variable)?;
    let wired = wire_deployment(&options.deployment, Sealing::UnderRootKey(&root_key))?;
    let key = System::new().block_on(async {
        wired.refuse_unfit_database().await?;
        rotate_signing_key_as_operator(&wired.app, &options.realm, algorithm)
            .await
            .map_err(OperatorError::Failed)
    })?;
    Ok(format!(
        "kid {}\nalg {}\n",
        key.key_id,
        key.algorithm.name()
    ))
}
