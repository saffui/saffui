//! The `serve` command: read the settings, bind both planes, serve until a
//! signal asks to stop.

use std::fmt;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::process::ExitCode;
use std::task::Poll;

use actix_rt::System;
use actix_rt::signal::unix::{SignalKind, signal};
use clap::Args;
use pgcore::pool::BuildPoolError;
use server::serve::{
    BindError, DEFAULT_DRAIN_TIMEOUT_SECONDS, PlaneAddresses, ShutdownOptions, bind_planes,
};

use crate::config::database::{
    DATABASE_POOL_SIZE, DATABASE_TLS, DATABASE_URL, DatabaseSettingsError, resolve_connection,
    resolve_pool_settings,
};
use tracing::info;

use crate::config::serving::{
    DATA_PLANE, DRAIN_DELAY, OPS_PLANE, ServingSettingsError, Setting, resolve_serving_settings,
};
use crate::telemetry;
use crate::wiring::{StartupRefusal, wire_product};

#[derive(Args)]
pub(crate) struct ServeOptions {
    #[arg(
        long,
        value_name = "ADDRESS",
        help = describe_setting("Address of the data plane", &DATA_PLANE)
    )]
    listen: Option<String>,
    #[arg(
        long,
        value_name = "ADDRESS",
        help = describe_setting("Address of the operations plane", &OPS_PLANE)
    )]
    ops_listen: Option<String>,
    #[arg(
        long,
        value_name = "SECONDS",
        help = describe_setting("Delay between failing readiness and stopping", &DRAIN_DELAY)
    )]
    drain_delay: Option<String>,
    #[arg(
        long,
        value_name = "MODE",
        help = format!("How the database link is protected: disable, require or verify-full [env: {DATABASE_TLS}]")
    )]
    database_tls: Option<String>,
    #[arg(
        long,
        value_name = "CONNECTIONS",
        help = describe_setting("Connections this node keeps to the database", &DATABASE_POOL_SIZE)
    )]
    database_pool_size: Option<String>,
}

fn describe_setting<T: fmt::Display>(purpose: &str, setting: &Setting<T>) -> String {
    format!(
        "{purpose} [env: {}] [default: {}]",
        setting.variable, setting.default
    )
}

/// Runs `serve` to its end and returns the exit code of the process.
pub(crate) fn run_command(options: &ServeOptions) -> ExitCode {
    match serve_until_signal(options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // A write that fails here has nowhere left to be told: the code still tells.
            let _ = writeln!(io::stderr(), "error: {error}");
            error.exit_code()
        }
    }
}

enum ServeError {
    Settings(ServingSettingsError),
    Database(DatabaseSettingsError),
    Wiring(BuildPoolError),
    Refused(StartupRefusal),
    Bind(BindError),
    Serving(io::Error),
}

impl ServeError {
    fn exit_code(&self) -> ExitCode {
        match self {
            // A setting that cannot be used is a usage error, option or variable alike.
            Self::Settings(_) | Self::Database(_) => ExitCode::from(2),
            Self::Wiring(_) | Self::Refused(_) | Self::Bind(_) | Self::Serving(_) => {
                ExitCode::FAILURE
            }
        }
    }
}

impl fmt::Display for ServeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Settings(error) => error.fmt(formatter),
            Self::Database(error) => error.fmt(formatter),
            Self::Wiring(error) => write!(formatter, "cannot reach the database: {error}"),
            Self::Refused(error) => write!(formatter, "refusing to serve: {error}"),
            Self::Bind(BindError { address, source }) => {
                write!(formatter, "cannot listen on {address}: {source}")
            }
            Self::Serving(source) => write!(formatter, "cannot serve: {source}"),
        }
    }
}

fn serve_until_signal(options: &ServeOptions) -> Result<(), ServeError> {
    let settings = resolve_serving_settings(
        options.listen.as_deref(),
        options.ops_listen.as_deref(),
        options.drain_delay.as_deref(),
        read_variable,
    )
    .map_err(ServeError::Settings)?;
    let database = resolve_connection(DATABASE_URL, options.database_tls.as_deref(), read_variable)
        .map_err(ServeError::Database)?;
    let pool = resolve_pool_settings(options.database_pool_size.as_deref(), read_variable)
        .map_err(ServeError::Database)?;
    telemetry::start_journal();
    let wired = wire_product(&database, pool).map_err(ServeError::Wiring)?;

    // Both are bound before anything is announced: an address already taken
    // fails here, not after the journal says the process listens.
    let planes = bind_planes(
        PlaneAddresses {
            data: settings.data,
            ops: settings.ops,
        },
        ShutdownOptions {
            drain_delay_seconds: settings.drain_delay_seconds,
            drain_timeout_seconds: DEFAULT_DRAIN_TIMEOUT_SECONDS,
        },
        wired.app.clone(),
    )
    .map_err(ServeError::Bind)?;

    System::new()
        .block_on(async {
            // Before anything is announced: a node that cannot read its
            // database, or that row security does not bind, never serves.
            if let Err(refusal) = wired.refuse_unfit_database().await {
                return Ok(Err(refusal));
            }
            let shutdown_requested = listen_for_shutdown_signals()?;
            info!(
                data = %planes.addresses.data,
                ops = %planes.addresses.ops,
                "listening"
            );
            planes.run_until(shutdown_requested).await.map(Ok)
        })
        .map_err(ServeError::Serving)?
        .map_err(ServeError::Refused)?;

    info!("shutdown complete");
    Ok(())
}

/// Read here and not by the argument parser, whose help and errors print the
/// value of every variable it reads. A value that is not Unicode is kept,
/// lossily, so that it fails as unreadable instead of passing for absent.
pub(crate) fn read_variable(name: &str) -> Option<String> {
    std::env::var_os(name).map(|value| value.to_string_lossy().into_owned())
}

/// Installs both handlers at once, before anything serves, and resolves at
/// the first signal. An orchestrator sends SIGTERM and a terminal SIGINT:
/// they ask for the same shutdown. A second signal is ignored: the wait ends
/// by itself, after the drain delay the operator set plus the drain timeout.
fn listen_for_shutdown_signals() -> io::Result<impl Future<Output = ()>> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(async move {
        let received = poll_fn(|context| {
            if interrupt.poll_recv(context).is_ready() {
                Poll::Ready("SIGINT")
            } else {
                terminate.poll_recv(context).map(|_| "SIGTERM")
            }
        })
        .await;
        info!(signal = received, "shutdown requested");
    })
}
