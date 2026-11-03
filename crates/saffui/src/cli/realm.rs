//! `saffui realm show`: read a realm through the administration API of a
//! running node. The first command that talks to a node over the network.

use std::io::{self, Write};
use std::process::ExitCode;

use api::RealmView;
use clap::{Args, Subcommand};
use saffui_core::tenancy::RealmName;

use crate::cli::api_client::{AdminSession, CallFailure};
use crate::cli::output::neutralize;
use crate::cli::serve::read_variable;
use crate::config::client::{
    CLIENT_ID, CLIENT_SECRET, ClientSettingError, SERVER, resolve_credentials, resolve_server,
};

#[derive(Args)]
pub(crate) struct RealmCommand {
    #[command(subcommand)]
    action: RealmAction,
}

#[derive(Subcommand)]
enum RealmAction {
    /// Show a realm as its administration API tells it.
    Show(ShowOptions),
}

#[derive(Args)]
#[command(after_help = format!(
    "The client is named by {CLIENT_ID}, and its secret by {CLIENT_SECRET}, a reference: file:///path or env://NAME.\n\
     The secret is sent to whatever listens on that port: run this on a machine no other account uses.\n\
     Exit codes: 2 a setting written wrong, 3 authentication missing or failed, 4 refused, 5 not found, 1 anything else."
))]
struct ShowOptions {
    /// The name of the realm.
    #[arg(long, value_name = "NAME")]
    realm: String,
    #[arg(
        long,
        value_name = "URL",
        help = format!("Where a node answers, as http://127.0.0.1:PORT or http://[::1]:PORT [env: {SERVER}]")
    )]
    server: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum ShowError {
    #[error("--realm: {0}")]
    Realm(&'static str),
    #[error(transparent)]
    Setting(#[from] ClientSettingError),
    #[error(transparent)]
    Call(#[from] CallFailure),
    #[error("the node answered with a realm it does not describe")]
    Unreadable,
}

impl ShowError {
    /// The exit code: 3 when no client is named to authenticate as, 2 for
    /// any other setting written wrong, and what the node said otherwise.
    fn exit_status(&self) -> u8 {
        match self {
            Self::Setting(
                ClientSettingError::ClientMissing | ClientSettingError::SecretMissing,
            ) => 3,
            Self::Realm(_) | Self::Setting(_) => 2,
            Self::Call(failure) => failure.exit_status(),
            Self::Unreadable => 1,
        }
    }
}

/// Runs `realm` to its end and returns the exit code of the process.
pub(crate) fn run_command(command: &RealmCommand) -> ExitCode {
    let RealmAction::Show(options) = &command.action;
    match show_realm(options) {
        Ok(told) => {
            if io::stdout().write_all(told.as_bytes()).is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(io::stderr(), "error: {error}");
            ExitCode::from(error.exit_status())
        }
    }
}

fn show_realm(options: &ShowOptions) -> Result<String, ShowError> {
    // Judged here, so that the path is built from a name that needs no escaping.
    let realm = RealmName::parse(&options.realm)
        .map_err(|failure| ShowError::Realm(failure.code.message()))?;
    let server = resolve_server(options.server.as_deref(), read_variable)?;
    let credentials = resolve_credentials(read_variable)?;
    let session = AdminSession::sign_in(server, realm, &credentials)?;
    let answer = session.read("")?;
    let shown: RealmView = serde_json::from_str(&answer).map_err(|_| ShowError::Unreadable)?;
    Ok(format!(
        "name {}\nissuer {}\nenabled {}\ncreated_at {}\nid {}\ntenant_id {}\n",
        neutralize(&shown.name),
        neutralize(&shown.issuer),
        shown.enabled,
        neutralize(&shown.created_at),
        neutralize(&shown.id),
        neutralize(&shown.tenant_id),
    ))
}

#[cfg(test)]
mod tests {
    use super::ShowError;
    use crate::cli::api_client::CallFailure;
    use crate::config::client::ClientSettingError;

    #[test]
    fn a_missing_client_asks_for_authentication_and_a_setting_written_wrong_is_misuse() {
        assert_eq!(
            ShowError::Setting(ClientSettingError::ClientMissing).exit_status(),
            3
        );
        assert_eq!(
            ShowError::Setting(ClientSettingError::SecretMissing).exit_status(),
            3
        );
        assert_eq!(
            ShowError::Setting(ClientSettingError::ServerRefused).exit_status(),
            2
        );
        assert_eq!(ShowError::Realm("not a name").exit_status(), 2);
        assert_eq!(ShowError::Call(CallFailure::NotFound).exit_status(), 5);
        assert_eq!(ShowError::Unreadable.exit_status(), 1);
    }
}
