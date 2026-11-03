//! Where the command line finds the node it talks to, and the client it
//! talks as. The secret of the client is given by reference, as the root key
//! is: never as an option, never as a value.

use std::net::SocketAddr;

use saffui_core::clients::check_client_identifier;
use saffui_core::secret::Secret;

use super::crypto::{Place, ReferenceFailure, follow_reference};

pub(crate) const SERVER: &str = "SAFFUI_SERVER";
pub(crate) const CLIENT_ID: &str = "SAFFUI_CLIENT_ID";
pub(crate) const CLIENT_SECRET: &str = "SAFFUI_CLIENT_SECRET";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ClientSettingError {
    #[error(
        "--server or {SERVER} is required: where a node of the deployment answers, as http://127.0.0.1:PORT"
    )]
    ServerMissing,
    // What was written is not repeated: it may carry a user and a password.
    #[error(
        "--server or {SERVER}: this command talks to a node on this machine only, over http://, to a loopback address written in digits (127.0.0.1:PORT or [::1]:PORT) and nothing after the port"
    )]
    ServerRefused,
    #[error("{CLIENT_ID} is required: the identifier of a client that may administer the realm")]
    ClientMissing,
    #[error("{CLIENT_ID} is not written as a client identifier")]
    ClientInvalid,
    #[error(
        "{CLIENT_SECRET} is required: a reference to the secret of the client, as file:///path or env://NAME"
    )]
    SecretMissing,
    #[error("{CLIENT_SECRET}: the reference must start with file:// or env://")]
    SecretScheme,
    #[error("{CLIENT_SECRET}: {0} is not set")]
    SecretVariableNotSet(Place),
    #[error("{CLIENT_SECRET}: {0} cannot be read")]
    SecretFileUnreadable(Place),
    #[error("{CLIENT_SECRET}: {0} is readable by others than its owner")]
    SecretFileExposed(Place),
}

/// The node to talk to: a loopback address and its port. No name is kept,
/// so none ever reaches the resolver of the system.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Server(SocketAddr);

impl Server {
    pub(crate) fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.0)
    }
}

/// The client the command line talks as.
pub(crate) struct ClientCredentials {
    pub(crate) client_id: String,
    pub(crate) secret: Secret,
}

/// Reads the node to talk to. Only `http://` to a loopback address written
/// in digits is accepted: the secret of the client crosses this link, and
/// this build has no TLS to protect it on any other.
pub(crate) fn resolve_server(
    option: Option<&str>,
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<Server, ClientSettingError> {
    let written = option
        .map(str::to_owned)
        .or_else(|| read_variable(SERVER))
        .ok_or(ClientSettingError::ServerMissing)?;
    let authority = written
        .strip_prefix("http://")
        .ok_or(ClientSettingError::ServerRefused)?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    // An address, never a name: `localhost` and `[localhost]` would be asked
    // of the resolver, and the resolver may answer with any address.
    let address: SocketAddr = authority
        .parse()
        .map_err(|_| ClientSettingError::ServerRefused)?;
    let zoned = matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0);
    if !address.ip().is_loopback() || address.port() == 0 || zoned {
        return Err(ClientSettingError::ServerRefused);
    }
    Ok(Server(address))
}

/// Reads the client the command line talks as.
pub(crate) fn resolve_credentials(
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<ClientCredentials, ClientSettingError> {
    let client_id = read_variable(CLIENT_ID).ok_or(ClientSettingError::ClientMissing)?;
    check_client_identifier(&client_id).map_err(|_| ClientSettingError::ClientInvalid)?;
    let reference = read_variable(CLIENT_SECRET).ok_or(ClientSettingError::SecretMissing)?;
    let secret = follow_reference(&reference, read_variable).map_err(|failure| match failure {
        ReferenceFailure::UnknownScheme => ClientSettingError::SecretScheme,
        ReferenceFailure::VariableNotSet(place) => ClientSettingError::SecretVariableNotSet(place),
        ReferenceFailure::FileUnreadable(place) => ClientSettingError::SecretFileUnreadable(place),
        ReferenceFailure::FileExposed(place) => ClientSettingError::SecretFileExposed(place),
    })?;
    Ok(ClientCredentials {
        client_id,
        secret: Secret::new(secret.trim().as_bytes().to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CLIENT_ID, CLIENT_SECRET, ClientSettingError, SERVER, resolve_credentials, resolve_server,
    };

    fn nothing(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn a_node_on_this_machine_over_http_is_accepted_from_the_option_or_the_variable() {
        for (written, kept) in [
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
            ("http://127.0.0.1:8080/", "http://127.0.0.1:8080"),
            ("http://127.0.0.2:1", "http://127.0.0.2:1"),
            ("http://[::1]:9000", "http://[::1]:9000"),
        ] {
            assert_eq!(
                resolve_server(Some(written), nothing).map(|server| server.url("")),
                Ok(kept.to_owned()),
                "{written}"
            );
        }
        let from_variable = |name: &str| (name == SERVER).then(|| "http://127.0.0.2:1".to_owned());
        assert_eq!(
            resolve_server(None, from_variable).map(|server| server.url("/x")),
            Ok("http://127.0.0.2:1/x".to_owned())
        );
        assert_eq!(
            resolve_server(None, nothing),
            Err(ClientSettingError::ServerMissing)
        );
    }

    #[test]
    fn a_node_elsewhere_over_tls_named_or_written_with_more_than_its_address_is_refused() {
        for written in [
            "http://id.example.org:8080",
            "http://10.0.0.1:8080",
            "https://127.0.0.1:8443",
            "http://localhost:8080",
            "http://[localhost]:8080",
            "http://[127.0.0.1]:8080",
            "http://[::ffff:127.0.0.1]:8080",
            "http://[::1%1]:8080",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:+8080",
            "http://127.0.0.1:8080/admin",
            "http://user:pass@127.0.0.1:8080",
            "http://127.0.0.1:8080?x=1",
            "127.0.0.1:8080",
        ] {
            let refused = resolve_server(Some(written), nothing);
            assert_eq!(refused, Err(ClientSettingError::ServerRefused), "{written}");
        }
        // The refusal carries nothing: what was written, a password included, is not repeated.
        let told = ClientSettingError::ServerRefused.to_string();
        assert!(told.contains("loopback"), "{told}");
    }

    #[test]
    fn the_secret_of_the_client_is_read_by_reference_and_never_as_a_value() {
        let read = |name: &str| match name {
            CLIENT_ID => Some("operator".to_owned()),
            CLIENT_SECRET => Some("env://THE_SECRET".to_owned()),
            "THE_SECRET" => Some("s3cret\n".to_owned()),
            _ => None,
        };
        let credentials = resolve_credentials(read).expect("credentials");
        assert_eq!(credentials.client_id, "operator");
        assert_eq!(credentials.secret.expose(), b"s3cret");

        let given_as_value = |name: &str| match name {
            CLIENT_ID => Some("operator".to_owned()),
            CLIENT_SECRET => Some("s3cret".to_owned()),
            _ => None,
        };
        let refused = resolve_credentials(given_as_value)
            .map(|_| ())
            .expect_err("a value");
        assert_eq!(refused, ClientSettingError::SecretScheme);
        assert!(!refused.to_string().contains("s3cret"));
        assert_eq!(
            resolve_credentials(nothing).map(|_| ()),
            Err(ClientSettingError::ClientMissing)
        );
    }

    #[test]
    fn a_secret_a_shell_expanded_after_env_is_not_repeated() {
        let expanded = "q3Zx-8Lm_0aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456";
        let reference = format!("env://{expanded}");
        let read = |name: &str| match name {
            CLIENT_ID => Some("operator".to_owned()),
            CLIENT_SECRET => Some(reference.clone()),
            _ => None,
        };
        let refused = resolve_credentials(read)
            .map(|_| ())
            .expect_err("nothing there");
        assert_eq!(
            refused.to_string(),
            "SAFFUI_CLIENT_SECRET: the variable it names is not set"
        );
    }
}
