use super::{Client, read_named_client};
use crate::app::App;
use crate::error::{ErrorCode, Failure};
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;

/// Authenticates a client by the secret it presents. A public application
/// has none to present: it is compared against a digest nothing matches.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientAuthenticationFailed`] for a client that does
/// not exist, that is disabled, or whose secret is wrong: the three answer
/// alike and take the same work. Returns the storage failure otherwise.
pub async fn authenticate_client(
    app: &App,
    work: &mut dyn UnitOfWork,
    client_id: &str,
    presented: &Secret,
) -> Result<Client, Failure> {
    let client = read_named_client(work, client_id).await?;
    let presented_digest = app.digester.sha256(presented.expose());
    // An unknown client is compared too, against a digest nothing matches:
    // the answer does not come sooner for a client that does not exist.
    let expected = client
        .as_ref()
        .and_then(|known| known.secret_digest.as_deref())
        .unwrap_or(&[0_u8; 32][..]);
    let matches = app
        .digester
        .equal_in_constant_time(&presented_digest, expected);
    match client {
        Some(client) if matches && client.enabled => Ok(client),
        _ => Err(Failure::new(ErrorCode::ClientAuthenticationFailed)),
    }
}

/// Identifies the client behind a request made for a person. A confidential
/// client proves itself with its secret. A public client has none to prove
/// with: it is only named, and what it presents next, a code with its
/// verifier, is what binds the request to it.
///
/// # Errors
///
/// As [`authenticate_client`]. A confidential client that presents no
/// secret is refused like a wrong one.
pub async fn identify_client(
    app: &App,
    work: &mut dyn UnitOfWork,
    client_id: &str,
    presented: Option<Secret>,
) -> Result<Client, Failure> {
    match presented {
        Some(secret) => authenticate_client(app, work, client_id, &secret).await,
        None => read_named_client(work, client_id)
            .await?
            .filter(|client| client.enabled && client.secret_digest.is_none())
            .ok_or(Failure::new(ErrorCode::ClientAuthenticationFailed)),
    }
}
