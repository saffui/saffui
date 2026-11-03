use super::{Client, read_named_client};
use crate::app::App;
use crate::error::{ErrorCode, Failure};
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;

/// Authenticates a client by the secret it presents.
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
        .map_or(&[0_u8; 32][..], |known| known.secret_digest.as_slice());
    let matches = app
        .digester
        .equal_in_constant_time(&presented_digest, expected);
    match client {
        Some(client) if matches && client.enabled => Ok(client),
        _ => Err(Failure::new(ErrorCode::ClientAuthenticationFailed)),
    }
}
