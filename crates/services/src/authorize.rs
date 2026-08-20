//! Where a login starts, and what may be sent onward from it.
//!
//! The split that matters here is not success against failure but showable
//! against sendable. RFC 6749 §4.1.2.1: a request whose client or redirect
//! cannot be trusted is shown to the user and never redirected, because
//! redirecting it is the open redirector.

use chrono::{DateTime, Duration, Utc};
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use models::entities::attributes::AttributeValue;
use models::entities::client::ClientModel;
use serde_json::json;
use store::providers::login::{self, AuthSession};
use store::providers::{auth_flows, clients};

/// How long a login may sit half finished.
const LOGIN_LIFESPAN: i64 = 900;

/// The flow a browser login runs when the client names none.
const BROWSER_FLOW: &str = "browser";

/// What the query asked for.
#[derive(Debug, Default)]
pub struct Requested<'a> {
    pub response_type: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub redirect_uri: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub state: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
}

/// A login opened, and where the browser goes next.
#[derive(Debug)]
pub struct Begun {
    pub auth_session_id: String,
}

/// Why the login did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// Shown to the user. Nothing here may be sent to a redirect, because what
    /// failed is the reason to believe there is one worth sending to.
    #[error("the request names no client this realm will redirect to")]
    Unshowable,
    /// Sent to the registered redirect, as §4.1.2.1 requires, with the state
    /// the client asked to have echoed.
    #[error("{0}")]
    Redirect(&'static str),
}

/// Start a login, or say how the refusal travels.
pub async fn begin(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    requested: &Requested<'_>,
    now: DateTime<Utc>,
) -> Result<Begun, Refusal> {
    let client = named_client(transaction, requested.client_id).await?;
    let redirect_uri = registered_redirect(&client, requested.redirect_uri)?;

    // From here the client and the redirect are established, so a refusal can
    // travel to the client rather than stopping at the user.
    if requested.response_type != Some("code") {
        return Err(Refusal::Redirect("unsupported_response_type"));
    }
    proof_is_registered(&client, requested)?;

    let flow = browser_flow(transaction, &client).await?;
    let auth_session_id = draw_id(provider)?;

    login::start(
        transaction,
        &AuthSession {
            session_id: auth_session_id.clone(),
            client_id: client.client_id.clone(),
            flow_id: flow,
            execution_id: None,
            user_id: None,
            redirect_uri: redirect_uri.to_owned(),
            expires_at: now + Duration::seconds(LOGIN_LIFESPAN),
            // Everything the redemption re-checks and the id token echoes. It
            // is written once, here, because by the time the flow finishes the
            // request that carried it is gone.
            notes: json!({
                "scope": requested.scope.unwrap_or_default(),
                "state": requested.state,
                "nonce": requested.nonce,
                "code_challenge": requested.code_challenge,
                "code_challenge_method": requested.code_challenge_method,
            }),
        },
    )
    .await
    .map_err(|_| Refusal::Redirect("server_error"))?;

    Ok(Begun { auth_session_id })
}

/// The client, or nothing that may be redirected to.
async fn named_client(
    transaction: &Transaction<'_>,
    client_id: Option<&str>,
) -> Result<ClientModel, Refusal> {
    let client_id = client_id
        .filter(|named| !named.is_empty())
        .ok_or(Refusal::Unshowable)?;
    clients::load(transaction, client_id)
        .await
        .map_err(|_| Refusal::Unshowable)?
        .filter(|client| client.enabled != Some(false))
        .ok_or(Refusal::Unshowable)
}

/// The redirect, matched whole against what the client registered.
///
/// Exact, not a prefix and not a pattern. Every open redirector in this protocol
/// is a server that matched loosely, and the code grant compares against this
/// same value later, so a match that is looser here is a match the redemption
/// cannot tighten.
///
/// A client with no registered redirect has none, which refuses everything. The
/// other reading, that an empty registration permits anything, is the open
/// redirector written as a default.
fn registered_redirect<'a>(
    client: &ClientModel,
    asked: Option<&'a str>,
) -> Result<&'a str, Refusal> {
    let asked = asked
        .filter(|uri| !uri.is_empty())
        .ok_or(Refusal::Unshowable)?;
    client
        .redirect_uris
        .as_ref()
        .is_some_and(|registered| registered.iter().any(|uri| uri == asked))
        .then_some(asked)
        .ok_or(Refusal::Unshowable)
}

/// A public client authenticates with nothing, so the challenge is the whole of
/// its proof. Required here rather than only at redemption: a code minted
/// without one is one anybody who intercepts the redirect can spend, and by
/// redemption it is too late to have asked.
fn proof_is_registered(client: &ClientModel, requested: &Requested<'_>) -> Result<(), Refusal> {
    match requested.code_challenge_method {
        Some("S256") | None => {}
        // `plain` is allowed by RFC 7636 §4.2 and deprecated by §7.2, and an
        // unknown method must not be read as the weaker one.
        Some(_) => return Err(Refusal::Redirect("invalid_request")),
    }
    if client.public_client == Some(true) && requested.code_challenge.is_none() {
        return Err(Refusal::Redirect("invalid_request"));
    }
    Ok(())
}

/// The flow this client's browser login runs.
async fn browser_flow(
    transaction: &Transaction<'_>,
    client: &ClientModel,
) -> Result<String, Refusal> {
    let named = client
        .auth_flow_binding_overrides
        .as_ref()
        .and_then(|bound| bound.get(BROWSER_FLOW))
        .and_then(AttributeValue::as_str)
        .unwrap_or(BROWSER_FLOW);

    auth_flows::flow_by_alias(transaction, named)
        .await
        .map_err(|_| Refusal::Redirect("server_error"))?
        .map(|flow| flow.flow_id)
        .ok_or(Refusal::Redirect("server_error"))
}

fn draw_id(provider: &dyn CryptoProvider) -> Result<String, Refusal> {
    let mut drawn = [0_u8; 16];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Refusal::Redirect("server_error"))?;
    Ok(data_encoding::HEXLOWER.encode(&drawn))
}
