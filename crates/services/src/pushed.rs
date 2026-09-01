use chrono::{DateTime, Duration, Utc};
use crypto::provider::{CryptoProvider, HashAlg};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use deadpool_postgres::Transaction;
use models::entities::client::ClientModel;
use serde_json::{Map, Value};
use store::providers::pushed::{self, Pushed};

/// What every reference this server hands out starts with, §2.2. A value
/// that does not is one this server never issued.
pub const HANDLE: &str = "urn:ietf:params:oauth:request_uri:";

/// How long a pushed request may sit. §2.2 asks for short; a browser is
/// redirected at once, so a minute is long enough to be generous.
const LIFESPAN: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unpushable {
    /// The parameters name another client than the one that authenticated.
    #[error("the request names another client")]
    NotTheClient,
    /// A pushed request carrying a reference to another one.
    #[error("a pushed request cannot carry a reference")]
    CarriesAReference,
    #[error("the request could not be kept")]
    Unwritable,
    /// A push that already violates the client's own security profile.
    #[error("{0}")]
    AgainstTheProfile(&'static str),
}

/// Keep a pushed request, and hand back the reference and how long it lives.
pub async fn keep_request(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    client: &ClientModel,
    parameters: &Map<String, Value>,
    now: DateTime<Utc>,
) -> Result<(String, i64), Unpushable> {
    if let Some(named) = parameters.get("client_id").and_then(Value::as_str)
        && named != client.client_id
    {
        return Err(Unpushable::NotTheClient);
    }
    // §2.1: a pushed request cannot carry a reference to another one.
    if parameters.contains_key("request_uri") {
        return Err(Unpushable::CarriesAReference);
    }
    // FAPI 2.0: what would be refused at the authorization endpoint anyway is
    // refused here, where the client still gets a status code it can read.
    if crate::fapi::is_fapi2(client) {
        if parameters.get("response_type").and_then(Value::as_str) != Some("code") {
            return Err(Unpushable::AgainstTheProfile(
                "the profile speaks the code flow alone",
            ));
        }
        if !parameters.contains_key("code_challenge") {
            return Err(Unpushable::AgainstTheProfile(
                "the profile requires proof key for code exchange",
            ));
        }
    }

    let mut drawn = [0u8; 32];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unpushable::Unwritable)?;
    let handle = format!("{HANDLE}{}", BASE64URL_NOPAD.encode(&drawn));
    let expires_at = now + Duration::seconds(LIFESPAN);
    pushed::keep(
        transaction,
        &reference_digest(provider, &handle)?,
        &client.client_id,
        &Value::Object(parameters.clone()),
        expires_at,
    )
    .await
    .map_err(|_| Unpushable::Unwritable)?;
    Ok((handle, LIFESPAN))
}

/// The parameters a reference stands for, spent by the asking.
pub async fn spend_reference(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    handle: &str,
) -> Option<PushedRequest> {
    if !handle.starts_with(HANDLE) {
        return None;
    }
    let hashed = reference_digest(provider, handle).ok()?;
    match pushed::spend(transaction, &hashed).await {
        Ok(Pushed::Fresh {
            client_id,
            parameters: Value::Object(map),
        }) => Some(PushedRequest { map, client_id }),
        _ => None,
    }
}

/// A pushed request, owned so the request built from it can borrow it.
pub struct PushedRequest {
    map: Map<String, Value>,
    pub client_id: String,
}

impl PushedRequest {
    fn text(&self, named: &str) -> Option<&str> {
        self.map.get(named).and_then(Value::as_str)
    }

    /// What was pushed, read as the request it stands for. Nothing from the
    /// browser's own query is read: what the client pushed is the request.
    pub fn as_request(&self) -> crate::authorize::Requested<'_> {
        crate::authorize::Requested {
            response_type: self.text("response_type"),
            client_id: Some(&self.client_id),
            redirect_uri: self.text("redirect_uri"),
            scope: self.text("scope"),
            state: self.text("state"),
            nonce: self.text("nonce"),
            code_challenge: self.text("code_challenge"),
            code_challenge_method: self.text("code_challenge_method"),
            dpop_jkt: self.text("dpop_jkt"),
            request: self.text("request"),
            request_uri: None,
            response_mode: self.text("response_mode"),
            prompt: self.text("prompt"),
            max_age: self.map.get("max_age").and_then(|held| {
                held.as_i64()
                    .or_else(|| held.as_str().and_then(|spelled| spelled.parse().ok()))
            }),
            acr_values: self.text("acr_values"),
            claims: self.text("claims"),
            organization: self.text("organization"),
            ui_locales: self.text("ui_locales"),
        }
    }
}

/// The digest the row is keyed by. The reference travels in a URL and is
/// never stored, so a leaked table yields nothing usable.
fn reference_digest(provider: &dyn CryptoProvider, handle: &str) -> Result<String, Unpushable> {
    let hashed = provider
        .digest()
        .hash(HashAlg::Sha256, handle.as_bytes())
        .map_err(|_| Unpushable::Unwritable)?;
    Ok(HEXLOWER.encode(&hashed))
}
