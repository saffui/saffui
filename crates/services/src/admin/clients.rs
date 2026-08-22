//! Registering, reshaping and retiring a client.

use crypto::password::storage::StoredPassword;
use crypto::provider::{Argon2Params, CryptoProvider};
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::client::{ClientCreateModel, ClientModel, Protocol};
use models::paging::Page;
use secrecy::{ExposeSecret, SecretBox};
use store::providers::{client_scopes, clients};
use store::query::list_query::ListQuery;
use url::Url;

use crate::provisioning::{STANDARD_SCOPES, provision_standard_scopes};

/// What a client is registered as.
#[derive(Debug, Clone, Default)]
pub struct Spec {
    pub name: Option<String>,
    pub confidential: bool,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    /// Where a logout token is posted when a login this client took part in
    /// ends.
    pub backchannel_logout_uri: Option<String>,
    /// Where the browser loads a frame when a login this client took part in
    /// ends.
    pub frontchannel_logout_uri: Option<String>,
}

/// What a registered client is reshaped to. Nothing named is nothing changed.
#[derive(Debug, Clone, Default)]
pub struct Reshape {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Doubly optional: nothing named leaves it alone, `Some(None)` clears it.
    pub backchannel_logout_uri: Option<Option<String>>,
    pub frontchannel_logout_uri: Option<Option<String>>,
}

/// Where a confidential client's secret comes from.
pub enum Secret<'a> {
    /// Drawn here and handed back once.
    Drawn,
    /// Supplied by the caller, as provisioning does from its environment.
    Given(&'a SecretBox<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unregistrable {
    #[error("a client with this identifier already exists")]
    AlreadyExists,
    #[error("no such client")]
    NotFound,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("the store could not be written")]
    Unwritable,
}

/// Register a client, and hand back its secret when it has one: this is the
/// only time the secret exists in the clear.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one registration"
)]
pub async fn register(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    client_id: &str,
    spec: &Spec,
    secret: Secret<'_>,
) -> Result<(ClientModel, Option<String>), Unregistrable> {
    check_id(client_id)?;
    check(spec)?;
    if clients::load(transaction, client_id)
        .await
        .map_err(|_| Unregistrable::Unwritable)?
        .is_some()
    {
        return Err(Unregistrable::AlreadyExists);
    }

    let metadata = AuditableModel::from_creator(tenant.to_owned(), by.to_owned());
    let mut client = ClientCreateModel {
        name: spec.name.clone().unwrap_or_else(|| client_id.to_owned()),
        display_name: spec.name.clone().unwrap_or_else(|| client_id.to_owned()),
        description: String::new(),
        enabled: Some(true),
    }
    .into_model(client_id.to_owned(), realm_id.to_owned(), metadata);
    client.protocol = Some(Protocol::OpenId);
    client.public_client = Some(!spec.confidential);
    client.standard_flow_enabled = Some(true);
    client.service_account_enabled = Some(false);
    client.direct_access_grants_enabled = Some(false);
    client.implicit_flow_enabled = Some(false);
    apply(&mut client, spec);
    clients::create(transaction, &client)
        .await
        .map_err(|_| Unregistrable::Unwritable)?;
    clients::update(transaction, &client)
        .await
        .map_err(|_| Unregistrable::Unwritable)?;

    // Every standard scope, and every one optional: granted when asked for
    // and not otherwise.
    provision_standard_scopes(transaction, tenant, realm_id)
        .await
        .map_err(|_| Unregistrable::Unwritable)?;
    for (scope, _, _) in STANDARD_SCOPES {
        client_scopes::attach_scope(transaction, client_id, scope, true)
            .await
            .map_err(|_| Unregistrable::Unwritable)?;
    }

    let mut shown = None;
    if spec.confidential {
        let drawn;
        let secret = match secret {
            Secret::Given(given) => given,
            Secret::Drawn => {
                drawn = SecretBox::new(Box::new(draw(provider)?));
                shown = Some(drawn.expose_secret().clone());
                &drawn
            }
        };
        keep_secret(transaction, provider, client_id, secret).await?;
    }
    Ok((client, shown))
}

/// One page of the realm's clients.
pub async fn list(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> Result<Page<ClientModel>, Unregistrable> {
    clients::list(transaction, query, with_total)
        .await
        .map_err(|_| Unregistrable::Unwritable)
}

pub async fn get(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> Result<ClientModel, Unregistrable> {
    clients::load(transaction, client_id)
        .await
        .map_err(|_| Unregistrable::Unwritable)?
        .ok_or(Unregistrable::NotFound)
}

/// Reshape a registered client. A list left out is a list left alone.
pub async fn update(
    transaction: &Transaction<'_>,
    client_id: &str,
    reshape: &Reshape,
) -> Result<ClientModel, Unregistrable> {
    let mut client = get(transaction, client_id).await?;
    let spec = Spec {
        name: reshape.name.clone(),
        confidential: client.public_client != Some(true),
        redirect_uris: reshape
            .redirect_uris
            .clone()
            .or_else(|| client.redirect_uris.clone())
            .unwrap_or_default(),
        post_logout_redirect_uris: reshape
            .post_logout_redirect_uris
            .clone()
            .or_else(|| client.post_logout_redirect_uris.clone())
            .unwrap_or_default(),
        backchannel_logout_uri: reshape
            .backchannel_logout_uri
            .clone()
            .unwrap_or_else(|| client.backchannel_logout_uri.clone()),
        frontchannel_logout_uri: reshape
            .frontchannel_logout_uri
            .clone()
            .unwrap_or_else(|| client.frontchannel_logout_uri.clone()),
    };
    check(&spec)?;
    if let Some(name) = &spec.name {
        client.name = name.clone();
        client.display_name = name.clone();
    }
    apply(&mut client, &spec);
    clients::update(transaction, &client)
        .await
        .map_err(|_| Unregistrable::Unwritable)?;
    Ok(client)
}

/// Draw a new secret for a confidential client and hand it back once.
pub async fn rotate_secret(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    client_id: &str,
) -> Result<String, Unregistrable> {
    let client = get(transaction, client_id).await?;
    if client.public_client == Some(true) {
        return Err(Unregistrable::Invalid("a public client keeps no secret"));
    }
    let drawn = draw(provider)?;
    keep_secret(
        transaction,
        provider,
        client_id,
        &SecretBox::new(Box::new(drawn.clone())),
    )
    .await?;
    Ok(drawn)
}

pub async fn remove(transaction: &Transaction<'_>, client_id: &str) -> Result<bool, Unregistrable> {
    clients::delete(transaction, client_id)
        .await
        .map_err(|_| Unregistrable::Unwritable)
}

fn apply(client: &mut ClientModel, spec: &Spec) {
    client.redirect_uris = Some(spec.redirect_uris.clone());
    client.post_logout_redirect_uris = (!spec.post_logout_redirect_uris.is_empty())
        .then(|| spec.post_logout_redirect_uris.clone());
    client.backchannel_logout_uri = spec.backchannel_logout_uri.clone();
    client.backchannel_logout_session_required = spec.backchannel_logout_uri.is_some();
    client.frontchannel_logout_uri = spec.frontchannel_logout_uri.clone();
    client.frontchannel_logout_session_required = spec.frontchannel_logout_uri.is_some();
}

/// RFC 6749 §3.1.2: a redirect is absolute and carries no fragment. The same
/// holds for the other places a browser is sent.
fn check(spec: &Spec) -> Result<(), Unregistrable> {
    let places = spec
        .redirect_uris
        .iter()
        .chain(&spec.post_logout_redirect_uris)
        .chain(spec.backchannel_logout_uri.as_ref())
        .chain(spec.frontchannel_logout_uri.as_ref());
    for uri in places {
        let parsed =
            Url::parse(uri).map_err(|_| Unregistrable::Invalid("a URI is not absolute"))?;
        if parsed.fragment().is_some() {
            return Err(Unregistrable::Invalid("a URI carries a fragment"));
        }
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(Unregistrable::Invalid("a URI is neither http nor https"));
        }
    }
    Ok(())
}

fn check_id(client_id: &str) -> Result<(), Unregistrable> {
    let shaped = !client_id.is_empty()
        && client_id.len() <= 255
        && client_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'));
    shaped.then_some(()).ok_or(Unregistrable::Invalid(
        "a client identifier is letters, digits, - _ . :",
    ))
}

/// 32 bytes of the provider's randomness, spelled to travel in a form.
fn draw(provider: &dyn CryptoProvider) -> Result<String, Unregistrable> {
    let mut drawn = [0u8; 32];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unregistrable::Unwritable)?;
    Ok(BASE64URL_NOPAD.encode(&drawn))
}

async fn keep_secret(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    client_id: &str,
    secret: &SecretBox<String>,
) -> Result<(), Unregistrable> {
    let StoredPassword::Argon2id { encoded } =
        StoredPassword::hash_argon2id(provider, Argon2Params::default(), secret)
            .map_err(|_| Unregistrable::Unwritable)?
    else {
        return Err(Unregistrable::Unwritable);
    };
    clients::rotate_secret(transaction, client_id, &encoded, None)
        .await
        .map_err(|_| Unregistrable::Unwritable)?;
    Ok(())
}
