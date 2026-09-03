use crypto::password::storage::StoredPassword;
use crypto::provider::SignAlg;
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
    /// The application's own base address. A relative redirect registration
    /// leans on it, and the console shows it as the client's home.
    pub root_url: Option<String>,
    /// The browser origins allowed to call the protocol endpoints from
    /// script: what CORS answers for this client. "*" admits any.
    pub web_origins: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    /// Where a logout token is posted when a login this client took part in
    /// ends.
    pub backchannel_logout_uri: Option<String>,
    /// Where the browser loads a frame when a login this client took part in
    /// ends.
    pub frontchannel_logout_uri: Option<String>,
    /// What the client registered about itself, OIDC Registration §2.
    pub registered: Registered,
    /// What the operator wrote about this client, for the people who will read
    /// the list in a year and wonder what it was for.
    pub description: Option<String>,
    /// Which of the grants that are opted into rather than inherited this
    /// client holds. Nothing named is nothing changed, so a re-registration
    /// under RFC 7592 leaves them where the operator put them.
    pub gates: Gates,
}

/// The grants a client holds by an operator's say-so rather than by asking.
///
/// Three keys on the client's own bag, which is where each of the three engines
/// already reads them. None leaves the key as it stands; the alternative would
/// mean every write of a name or a redirect silently retuning what the client
/// may do.
#[derive(Debug, Clone, Default)]
pub struct Gates {
    /// RFC 8628, read by `services::device::allows_device`.
    pub device: Option<bool>,
    /// RFC 8693, read by the exchange grant.
    pub token_exchange: Option<bool>,
    /// CIBA, whose opt-in is the delivery mode itself: there is no separate
    /// flag to disagree with.
    pub ciba: Option<CibaOptIn>,
}

/// How this client is signed in over the backchannel, or not at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CibaOptIn {
    /// The mode goes, and with it the grant.
    Off,
    Poll,
    /// The endpoint the notification is posted to. An https address, checked
    /// where it is read.
    Ping(String),
}

/// What a client says about itself when it registers. Empty for one an
/// administrator makes, which registers nothing.
#[derive(Debug, Clone, Default)]
pub struct Registered {
    /// Whether the person has to agree before this client is given anything.
    /// Absent leaves the client as the store made it.
    pub consent_required: Option<bool>,
    /// How this client registered to receive an identity token and a userinfo
    /// answer, when it registered to receive them encrypted.
    pub id_token_encryption: Option<models::entities::client::JweRegistration>,
    pub userinfo_encryption: Option<models::entities::client::JweRegistration>,
    pub request_object_encryption: Option<models::entities::client::JweRegistration>,
    pub response_types: Option<Vec<String>>,
    pub implicit: bool,
    pub jwks: Option<serde_json::Value>,
    pub jwks_uri: Option<String>,
    pub id_token_signed_response_alg: Option<SignAlg>,
    pub userinfo_signed_response_alg: Option<SignAlg>,
    pub request_object_signing_alg: Option<SignAlg>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub application_type: Option<String>,
    pub default_max_age: Option<i32>,
    pub default_acr_values: Option<Vec<String>>,
    pub initiate_login_uri: Option<String>,
    pub request_uris: Option<Vec<String>>,
    pub subject_type: Option<String>,
    pub sector_identifier_uri: Option<String>,
    pub require_pushed_authorization_requests: Option<bool>,
    /// How this client proves it is itself, as the column spells it.
    pub method: String,
    pub token_endpoint_auth_signing_alg: Option<SignAlg>,
    pub at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Registered {
    /// What this client already registered, so a reshape that names none of it
    /// keeps it rather than clearing it.
    pub fn of(client: &ClientModel) -> Self {
        Registered {
            consent_required: client.consent_required,
            id_token_encryption: client.id_token_encryption,
            userinfo_encryption: client.userinfo_encryption,
            request_object_encryption: client.request_object_encryption,
            response_types: client.response_types.clone(),
            implicit: client.implicit_flow_enabled == Some(true),
            jwks: client.jwks.clone(),
            jwks_uri: client.jwks_uri.clone(),
            id_token_signed_response_alg: client.id_token_signed_response_alg,
            userinfo_signed_response_alg: client.userinfo_signed_response_alg,
            request_object_signing_alg: client.request_object_signing_alg,
            client_uri: client.client_uri.clone(),
            logo_uri: client.logo_uri.clone(),
            policy_uri: client.policy_uri.clone(),
            tos_uri: client.tos_uri.clone(),
            contacts: client.contacts.clone(),
            application_type: client.application_type.clone(),
            default_max_age: client.default_max_age,
            default_acr_values: client.default_acr_values.clone(),
            initiate_login_uri: client.initiate_login_uri.clone(),
            require_pushed_authorization_requests: client.require_pushed_authorization_requests,
            request_uris: client.request_uris.clone(),
            subject_type: client.subject_type.clone(),
            sector_identifier_uri: client.sector_identifier_uri.clone(),
            method: client
                .client_authenticator_type
                .clone()
                .unwrap_or_else(|| "client-secret".to_owned()),
            token_endpoint_auth_signing_alg: client.token_endpoint_auth_signing_alg,
            at: client.registered_at,
        }
    }
}

/// What a registered client is reshaped to. Nothing named is nothing changed.
#[derive(Debug, Clone, Default)]
pub struct Reshape {
    pub name: Option<String>,
    /// Doubly optional, like the logout addresses: `Some(None)` clears it.
    pub root_url: Option<Option<String>>,
    pub web_origins: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Doubly optional: nothing named leaves it alone, `Some(None)` clears it.
    pub backchannel_logout_uri: Option<Option<String>>,
    pub frontchannel_logout_uri: Option<Option<String>>,
    pub description: Option<String>,
    /// The client's home page, OIDC Registration's `client_uri`. Doubly
    /// optional like the addresses above.
    pub client_uri: Option<Option<String>>,
    pub gates: Gates,
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
    client.implicit_flow_enabled = Some(spec.registered.implicit);
    client.registered_at = spec.registered.at;
    apply(&mut client, spec);
    clients::create(transaction, &client)
        .await
        .map_err(|_| Unregistrable::Unwritable)?;
    clients::update(transaction, &client)
        .await
        .map_err(|_| Unregistrable::Unwritable)?;

    // Every standard scope, optional: granted when asked for.
    provision_standard_scopes(transaction, tenant, realm_id)
        .await
        .map_err(|_| Unregistrable::Unwritable)?;
    for (scope, _, _) in STANDARD_SCOPES {
        client_scopes::attach_scope(transaction, client_id, scope, true)
            .await
            .map_err(|_| Unregistrable::Unwritable)?;
    }
    // What the catalogue calls a default joins the offer, optional like the
    // rest: grantable when asked for. The flag answers which scopes a new
    // client is offered, and only that; carrying one unasked stays the
    // plane's per-client act, because `granted_scope` reads the attachment's
    // manner and making a realm-wide flag grant realm-wide was refused
    // there. Read live rather than from the constant above, so a default an
    // administrator made, or unmade, reaches the next client either way.
    for scope in client_scopes::default_scopes(transaction, Protocol::OpenId)
        .await
        .map_err(|_| Unregistrable::Unwritable)?
    {
        client_scopes::attach_scope(transaction, client_id, &scope.client_scope_id, true)
            .await
            .map_err(|_| Unregistrable::Unwritable)?;
    }

    // A client whose assertions are verified against a key it published keeps
    // no secret: one minted for it would be a credential nothing checks.
    let mut shown = None;
    if spec.confidential && spec.registered.method != "private-key-jwt" {
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
    let client = get(transaction, client_id).await?;
    let spec = Spec {
        registered: Registered::of(&client),
        name: reshape.name.clone(),
        confidential: client.public_client != Some(true),
        root_url: reshape
            .root_url
            .clone()
            .unwrap_or_else(|| client.root_url.clone()),
        web_origins: reshape
            .web_origins
            .clone()
            .or_else(|| client.web_origins.clone())
            .unwrap_or_default(),
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
        description: reshape.description.clone(),
        gates: reshape.gates.clone(),
    };
    let mut spec = spec;
    if let Some(home) = &reshape.client_uri {
        spec.registered.client_uri = home.clone();
    }
    reshape_registered(transaction, client_id, &spec).await
}

/// The same, from a whole spec rather than from what a reshape named. RFC 7592
/// §2.2 replaces the registration, so a value the request left out is cleared
/// and not kept.
pub async fn reshape_registered(
    transaction: &Transaction<'_>,
    client_id: &str,
    spec: &Spec,
) -> Result<ClientModel, Unregistrable> {
    let mut client = get(transaction, client_id).await?;
    check(spec)?;
    if let Some(name) = &spec.name {
        client.name = name.clone();
        client.display_name = name.clone();
    }
    client.public_client = Some(!spec.confidential);
    client.implicit_flow_enabled = Some(spec.registered.implicit);
    apply(&mut client, spec);
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

/// Write the named gates onto the client's bag, and only the named ones.
///
/// The engines read these keys as they stand; nothing here invents a second
/// place to say the same thing. Turning one off removes the key rather than
/// writing a false, because absent is what every reader already treats as no.
fn apply_gates(client: &mut ClientModel, gates: &Gates) {
    use models::entities::attributes::AttributeValue;

    let mut bag = client.configs.clone().unwrap_or_default();
    let mut said = |key: &str, on: bool| {
        if on {
            bag.insert(key.to_owned(), AttributeValue::Str("true".to_owned()));
        } else {
            bag.remove(key);
        }
    };
    if let Some(on) = gates.device {
        said(crate::device::GRANT_FLAG, on);
    }
    if let Some(on) = gates.token_exchange {
        said(crate::grant::EXCHANGE_FLAG, on);
    }
    if let Some(mode) = &gates.ciba {
        match mode {
            CibaOptIn::Off => {
                bag.remove(crate::ciba::DELIVERY_FLAG);
                bag.remove(crate::ciba::NOTIFICATION_ENDPOINT_FLAG);
            }
            CibaOptIn::Poll => {
                bag.insert(
                    crate::ciba::DELIVERY_FLAG.to_owned(),
                    AttributeValue::Str("poll".to_owned()),
                );
                bag.remove(crate::ciba::NOTIFICATION_ENDPOINT_FLAG);
            }
            CibaOptIn::Ping(endpoint) => {
                bag.insert(
                    crate::ciba::DELIVERY_FLAG.to_owned(),
                    AttributeValue::Str("ping".to_owned()),
                );
                bag.insert(
                    crate::ciba::NOTIFICATION_ENDPOINT_FLAG.to_owned(),
                    AttributeValue::Str(endpoint.clone()),
                );
            }
        }
    }
    client.configs = Some(bag);
}

fn apply(client: &mut ClientModel, spec: &Spec) {
    if let Some(said) = &spec.description {
        client.description = said.clone();
    }
    apply_gates(client, &spec.gates);
    client.root_url = spec
        .root_url
        .clone()
        .filter(|held| !held.is_empty())
        .map(|held| held.trim_end_matches('/').to_owned());
    client.web_origins = (!spec.web_origins.is_empty()).then(|| spec.web_origins.clone());
    let registered = &spec.registered;
    client.response_types = registered.response_types.clone();
    client.jwks = registered.jwks.clone();
    client.jwks_uri = registered.jwks_uri.clone();
    client.id_token_signed_response_alg = registered.id_token_signed_response_alg;
    client.userinfo_signed_response_alg = registered.userinfo_signed_response_alg;
    client.request_object_signing_alg = registered.request_object_signing_alg;
    client.client_uri = registered.client_uri.clone();
    client.logo_uri = registered.logo_uri.clone();
    client.policy_uri = registered.policy_uri.clone();
    client.tos_uri = registered.tos_uri.clone();
    client.contacts = registered.contacts.clone();
    client.application_type = registered.application_type.clone();
    client.default_max_age = registered.default_max_age;
    client.default_acr_values = registered.default_acr_values.clone();
    client.initiate_login_uri = registered.initiate_login_uri.clone();
    client.require_pushed_authorization_requests = registered.require_pushed_authorization_requests;
    client.request_uris = registered.request_uris.clone();
    client.subject_type = registered.subject_type.clone();
    client.sector_identifier_uri = registered.sector_identifier_uri.clone();
    client.token_endpoint_auth_signing_alg = registered.token_endpoint_auth_signing_alg;
    client.id_token_encryption = registered.id_token_encryption;
    client.userinfo_encryption = registered.userinfo_encryption;
    client.request_object_encryption = registered.request_object_encryption;
    if let Some(required) = registered.consent_required {
        client.consent_required = Some(required);
    }
    if !registered.method.is_empty() {
        client.client_authenticator_type = Some(registered.method.clone());
    }
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
