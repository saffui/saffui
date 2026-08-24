//! A client registering itself. RFC 7591, RFC 7592, and OpenID Connect
//! Dynamic Client Registration 1.0.

use chrono::{DateTime, Utc};
use crypto::envelope::Envelope;
use crypto::password::migration::verify_and_plan;
use crypto::password::storage::StoredPassword;
use crypto::provider::{Argon2Params, CryptoProvider, SignAlg};
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use models::entities::client::ClientModel;
use models::entities::realm::{ClientRegistration, RealmModel};
use secrecy::SecretBox;
use serde::Deserialize;
use serde_json::{Value, json};
use store::keyring::RealmKeyring;
use store::providers::clients;
use url::Url;

use crate::admin::clients::{self as admin_clients, Registered, Secret, Spec, Unregistrable};
use crate::response_type::ResponseType;

/// How long a drawn identifier is, in bytes of randomness.
const IDENTIFIER_BYTES: usize = 16;
const CREDENTIAL_BYTES: usize = 32;

/// The client metadata a registration carries. Every member is optional;
/// §2 gives each one a default.
#[derive(Debug, Default, Deserialize)]
pub struct Metadata {
    /// Only ever read on an amendment, RFC 7592 §2.2, where it must name the
    /// client being amended.
    pub client_id: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    pub application_type: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub jwks_uri: Option<String>,
    pub jwks: Option<Value>,
    pub sector_identifier_uri: Option<String>,
    pub subject_type: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub token_endpoint_auth_signing_alg: Option<String>,
    pub id_token_signed_response_alg: Option<String>,
    pub userinfo_signed_response_alg: Option<String>,
    pub request_object_signing_alg: Option<String>,
    pub default_max_age: Option<i64>,
    pub default_acr_values: Option<Vec<String>>,
    pub initiate_login_uri: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    pub backchannel_logout_uri: Option<String>,
    pub frontchannel_logout_uri: Option<String>,
    pub scope: Option<String>,
}

/// What a registration hands back. The two credentials exist in the clear
/// exactly here.
pub struct Registration {
    pub client: ClientModel,
    pub secret: Option<String>,
    pub access_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("this realm registers no clients")]
    Closed,
    #[error("the initial access token is missing or wrong")]
    Unauthorized,
    #[error("no such client")]
    Unknown,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("the store could not be written")]
    Unwritable,
}

impl From<Unregistrable> for Refused {
    fn from(why: Unregistrable) -> Self {
        match why {
            Unregistrable::NotFound => Refused::Unknown,
            Unregistrable::Invalid(what) => Refused::Invalid(what),
            Unregistrable::AlreadyExists | Unregistrable::Unwritable => Refused::Unwritable,
        }
    }
}

/// Whether this realm answers a registration at all, and whether this caller
/// may have one.
pub fn admits(
    realm: &RealmModel,
    provider: &dyn CryptoProvider,
    presented: Option<&str>,
) -> Result<(), Refused> {
    match realm.client_registration {
        ClientRegistration::Disabled => Err(Refused::Closed),
        ClientRegistration::Open => Ok(()),
        ClientRegistration::Protected => {
            let held = realm
                .registration_secret
                .as_deref()
                .ok_or(Refused::Closed)?;
            let presented = presented.ok_or(Refused::Unauthorized)?;
            matches(provider, held, presented)
                .then_some(())
                .ok_or(Refused::Unauthorized)
        }
    }
}

/// Register a client from what it said about itself.
pub async fn register(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    sealing: Option<(&RealmKeyring, &Envelope)>,
    tenant: &str,
    realm_id: &str,
    metadata: &Metadata,
    now: DateTime<Utc>,
) -> Result<Registration, Refused> {
    let spec = spec_of(metadata, now)?;
    let client_id = draw(provider, IDENTIFIER_BYTES)?;
    let (client, secret) = admin_clients::register(
        transaction,
        provider,
        tenant,
        realm_id,
        "registration",
        &client_id,
        &spec,
        Secret::Drawn,
    )
    .await?;

    // `client_secret_jwt` recomputes an HMAC over the secret, so this
    // deployment has to be able to read it back. Sealed rather than hashed,
    // and the hash the registration just wrote is cleared with it.
    if spec.registered.method == "client-secret-jwt" {
        let held = secret.as_deref().ok_or(Refused::Unwritable)?;
        let (ring, envelope) = sealing.ok_or(Refused::Unwritable)?;
        let sealed = ring
            .seal(
                envelope,
                crate::client::SECRET_SCOPE,
                &client_id,
                held.as_bytes(),
            )
            .await
            .map_err(|_| Refused::Unwritable)?;
        let version = i32::try_from(ring.active_version()).map_err(|_| Refused::Unwritable)?;
        clients::seal_secret(transaction, &client_id, &sealed, version, None)
            .await
            .map_err(|_| Refused::Unwritable)?;
    }

    let access_token = draw(provider, CREDENTIAL_BYTES)?;
    keep_access_token(transaction, provider, &client_id, &access_token).await?;
    Ok(Registration {
        client,
        secret,
        access_token,
    })
}

/// The client this registration access token stands for.
pub async fn holder_of(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    client_id: &str,
    presented: Option<&str>,
) -> Result<ClientModel, Refused> {
    let presented = presented.ok_or(Refused::Unauthorized)?;
    let client = clients::load(transaction, client_id)
        .await
        .map_err(|_| Refused::Unwritable)?;
    let held = clients::load_registration_token(transaction, client_id)
        .await
        .map_err(|_| Refused::Unwritable)?;
    // Unauthorized whatever is missing, and the same work done either way:
    // answering an unknown identifier without paying the verification is how
    // a caller learns which identifiers exist.
    let Some((client, held)) = client.zip(held) else {
        let _ = hashed(provider, presented);
        return Err(Refused::Unauthorized);
    };
    if !matches(provider, &held, presented) {
        return Err(Refused::Unauthorized);
    }
    Ok(client)
}

/// Replace everything this client registered with what it now says, §2.2 of
/// RFC 7592: the request is the whole metadata, and what it omits is cleared.
pub async fn amend(
    transaction: &Transaction<'_>,
    client: &ClientModel,
    metadata: &Metadata,
) -> Result<ClientModel, Refused> {
    let mut spec = spec_of(metadata, client.registered_at.unwrap_or_else(Utc::now))?;
    spec.confidential = client.public_client != Some(true);
    let amended = admin_clients::reshape_registered(transaction, &client.client_id, &spec).await?;
    Ok(amended)
}

pub async fn withdraw(transaction: &Transaction<'_>, client_id: &str) -> Result<(), Refused> {
    admin_clients::remove(transaction, client_id).await?;
    Ok(())
}

/// The registration response, §3.2.1: every value that was registered.
pub fn as_document(client: &ClientModel, issued_at: i64) -> Value {
    let mut document = json!({
        "client_id": client.client_id,
        "client_id_issued_at": issued_at,
        "redirect_uris": client.redirect_uris.clone().unwrap_or_default(),
        "response_types": client.response_types.clone().unwrap_or_else(|| vec!["code".to_owned()]),
        "grant_types": grant_types_of(client),
        "token_endpoint_auth_method": auth_method_of(client),
        "application_type": client.application_type.clone().unwrap_or_else(|| "web".to_owned()),
        "subject_type": "public",
        "id_token_signed_response_alg": alg_name(client.id_token_signed_response_alg).unwrap_or("RS256"),
    });
    let named = document.as_object_mut().expect("a json object");
    for (key, value) in [
        ("client_name", client.name.clone()),
        ("client_uri", client.client_uri.clone().unwrap_or_default()),
        ("logo_uri", client.logo_uri.clone().unwrap_or_default()),
        ("policy_uri", client.policy_uri.clone().unwrap_or_default()),
        ("tos_uri", client.tos_uri.clone().unwrap_or_default()),
        ("jwks_uri", client.jwks_uri.clone().unwrap_or_default()),
        (
            "initiate_login_uri",
            client.initiate_login_uri.clone().unwrap_or_default(),
        ),
        (
            "backchannel_logout_uri",
            client.backchannel_logout_uri.clone().unwrap_or_default(),
        ),
        (
            "frontchannel_logout_uri",
            client.frontchannel_logout_uri.clone().unwrap_or_default(),
        ),
    ] {
        if !value.is_empty() {
            named.insert(key.to_owned(), Value::from(value));
        }
    }
    for (key, value) in [
        ("contacts", client.contacts.clone()),
        ("default_acr_values", client.default_acr_values.clone()),
        (
            "post_logout_redirect_uris",
            client.post_logout_redirect_uris.clone(),
        ),
    ] {
        if let Some(value) = value.filter(|held| !held.is_empty()) {
            named.insert(key.to_owned(), Value::from(value));
        }
    }
    if let Some(jwks) = &client.jwks {
        named.insert("jwks".to_owned(), jwks.clone());
    }
    if let Some(age) = client.default_max_age {
        named.insert("default_max_age".to_owned(), Value::from(age));
    }
    for (key, alg) in [
        (
            "userinfo_signed_response_alg",
            client.userinfo_signed_response_alg,
        ),
        (
            "request_object_signing_alg",
            client.request_object_signing_alg,
        ),
    ] {
        if let Some(named_alg) = alg_name(alg) {
            named.insert(key.to_owned(), Value::from(named_alg));
        }
    }
    document
}

fn grant_types_of(client: &ClientModel) -> Vec<&'static str> {
    let mut held = Vec::new();
    if client.standard_flow_enabled == Some(true) {
        held.push("authorization_code");
        held.push("refresh_token");
    }
    if client.implicit_flow_enabled == Some(true) {
        held.push("implicit");
    }
    held
}

fn auth_method_of(client: &ClientModel) -> &'static str {
    method_named(
        client
            .client_authenticator_type
            .as_deref()
            .unwrap_or("client-secret"),
    )
}

fn alg_name(alg: Option<SignAlg>) -> Option<&'static str> {
    Some(match alg? {
        SignAlg::Rs256 => "RS256",
        SignAlg::Rs384 => "RS384",
        SignAlg::Rs512 => "RS512",
        SignAlg::Ps256 => "PS256",
        SignAlg::Ps384 => "PS384",
        SignAlg::Ps512 => "PS512",
        SignAlg::Es256 => "ES256",
        SignAlg::Es384 => "ES384",
        SignAlg::Es512 => "ES512",
        SignAlg::EdDsa => "EdDSA",
    })
}

fn read_alg(named: Option<&String>) -> Result<Option<SignAlg>, Refused> {
    let Some(named) = named else {
        return Ok(None);
    };
    // `none` is refused rather than accepted: this provider does not mint
    // unsigned tokens, and registering one would fail at the first issuance.
    SignAlg::ALL
        .iter()
        .find(|alg| alg_name(Some(**alg)) == Some(named.as_str()))
        .copied()
        .map(Some)
        .ok_or(Refused::Invalid(
            "an algorithm this provider does not sign with",
        ))
}

/// §9's names, as the column spells them. A method not named here is refused
/// rather than answered with a secret, which would be a downgrade.
fn read_method(named: Option<&str>) -> Result<&'static str, Refused> {
    Ok(match named.unwrap_or("client_secret_basic") {
        "client_secret_basic" | "client_secret_post" => "client-secret",
        "none" => "none",
        "client_secret_jwt" => "client-secret-jwt",
        "private_key_jwt" => "private-key-jwt",
        _ => {
            return Err(Refused::Invalid(
                "an authentication method this endpoint does not accept",
            ));
        }
    })
}

/// The wire spelling, for the registration response.
fn method_named(held: &str) -> &'static str {
    match held {
        "none" => "none",
        "client-secret-jwt" => "client_secret_jwt",
        "private-key-jwt" => "private_key_jwt",
        _ => "client_secret_basic",
    }
}

/// §2 of the registration spec, mapped onto what this provider can honour.
fn spec_of(metadata: &Metadata, now: DateTime<Utc>) -> Result<Spec, Refused> {
    if metadata.sector_identifier_uri.is_some()
        || metadata
            .subject_type
            .as_deref()
            .is_some_and(|named| named != "public")
    {
        return Err(Refused::Invalid("only the public subject type is issued"));
    }
    if metadata.jwks.is_some() && metadata.jwks_uri.is_some() {
        return Err(Refused::Invalid("keys are published one way, not two"));
    }
    let method = read_method(metadata.token_endpoint_auth_method.as_deref())?;
    // §9: a client signing its own assertions has to publish the keys they are
    // verified against, and one registering none could never authenticate.
    if method == "private-key-jwt" && metadata.jwks.is_none() && metadata.jwks_uri.is_none() {
        return Err(Refused::Invalid(
            "signing assertions with a key needs the keys published",
        ));
    }

    let asked = response_types_of(metadata)?;
    let confidential = method != "none";
    let application_type = match metadata.application_type.as_deref() {
        None | Some("web") => "web",
        Some("native") => "native",
        Some(_) => return Err(Refused::Invalid("an application type §2 does not name")),
    };
    check_places(
        metadata,
        application_type,
        asked.iter().any(|held| held.mints_here()),
    )?;

    Ok(Spec {
        name: metadata.client_name.clone(),
        confidential,
        redirect_uris: metadata.redirect_uris.clone(),
        post_logout_redirect_uris: metadata.post_logout_redirect_uris.clone(),
        backchannel_logout_uri: metadata.backchannel_logout_uri.clone(),
        frontchannel_logout_uri: metadata.frontchannel_logout_uri.clone(),
        registered: Registered {
            response_types: Some(named_response_types(metadata)),
            implicit: asked.iter().any(|held| held.mints_here()),
            jwks: metadata.jwks.clone(),
            jwks_uri: metadata.jwks_uri.clone(),
            id_token_signed_response_alg: read_alg(metadata.id_token_signed_response_alg.as_ref())?,
            userinfo_signed_response_alg: read_alg(metadata.userinfo_signed_response_alg.as_ref())?,
            request_object_signing_alg: read_alg(metadata.request_object_signing_alg.as_ref())?,
            client_uri: metadata.client_uri.clone(),
            logo_uri: metadata.logo_uri.clone(),
            policy_uri: metadata.policy_uri.clone(),
            tos_uri: metadata.tos_uri.clone(),
            contacts: metadata.contacts.clone(),
            application_type: Some(application_type.to_owned()),
            default_max_age: metadata
                .default_max_age
                .map(|age| i32::try_from(age).unwrap_or(i32::MAX)),
            default_acr_values: metadata.default_acr_values.clone(),
            initiate_login_uri: metadata.initiate_login_uri.clone(),
            method: method.to_owned(),
            token_endpoint_auth_signing_alg: read_alg(
                metadata.token_endpoint_auth_signing_alg.as_ref(),
            )?,
            at: Some(now),
        },
    })
}

fn named_response_types(metadata: &Metadata) -> Vec<String> {
    if metadata.response_types.is_empty() {
        vec!["code".to_owned()]
    } else {
        metadata.response_types.clone()
    }
}

/// Each named set, read through the same reader the authorization endpoint
/// uses: a set registered here that could never be asked for is not one.
fn response_types_of(metadata: &Metadata) -> Result<Vec<ResponseType>, Refused> {
    let named = named_response_types(metadata);
    let mut asked = Vec::with_capacity(named.len());
    for value in &named {
        let read = ResponseType::read(value)
            .filter(|held| !held.as_str().is_empty())
            .ok_or(Refused::Invalid(
                "a response type this provider does not answer",
            ))?;
        asked.push(read);
    }
    // §2: the two lists say the same thing twice, and disagreeing is an error
    // rather than a preference to reconcile.
    for named in &metadata.grant_types {
        let consistent = match named.as_str() {
            "authorization_code" => asked.iter().any(|held| held.code),
            "implicit" => asked.iter().any(|held| held.mints_here()),
            "refresh_token" => asked.iter().any(|held| held.code),
            _ => {
                return Err(Refused::Invalid(
                    "a grant type this provider does not honour",
                ));
            }
        };
        if !consistent {
            return Err(Refused::Invalid(
                "the grant types and the response types disagree",
            ));
        }
    }
    Ok(asked)
}

/// §2: a web client using the implicit flow redirects over https and never to
/// localhost, and every place a browser is sent is absolute and unfragmented.
fn check_places(metadata: &Metadata, application_type: &str, mints: bool) -> Result<(), Refused> {
    for uri in &metadata.redirect_uris {
        let parsed = Url::parse(uri).map_err(|_| Refused::Invalid("a redirect is not absolute"))?;
        if parsed.fragment().is_some() {
            return Err(Refused::Invalid("a redirect carries a fragment"));
        }
        if application_type == "web" && mints {
            let localhost = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
            if parsed.scheme() != "https" || localhost {
                return Err(Refused::Invalid(
                    "a web client minting at the authorization endpoint redirects over https",
                ));
            }
        }
    }
    Ok(())
}

fn draw(provider: &dyn CryptoProvider, bytes: usize) -> Result<String, Refused> {
    let mut drawn = vec![0u8; bytes];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Refused::Unwritable)?;
    Ok(BASE64URL_NOPAD.encode(&drawn))
}

async fn keep_access_token(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    client_id: &str,
    token: &str,
) -> Result<(), Refused> {
    let encoded = hashed(provider, token)?;
    clients::rotate_registration_token(transaction, client_id, &encoded)
        .await
        .map_err(|_| Refused::Unwritable)?;
    Ok(())
}

pub fn hashed(provider: &dyn CryptoProvider, token: &str) -> Result<String, Refused> {
    let StoredPassword::Argon2id { encoded } = StoredPassword::hash_argon2id(
        provider,
        Argon2Params::default(),
        &SecretBox::new(Box::new(token.to_owned())),
    )
    .map_err(|_| Refused::Unwritable)?
    else {
        return Err(Refused::Unwritable);
    };
    Ok(encoded)
}

fn matches(provider: &dyn CryptoProvider, held: &str, presented: &str) -> bool {
    let Ok(stored) = (StoredPassword::Argon2id {
        encoded: held.to_owned(),
    })
    .to_legacy_hash() else {
        return false;
    };
    let offered = SecretBox::new(Box::new(presented.to_owned()));
    verify_and_plan(provider, &offered, &stored).is_ok_and(|plan| plan.valid)
}
