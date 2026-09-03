use std::net::IpAddr;

use chrono::{DateTime, Utc};
use config::proxying::Peer;
use crypto::envelope::Envelope;
use crypto::password::migration::verify_and_plan;
use crypto::password::storage::StoredPassword;
use crypto::provider::{Argon2Params, CryptoProvider, SignAlg};
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use models::entities::client::{ClientModel, JweRegistration};
use models::entities::keys::{JweAlgorithm, JweEncryption};
use models::entities::realm::{ClientRegistration, RealmModel};
use secrecy::SecretBox;
use serde::Deserialize;
use serde_json::{Value, json};
use store::keyring::RealmKeyring;
use store::providers::clients;
use url::Url;

use crate::admin::clients::{self as admin_clients, Registered, Secret, Spec, Unregistrable};
use crate::response_type::ResponseType;

/// What a client this endpoint created is written down as having been created
/// by. The ceiling is counted over these and over nothing else, so a realm
/// filled from outside never stops an administrator writing clients down.
pub const REGISTRAR: &str = "registration";

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
    /// §2 again, and every one of them refused: this provider signs what it
    /// answers with and does not encrypt it.
    pub id_token_encrypted_response_alg: Option<String>,
    pub id_token_encrypted_response_enc: Option<String>,
    pub userinfo_encrypted_response_alg: Option<String>,
    pub userinfo_encrypted_response_enc: Option<String>,
    pub request_object_encryption_alg: Option<String>,
    pub request_object_encryption_enc: Option<String>,
    /// §2: whether `auth_time` is required in the identity token. Always there,
    /// so registering it changes nothing and refusing it would be untrue.
    pub require_auth_time: Option<bool>,
    pub id_token_signed_response_alg: Option<String>,
    pub userinfo_signed_response_alg: Option<String>,
    pub request_object_signing_alg: Option<String>,
    pub default_max_age: Option<i64>,
    pub default_acr_values: Option<Vec<String>>,
    pub initiate_login_uri: Option<String>,
    pub require_pushed_authorization_requests: Option<bool>,
    /// §6.2: where this client hosts request objects, and the only places this
    /// server will fetch one from.
    pub request_uris: Option<Vec<String>>,
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
    #[error("this realm registers no more clients")]
    TooMany,
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
    // Where the request was dialled from, as the proxying settled it. Absent
    // is a caller with no address, which no list of addresses holds.
    caller: Option<IpAddr>,
) -> Result<(), Refused> {
    if !trusts(&realm.registration_bounds.trusted_hosts, caller) {
        // Answered as a realm that registers nothing, so a caller that is not
        // on the list learns nothing about the one that is.
        return Err(Refused::Closed);
    }
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

/// Whether a caller is one of the hosts this realm registers from.
///
/// An empty list is every caller: what opens the endpoint at all is the realm's
/// policy, and a deployment that named no hosts asked for no host constraint.
/// An entry that does not parse holds nobody, so a typo narrows the list rather
/// than widening it.
fn trusts(hosts: &[String], caller: Option<IpAddr>) -> bool {
    if hosts.is_empty() {
        return true;
    }
    let Some(caller) = caller else {
        return false;
    };
    hosts
        .iter()
        .filter_map(|held| Peer::parse(held))
        .any(|peer| peer.holds(caller))
}

/// Register a client from what it said about itself.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one registration"
)]
pub async fn register(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    sealing: Option<(&RealmKeyring, &Envelope)>,
    tenant: &str,
    realm: &RealmModel,
    metadata: &Metadata,
    // What the sector document listed, when one was named and fetched.
    sector: Option<&[String]>,
    now: DateTime<Utc>,
) -> Result<Registration, Refused> {
    let mut spec = spec_of(metadata, now)?;
    check_sector(metadata, sector)?;
    // Vetted by nobody, so the person it asks for is the one who decides.
    if realm.registration_bounds.requires_consent {
        spec.registered.consent_required = Some(true);
    }
    if let Some(ceiling) = realm.registration_bounds.max_clients {
        // Held before the count, and released at commit: counting and then
        // creating without it lets two registrations one below the ceiling
        // both read a count that passes.
        clients::hold_registrations(transaction, &realm.realm_id)
            .await
            .map_err(|_| Refused::Unwritable)?;
        let held = clients::count_created_by(transaction, &realm.realm_id, REGISTRAR)
            .await
            .map_err(|_| Refused::Unwritable)?;
        if held >= i64::from(ceiling) {
            return Err(Refused::TooMany);
        }
    }
    let client_id = draw(provider, IDENTIFIER_BYTES)?;
    let (client, secret) = admin_clients::register(
        transaction,
        provider,
        tenant,
        &realm.realm_id,
        REGISTRAR,
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
        "subject_type": client.subject_type.clone().unwrap_or_else(|| "public".to_owned()),
        "id_token_signed_response_alg": alg_name(client.id_token_signed_response_alg).unwrap_or("RS256"),
    });
    let named = document.as_object_mut().expect("a json object");
    // §3.2: what was registered, given back as registered. A pair the client
    // named half of comes back whole, because the default it took is now what
    // this server will use.
    for (field, registration) in [
        ("id_token", client.id_token_encryption),
        ("userinfo", client.userinfo_encryption),
    ] {
        if let Some(registration) = registration {
            named.insert(
                format!("{field}_encrypted_response_alg"),
                Value::from(registration.alg.as_str()),
            );
            named.insert(
                format!("{field}_encrypted_response_enc"),
                Value::from(registration.enc.as_str()),
            );
        }
    }
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
        ("request_uris", client.request_uris.clone()),
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
    if let Some(pushes) = client.require_pushed_authorization_requests {
        named.insert(
            "require_pushed_authorization_requests".to_owned(),
            Value::from(pushes),
        );
    }
    // Always true, because `auth_time` is always there. Stated rather than
    // omitted: absent is read as false, which would be untrue.
    named.insert("require_auth_time".to_owned(), Value::from(true));
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

/// A registered encryption pair, OpenID Connect Registration §2.
///
/// An `alg` with no `enc` takes the specified default. An `enc` with no `alg`
/// is refused: it names how to encrypt and not what to encrypt to, which is
/// half of an instruction and would otherwise be read as none at all.
fn read_encryption(
    alg: Option<&str>,
    enc: Option<&str>,
) -> Result<Option<JweRegistration>, Refused> {
    let Some(alg) = alg else {
        return match enc {
            None => Ok(None),
            Some(_) => Err(Refused::Invalid(
                "an encryption method with no algorithm names nothing to encrypt to",
            )),
        };
    };
    let alg = alg
        .parse::<JweAlgorithm>()
        .map_err(|_| Refused::Invalid("an encryption algorithm §2 does not name"))?;
    let enc = enc
        .map(|named| {
            named
                .parse::<JweEncryption>()
                .map_err(|_| Refused::Invalid("an encryption method §2 does not name"))
        })
        .transpose()?;
    Ok(Some(JweRegistration::new(alg, enc)))
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

/// §5: every redirect this client registered appears in the document its
/// sector identifier names, or the client is claiming a sector it does not
/// belong to and would be told another client's identifiers.
fn check_sector(metadata: &Metadata, listed: Option<&[String]>) -> Result<(), Refused> {
    if metadata.sector_identifier_uri.is_none() {
        return Ok(());
    }
    let listed = listed.ok_or(Refused::Invalid(
        "the sector identifier document could not be read",
    ))?;
    metadata
        .redirect_uris
        .iter()
        .all(|held| listed.iter().any(|named| named == held))
        .then_some(())
        .ok_or(Refused::Invalid(
            "a redirect is not in the sector identifier document",
        ))
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
    // The request object travels the other way: this server decrypts it, with
    // a key it published for the purpose.
    let request_object_encryption = read_encryption(
        metadata.request_object_encryption_alg.as_deref(),
        metadata.request_object_encryption_enc.as_deref(),
    )?;
    // Encryption wraps a signature or it wraps nothing. An object this server
    // decrypts and cannot then verify is one anybody could have sent, since
    // the key it was encrypted to is published for that.
    if request_object_encryption.is_some() && metadata.request_object_signing_alg.is_none() {
        return Err(Refused::Invalid(
            "an encrypted request object with no signature is one anybody may send",
        ));
    }
    let id_token_encryption = read_encryption(
        metadata.id_token_encrypted_response_alg.as_deref(),
        metadata.id_token_encrypted_response_enc.as_deref(),
    )?;
    let userinfo_encryption = read_encryption(
        metadata.userinfo_encrypted_response_alg.as_deref(),
        metadata.userinfo_encrypted_response_enc.as_deref(),
    )?;

    let subject_type = match metadata.subject_type.as_deref() {
        None | Some("public") => "public",
        Some("pairwise") => "pairwise",
        Some(_) => return Err(Refused::Invalid("a subject type §8 does not name")),
    };
    // §5 for the sector document, which is fetched and read; OIDC Core §4 for
    // where a third party sends a person to have this client start a login.
    // Both are named as https or not at all.
    for (named, what) in [
        (
            metadata.sector_identifier_uri.as_deref(),
            "a sector identifier is fetched over https",
        ),
        (
            metadata.initiate_login_uri.as_deref(),
            "a login is initiated over https",
        ),
    ] {
        if named.is_some_and(|held| !held.starts_with("https://")) {
            return Err(Refused::Invalid(what));
        }
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
        root_url: None,
        web_origins: Vec::new(),
        name: metadata.client_name.clone(),
        confidential,
        redirect_uris: metadata.redirect_uris.clone(),
        post_logout_redirect_uris: metadata.post_logout_redirect_uris.clone(),
        backchannel_logout_uri: metadata.backchannel_logout_uri.clone(),
        frontchannel_logout_uri: metadata.frontchannel_logout_uri.clone(),
        registered: Registered {
            consent_required: None,
            id_token_encryption,
            userinfo_encryption,
            request_object_encryption,
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
            require_pushed_authorization_requests: metadata.require_pushed_authorization_requests,
            request_uris: metadata.request_uris.clone(),
            subject_type: Some(subject_type.to_owned()),
            sector_identifier_uri: metadata.sector_identifier_uri.clone(),
            method: method.to_owned(),
            token_endpoint_auth_signing_alg: read_alg(
                metadata.token_endpoint_auth_signing_alg.as_ref(),
            )?,
            at: Some(now),
        },
        // A registration says nothing about the description an operator wrote,
        // and RFC 7592 replaces only what it names: the note and the grants an
        // operator turned on are not the client's to clear by re-registering.
        description: None,
        gates: crate::admin::clients::Gates::default(),
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

/// Draw the secret protected registration is opened with, and hand it back
/// once. Only the hash is kept, so losing the answer means drawing again.
pub async fn rotate_registration_secret(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm_id: &str,
) -> Result<String, Refused> {
    let mut realm = store::providers::realms::load(transaction, realm_id)
        .await
        .map_err(|_| Refused::Unwritable)?
        .ok_or(Refused::Closed)?;
    let mut drawn = [0u8; 32];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Refused::Unwritable)?;
    let secret = data_encoding::BASE64URL_NOPAD.encode(&drawn);
    realm.registration_secret = Some(hashed(provider, &secret)?);
    store::providers::realms::update(transaction, &realm)
        .await
        .map_err(|_| Refused::Unwritable)?;
    Ok(secret)
}

/// Take the secret away. Protected registration then admits nobody until a
/// new one is drawn, which is the safe direction to fail in.
pub async fn forget_registration_secret(
    transaction: &Transaction<'_>,
    realm_id: &str,
) -> Result<(), Refused> {
    let mut realm = store::providers::realms::load(transaction, realm_id)
        .await
        .map_err(|_| Refused::Unwritable)?
        .ok_or(Refused::Closed)?;
    realm.registration_secret = None;
    store::providers::realms::update(transaction, &realm)
        .await
        .map_err(|_| Refused::Unwritable)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listed(hosts: &[&str]) -> Vec<String> {
        hosts.iter().map(|held| (*held).to_owned()).collect()
    }

    fn at(address: &str) -> Option<IpAddr> {
        Some(address.parse().expect("an address"))
    }

    #[test]
    fn naming_no_host_admits_every_caller() {
        assert!(trusts(&[], at("203.0.113.7")));
        assert!(trusts(&[], None));
    }

    #[test]
    fn a_caller_with_no_address_is_held_by_no_list() {
        assert!(!trusts(&listed(&["0.0.0.0/0"]), None));
    }

    #[test]
    fn a_prefix_holds_what_is_inside_it_and_nothing_else() {
        let hosts = listed(&["10.0.0.0/8", "192.0.2.5"]);
        assert!(trusts(&hosts, at("10.9.9.9")));
        assert!(trusts(&hosts, at("192.0.2.5")));
        assert!(!trusts(&hosts, at("192.0.2.6")));
        assert!(!trusts(&hosts, at("11.0.0.1")));
    }

    /// A list of one family never holds the other, whatever the prefix says.
    #[test]
    fn a_prefix_of_one_family_holds_none_of_the_other() {
        assert!(!trusts(&listed(&["0.0.0.0/0"]), at("::1")));
        assert!(!trusts(&listed(&["::/0"]), at("203.0.113.7")));
    }

    /// A typo narrows the list. The alternative is an entry nobody reads
    /// widening it to everybody.
    #[test]
    fn an_entry_that_does_not_parse_holds_nobody() {
        assert!(!trusts(&listed(&["not-an-address"]), at("203.0.113.7")));
        assert!(trusts(
            &listed(&["not-an-address", "203.0.113.7"]),
            at("203.0.113.7")
        ));
    }
}
