use chrono::{DateTime, Utc};
use crypto::jose::jwk::KeyPair;
use crypto::jose::jwk::alg::rsa::RsaKeyPair;
use crypto::provider::{CryptoProvider, PrivateKey, PublicKey, SignAlg};
use crypto::x509::{
    CertifiedKey, Issuance, issue_certificate, public_key_of, read_certificate_facts,
};
use data_encoding::HEXLOWER;
use deadpool_postgres::Transaction;
use models::entities::attributes::AttributesMap;
use models::entities::authz::IdentityProviderModel;
use models::entities::brokering::{SamlBrokerSession, SamlLoginRequest};
use models::entities::keys::{JweAlgorithm, KeyUse, RealmEncryptionKey, RealmSigningKey};
use saml::authn::{AuthnRequest, write_authn_request};
use saml::logout::{
    Delivered, ExpectedLogout, LogoutResponse, RefusedLogout, accept_logout_request,
    write_logout_response,
};
use saml::metadata::{
    Endpoint, IdentityProvider, Misread, ServiceProvider, describe_service_provider,
    read_identity_provider,
};
use saml::post::decode_posted_message;
use saml::redirect::{Carried, decode_query, encode_query};
use saml::response::{Accepted, Expected, Refused, accept_response, read_answered_request_id};
use saml::xml::{Limits, read_message};
use serde_json::{Map, Value};
use store::providers::{realm_keys, replay};

use crate::brokering::{Arrival, STATE_LIFESPAN, Unbrokered, text};
use crate::grant::Signing;

const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const MINIMUM_RSA_BITS: u32 = 2048;
/// Core §8.3.6 bounds an entity identifier to 1024 characters.
const ENTITY_ID_MAX_CHARS: usize = 1024;

/// Whether a provider's configuration names SAML as its protocol.
pub fn is_saml(provider: &IdentityProviderModel) -> bool {
    provider
        .configs
        .as_ref()
        .and_then(|bag| text(bag, "protocol"))
        == Some("saml")
}

/// A SAML identity provider as a realm brokers it, read from what an administrator
/// saved.
#[derive(Debug, Clone)]
pub struct SamlUpstream {
    pub identity_provider: IdentityProvider,
    /// Persistent unless the administrator asked for another format.
    pub name_id_format: String,
    /// The attribute naming the person when the name identifier is not persistent.
    pub principal_attribute: Option<String>,
    pub username_attribute: Option<String>,
    pub email_attribute: Option<String>,
    /// The entity identifier the realm answers to here, when an administrator
    /// overrode the one its alias gives, as a migration needs.
    pub sp_entity_id: Option<String>,
}

/// Why a SAML provider's configuration cannot be used, each naming what failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnusableSaml {
    #[error("the provider names no {0}")]
    Missing(&'static str),
    #[error("the identity provider's metadata cannot be used: {0}")]
    Metadata(Misread),
    #[error("the identity provider's {0} is not an https address")]
    Insecure(&'static str),
    #[error("a signing key of the identity provider is too weak to trust: {0}")]
    WeakKey(&'static str),
    #[error(
        "a name identifier format other than persistent needs principal_attribute, since such a name can be given to someone else"
    )]
    NoPrincipal,
    #[error(
        "principal_attribute names the email attribute, and an address can be given to someone else"
    )]
    EmailAsPrincipal,
    #[error("{0} is not an entity identifier")]
    NotAnEntity(&'static str),
}

impl SamlUpstream {
    /// Read the stored bag the way a login will read it, refusing at the door what
    /// cannot be used: metadata that does not read, an address in clear off this
    /// machine, a signing key too weak to trust, or a name that can be given to
    /// someone else with nothing steadier beside it.
    pub fn parse(provider: &IdentityProviderModel) -> Result<Self, UnusableSaml> {
        let empty = AttributesMap::new();
        let bag = provider.configs.as_ref().unwrap_or(&empty);
        let metadata = text(bag, "idp_metadata").ok_or(UnusableSaml::Missing("idp_metadata"))?;
        let identity_provider =
            read_identity_provider(metadata, Limits::MESSAGE).map_err(UnusableSaml::Metadata)?;

        if !commons::address::is_https_or_loopback(&identity_provider.single_sign_on) {
            return Err(UnusableSaml::Insecure("single sign-on address"));
        }
        if let Some(logout) = &identity_provider.single_logout
            && (!commons::address::is_https_or_loopback(&logout.location)
                || logout
                    .response_location
                    .as_deref()
                    .is_some_and(|held| !commons::address::is_https_or_loopback(held)))
        {
            return Err(UnusableSaml::Insecure("single logout address"));
        }

        for certificate in &identity_provider.signing_certificates {
            let facts = read_certificate_facts(certificate)
                .ok_or(UnusableSaml::WeakKey("a certificate that does not read"))?;
            let weakness = match facts.key {
                CertifiedKey::Rsa { bits } if bits < MINIMUM_RSA_BITS => {
                    Some("RSA below 2048 bits")
                }
                CertifiedKey::Rsa { .. } => None,
                CertifiedKey::Ec { curve } => curve
                    .is_none()
                    .then_some("a curve other than P-256, P-384 or P-521"),
                CertifiedKey::Other => Some("a key of a kind not verified here"),
            };
            if let Some(weakness) = weakness {
                return Err(UnusableSaml::WeakKey(weakness));
            }
        }

        let name_id_format = text(bag, "name_id_format")
            .filter(|format| !format.is_empty())
            .unwrap_or(PERSISTENT)
            .to_owned();
        let principal_attribute = read_given(bag, "principal_attribute");
        let email_attribute = read_given(bag, "email_attribute");
        if name_id_format != PERSISTENT && principal_attribute.is_none() {
            return Err(UnusableSaml::NoPrincipal);
        }
        if principal_attribute.is_some() && principal_attribute == email_attribute {
            return Err(UnusableSaml::EmailAsPrincipal);
        }
        let sp_entity_id = read_given(bag, "sp_entity_id");
        if sp_entity_id.as_deref().is_some_and(|entity| {
            entity.trim() != entity || entity.chars().count() > ENTITY_ID_MAX_CHARS
        }) {
            return Err(UnusableSaml::NotAnEntity("sp_entity_id"));
        }

        Ok(Self {
            identity_provider,
            name_id_format,
            principal_attribute,
            username_attribute: read_given(bag, "username_attribute"),
            email_attribute,
            sp_entity_id,
        })
    }
}

/// A value the administrator gave, when they gave one: empty is none.
fn read_given(bag: &AttributesMap, key: &str) -> Option<String> {
    text(bag, key)
        .filter(|given| !given.is_empty())
        .map(str::to_owned)
}

/// RFC 5280 §4.1.2.5: the instant a certificate with no well-defined end carries.
const NO_WELL_DEFINED_END: i64 = 253_402_300_799;
/// The realm encryption keys a SAML provider can encrypt to, in the order offered.
const RSA_ENCRYPTION: [JweAlgorithm; 4] = [
    JweAlgorithm::RsaOaep256,
    JweAlgorithm::RsaOaep,
    JweAlgorithm::RsaOaep384,
    JweAlgorithm::RsaOaep512,
];

/// Why a realm could not describe itself to a SAML provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Undescribed {
    #[error("the realm holds no active RSA key to sign with")]
    NoSigningKey,
    #[error("a realm key could not be read as RSA")]
    UnreadableKey,
    #[error("a certificate could not be issued for a realm key")]
    Unissued,
    #[error("the store could not be read")]
    Backend,
}

/// Where a realm takes one SAML provider's messages: the base of its metadata,
/// assertion consumer and logout addresses, under the realm's issuer.
pub fn compose_saml_address(issuer: &str, alias: &str) -> String {
    format!("{issuer}/broker/{alias}/saml")
}

/// The realm keys a SAML provider is shown: the active RSA key the realm signs
/// with, and an active RSA key assertions may be encrypted to when it holds one.
pub async fn load_published_keys(
    transaction: &Transaction<'_>,
    signing: &Signing<'_>,
) -> Result<(RealmSigningKey, Option<RealmEncryptionKey>), Undescribed> {
    let signing_key = load_signing_key(transaction, signing).await?;
    for algorithm in RSA_ENCRYPTION {
        let found =
            realm_keys::active_encryption(transaction, signing.ring, signing.envelope, algorithm)
                .await
                .map_err(|_| Undescribed::Backend)?;
        if found.is_some() {
            return Ok((signing_key, found));
        }
    }
    Ok((signing_key, None))
}

/// The realm's metadata as this provider's service provider: the entity identifier
/// it answers to, where responses and logout come, and a certificate for each of
/// its keys issued under its signing key. The same keys give the same bytes, so
/// nothing is stored and a provider that imported them keeps finding them.
pub fn describe_realm(
    upstream: &SamlUpstream,
    issuer: &str,
    alias: &str,
    realm_id: &str,
    signing_key: &RealmSigningKey,
    encryption_key: Option<&RealmEncryptionKey>,
) -> Result<String, Undescribed> {
    let signer =
        RsaKeyPair::from_pem(&signing_key.private_pem).map_err(|_| Undescribed::UnreadableKey)?;
    let signing_certificate = issue_key_certificate(
        &signer,
        &signer,
        realm_id,
        &signing_key.kid,
        signing_key.created_at,
    )?;
    let encryption_certificates = match encryption_key {
        Some(key) => {
            let sealed_to =
                RsaKeyPair::from_pem(&key.private_pem).map_err(|_| Undescribed::UnreadableKey)?;
            vec![issue_key_certificate(
                &sealed_to,
                &signer,
                realm_id,
                &key.kid,
                signing_key.created_at,
            )?]
        }
        None => Vec::new(),
    };
    let base = compose_saml_address(issuer, alias);
    let entity_id = resolve_entity_id(upstream, &base);
    Ok(describe_service_provider(&ServiceProvider {
        entity_id: &entity_id,
        assertion_consumer: &format!("{base}/acs"),
        single_logout: &format!("{base}/slo"),
        name_id_format: Some(upstream.name_id_format.as_str()),
        signing_certificates: &[signing_certificate],
        encryption_certificates: &encryption_certificates,
    }))
}

/// A certificate for the subject's key under the signer's, named for the realm, its
/// serial drawn from the key's thumbprint and its start the signing key's.
fn issue_key_certificate(
    subject: &RsaKeyPair,
    signer: &RsaKeyPair,
    realm_id: &str,
    kid: &str,
    not_before: i64,
) -> Result<Vec<u8>, Undescribed> {
    issue_certificate(&Issuance {
        subject_key: &PublicKey::from_der(subject.to_der_public_key()),
        subject_name: realm_id,
        issuer_key: &PrivateKey::from_der(signer.to_der_private_key()),
        issuer_name: realm_id,
        serial: &derive_serial(kid),
        not_before,
        not_after: NO_WELL_DEFINED_END,
    })
    .ok_or(Undescribed::Unissued)
}

/// Sixteen octets of a key's thumbprint, the top bit cleared and the next one set,
/// so the serial is positive, never zero and within the 20 octets RFC 5280 allows.
fn derive_serial(kid: &str) -> Vec<u8> {
    let mut serial = data_encoding::BASE64URL_NOPAD
        .decode(kid.as_bytes())
        .unwrap_or_else(|_| kid.as_bytes().to_vec());
    serial.resize(16, 0);
    serial[0] = (serial[0] & 0x7f) | 0x40;
    serial
}

/// What leaves for a SAML provider: where the browser goes, and the row that ties
/// the provider's answer to this departure.
pub struct SamlDeparture {
    pub location: String,
    pub request: SamlLoginRequest,
}

/// The realm's active RSA key, the one it signs what it sends SAML providers with.
pub async fn load_signing_key(
    transaction: &Transaction<'_>,
    signing: &Signing<'_>,
) -> Result<RealmSigningKey, Undescribed> {
    realm_keys::active(
        transaction,
        signing.ring,
        signing.envelope,
        KeyUse::Sig,
        Some(SignAlg::Rs256),
    )
    .await
    .map_err(|_| Undescribed::Backend)?
    .ok_or(Undescribed::NoSigningKey)
}

/// Send a login to a SAML provider: an authentication request under a fresh
/// identifier, issued by the realm's entity for this provider, asking for the name
/// format the provider was set up to give and for the answer at this provider's
/// consumer, on a Redirect query the realm's RSA key signs. The request row is what
/// the answer will be held to, and it lasts as long as a brokered login.
pub fn depart(
    provider: &dyn CryptoProvider,
    upstream: &SamlUpstream,
    issuer: &str,
    alias: &str,
    signing_key: &RealmSigningKey,
    auth_session: &str,
    now: DateTime<Utc>,
) -> Result<SamlDeparture, Unbrokered> {
    let request_id = draw_message_id(provider).ok_or(Unbrokered::Backend)?;
    let base = compose_saml_address(issuer, alias);
    let message = write_authn_request(&AuthnRequest {
        id: &request_id,
        issue_instant: now.timestamp(),
        destination: &upstream.identity_provider.single_sign_on,
        issuer: &resolve_entity_id(upstream, &base),
        assertion_consumer: &format!("{base}/acs"),
        name_id_format: Some(upstream.name_id_format.as_str()),
        force_authn: false,
    })
    .map_err(|_| Unbrokered::Backend)?;
    let location = sign_redirect(
        provider,
        signing_key,
        Carried::Request,
        &message,
        None,
        &upstream.identity_provider.single_sign_on,
    )
    .ok_or(Unbrokered::Backend)?;
    Ok(SamlDeparture {
        location,
        request: SamlLoginRequest {
            request_id,
            provider_alias: alias.to_owned(),
            auth_session: auth_session.to_owned(),
            expires_at: now + STATE_LIFESPAN,
        },
    })
}

/// The entity identifier the realm answers to for this provider: the one an
/// administrator set, or the address of its metadata.
fn resolve_entity_id(upstream: &SamlUpstream, base: &str) -> String {
    upstream
        .sp_entity_id
        .clone()
        .unwrap_or_else(|| format!("{base}/metadata"))
}

/// Who a SAML provider's accepted assertion names, read as a brokered login reads
/// an arrival. The person is the persistent name identifier when the provider was
/// set up for one, and then only a name in that format; otherwise the one value of
/// the attribute set to name them. A name that can be given to someone else is never
/// taken as the person. An address the provider gives counts as verified, so linking
/// by it rests on the provider being trusted for addresses.
pub fn arrive(upstream: &SamlUpstream, accepted: &Accepted) -> Result<Arrival, Unbrokered> {
    let mut gathered: Map<String, Value> = Map::new();
    for (name, values) in &accepted.attributes {
        if let Value::Array(listed) = gathered
            .entry(name.clone())
            .or_insert_with(|| Value::Array(Vec::new()))
        {
            listed.extend(values.iter().cloned().map(Value::String));
        }
    }
    let claims: Map<String, Value> = gathered
        .into_iter()
        .filter_map(|(name, value)| match value {
            Value::Array(mut listed) if listed.len() == 1 => listed.pop().map(|only| (name, only)),
            Value::Array(listed) if listed.is_empty() => None,
            other => Some((name, other)),
        })
        .collect();
    let single = |attribute: &Option<String>| {
        attribute
            .as_deref()
            .and_then(|name| claims.get(name))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };

    let external_user_id = if upstream.name_id_format == PERSISTENT {
        if accepted.name_id.format.as_deref() != Some(PERSISTENT) {
            return Err(Unbrokered::Refused);
        }
        accepted.name_id.value.clone()
    } else {
        single(&upstream.principal_attribute).ok_or(Unbrokered::Refused)?
    };
    let username = single(&upstream.username_attribute);
    let email = single(&upstream.email_attribute);
    Ok(Arrival {
        external_user_id,
        username,
        email_verified: email.is_some(),
        email,
        claims,
    })
}

/// The private keys a realm decrypts assertions with: every RSA encryption key it
/// still holds for use, a rotated one included, so an assertion encrypted to a key a
/// provider imported before the rotation still opens. A key that does not read as
/// RSA is left out.
pub fn read_decryption_keys(keys: &[RealmEncryptionKey]) -> Vec<PrivateKey> {
    keys.iter()
        .filter_map(|key| RsaKeyPair::from_pem(&key.private_pem).ok())
        .map(|pair| PrivateKey::from_der(pair.to_der_private_key()))
        .collect()
}

/// Clocks in two organisations drift further apart than clocks inside one.
const SKEW: i64 = 180;
/// Bindings §3.4.3 and §3.5.3 bound a relay state to 80 bytes.
const RELAY_STATE_MAX_BYTES: usize = 80;

/// Why a SAML provider's answer was not taken, each naming what failed for the
/// operator's log. The browser is told one thing whatever the variant, the store
/// failing aside.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Untaken {
    #[error("the answer is not a SAML response that reads")]
    Unreadable,
    #[error("the answer names no request still open for this provider")]
    NoOpenRequest,
    #[error("the answer came back to another browser than the one that left")]
    OtherBrowser,
    #[error("the response was refused: {0}")]
    Refused(Refused),
    #[error("the assertion was already taken")]
    Replayed,
    #[error("the assertion names nobody this provider may name")]
    Unnamed,
    #[error("the store could not be read or written")]
    Backend,
}

/// A SAML provider's answer once taken: the request it spent, what its verified
/// assertion says, and who that is as an arrival.
pub struct SamlAnswer {
    pub request: SamlLoginRequest,
    pub accepted: Accepted,
    pub arrival: Arrival,
}

/// Take a SAML provider's answer, posted back for the login a browser left open.
///
/// The request the answer names is spent, and only for the browser that left with
/// it: a refusal commits nothing, so the request stays with that browser. The
/// response is then held to that request, to the provider's entity and signing
/// keys, to the realm's entity for this provider and its consumer address, and
/// decrypted with every RSA key the realm still holds; its assertion is taken once,
/// and names the person only as `arrive` allows.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a piece of the answer the consumer already holds"
)]
pub async fn take_answer(
    transaction: &Transaction<'_>,
    signing: &Signing<'_>,
    upstream: &SamlUpstream,
    issuer: &str,
    alias: &str,
    posted: &str,
    auth_session: &str,
    now: DateTime<Utc>,
) -> Result<SamlAnswer, Untaken> {
    let message = decode_posted_message(posted).ok_or(Untaken::Unreadable)?;
    let document = read_message(&message, Limits::MESSAGE).map_err(|_| Untaken::Unreadable)?;
    let request_id = read_answered_request_id(&document).ok_or(Untaken::NoOpenRequest)?;
    let request = store::providers::saml_brokering::consume_login_request(
        transaction,
        request_id,
        alias,
        now,
    )
    .await
    .map_err(|_| Untaken::Backend)?
    .ok_or(Untaken::NoOpenRequest)?;
    if !crypto::constant_time::eq(request.auth_session.as_bytes(), auth_session.as_bytes()) {
        return Err(Untaken::OtherBrowser);
    }

    let trusted = read_trusted_keys(upstream);
    let held = realm_keys::load_usable_encryption_keys(transaction, signing.ring, signing.envelope)
        .await
        .map_err(|_| Untaken::Backend)?;
    let decryption_keys = read_decryption_keys(&held);
    let base = compose_saml_address(issuer, alias);
    let accepted = accept_response(
        signing.provider,
        &document,
        &Expected {
            issuer: &upstream.identity_provider.entity_id,
            audience: &resolve_entity_id(upstream, &base),
            recipient: &format!("{base}/acs"),
            request_id: &request.request_id,
            trusted: &trusted,
            decryption_keys: &decryption_keys,
            now: now.timestamp(),
            skew: SKEW,
        },
    )
    .map_err(Untaken::Refused)?;

    // Kept for as long as the assertion could still be taken: until its confirmation
    // closes, or the request it answers runs out, whichever comes first.
    let kept_until = DateTime::from_timestamp(accepted.replayable_until + SKEW, 0)
        .map_or(request.expires_at, |closing| {
            closing.min(request.expires_at)
        });
    let fresh = replay::remember_once(
        transaction,
        signing.provider.digest(),
        "saml-assertion",
        &format!("{alias}:{}", accepted.assertion_id),
        kept_until,
    )
    .await
    .map_err(|_| Untaken::Backend)?;
    if !fresh {
        return Err(Untaken::Replayed);
    }
    let arrival = arrive(upstream, &accepted).map_err(|_| Untaken::Unnamed)?;
    Ok(SamlAnswer {
        request,
        accepted,
        arrival,
    })
}

/// Keep what a SAML provider named an admitted login by, so its logout finds it.
pub async fn record_named_session(
    transaction: &Transaction<'_>,
    alias: &str,
    session_id: &str,
    accepted: &Accepted,
) -> Result<(), Unbrokered> {
    let named = &accepted.name_id;
    store::providers::saml_brokering::record_broker_session(
        transaction,
        &SamlBrokerSession {
            session_id: session_id.to_owned(),
            provider_alias: alias.to_owned(),
            name_id: named.value.clone(),
            name_id_format: named.format.clone(),
            name_qualifier: named.name_qualifier.clone(),
            sp_name_qualifier: named.sp_name_qualifier.clone(),
            session_index: accepted.session_index.clone(),
        },
    )
    .await
    .map_err(|_| Unbrokered::Backend)
}

/// A fresh identifier for a message the realm sends: an underscore, since an XML
/// identifier cannot open with a digit, then 32 drawn octets in hexadecimal.
fn draw_message_id(provider: &dyn CryptoProvider) -> Option<String> {
    let mut drawn = [0_u8; 32];
    provider.rand().fill(&mut drawn).ok()?;
    Some(format!("_{}", HEXLOWER.encode(&drawn)))
}

/// Where the browser takes `message` to `address`: on a Redirect query the realm's
/// RSA key signs, added to whatever query the address already holds.
fn sign_redirect(
    provider: &dyn CryptoProvider,
    signing_key: &RealmSigningKey,
    carried: Carried,
    message: &str,
    relay_state: Option<&str>,
    address: &str,
) -> Option<String> {
    let key = RsaKeyPair::from_pem(&signing_key.private_pem).ok()?;
    let private_key = PrivateKey::from_der(key.to_der_private_key());
    let query = encode_query(carried, message, relay_state, SignAlg::Rs256, &|octets| {
        provider
            .signer()
            .sign(SignAlg::Rs256, &private_key, octets)
            .ok()
    })
    .ok()?;
    let separator = if address.contains('?') { '&' } else { '?' };
    Some(format!("{address}{separator}{query}"))
}

/// The keys a SAML provider signs with, from the certificates its metadata carries.
fn read_trusted_keys(upstream: &SamlUpstream) -> Vec<PublicKey> {
    upstream
        .identity_provider
        .signing_certificates
        .iter()
        .filter_map(|certificate| public_key_of(certificate))
        .collect()
}

/// A SAML logout message as it reached the realm's logout address for a provider.
#[derive(Debug, Clone, Copy)]
pub enum SamlLogoutMessage<'a> {
    /// A Redirect query exactly as it arrived, since its signature covers those
    /// octets.
    Redirected(&'a str),
    /// The fields of a POST.
    Posted {
        request: &'a str,
        relay_state: Option<&'a str>,
    },
}

/// Why a SAML provider's logout request was not heeded, each naming what failed for
/// the operator's log. The browser is told one thing whatever the variant, the store
/// failing aside.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unheeded {
    #[error("the message is not a SAML logout request that reads")]
    Unreadable,
    #[error("the logout request was refused: {0}")]
    Refused(RefusedLogout),
    #[error("the logout request was already heeded")]
    Replayed,
    #[error("the store could not be read or written")]
    Backend,
}

/// A SAML provider's logout request once heeded: the logins it names that still
/// stand, and where the browser takes the realm's answer when the provider listens
/// for one.
#[derive(Debug)]
pub struct HeededLogout {
    pub sessions: Vec<String>,
    pub answer: Option<String>,
}

/// Heed a SAML provider's logout request.
///
/// The request is held to the provider's entity and signing keys and to the realm's
/// logout address for this provider, is heeded once, and names the logins still
/// standing through this provider under its name identifier. The answer reports
/// success whatever was found, since a logout that finds nothing leaves nothing to
/// end, and goes back on a Redirect query the realm's RSA key signs, with the relay
/// state the request came with, to where the provider takes answers.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a piece of the logout the address already holds"
)]
pub async fn heed_logout_request(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    upstream: &SamlUpstream,
    issuer: &str,
    alias: &str,
    signing_key: &RealmSigningKey,
    message: SamlLogoutMessage<'_>,
    now: DateTime<Utc>,
) -> Result<HeededLogout, Unheeded> {
    let base = compose_saml_address(issuer, alias);
    let destination = format!("{base}/slo");
    let trusted = read_trusted_keys(upstream);
    let expected = ExpectedLogout {
        issuer: &upstream.identity_provider.entity_id,
        destination: &destination,
        trusted: &trusted,
        now: now.timestamp(),
        skew: SKEW,
    };
    let (requested, relay_state) = match message {
        SamlLogoutMessage::Redirected(query) => {
            let received =
                decode_query(query, Limits::MESSAGE).map_err(|_| Unheeded::Unreadable)?;
            if received.carried != Carried::Request {
                return Err(Unheeded::Unreadable);
            }
            let requested =
                accept_logout_request(provider, Delivered::Redirected(&received), &expected)
                    .map_err(Unheeded::Refused)?;
            (requested, received.relay_state)
        }
        SamlLogoutMessage::Posted {
            request,
            relay_state,
        } => {
            let xml = decode_posted_message(request).ok_or(Unheeded::Unreadable)?;
            let requested = accept_logout_request(provider, Delivered::Posted(&xml), &expected)
                .map_err(Unheeded::Refused)?;
            (requested, relay_state.map(str::to_owned))
        }
    };
    if relay_state
        .as_ref()
        .is_some_and(|held| held.len() > RELAY_STATE_MAX_BYTES)
    {
        return Err(Unheeded::Unreadable);
    }

    let fresh = replay::remember_once(
        transaction,
        provider.digest(),
        "saml-logout-request",
        &format!("{alias}:{}", requested.id),
        DateTime::from_timestamp(requested.replayable_until, 0).unwrap_or(now + STATE_LIFESPAN),
    )
    .await
    .map_err(|_| Unheeded::Backend)?;
    if !fresh {
        return Err(Unheeded::Replayed);
    }
    let sessions = store::providers::saml_brokering::find_named_sessions(
        transaction,
        alias,
        &requested.name_id.value,
        &requested.session_indexes,
    )
    .await
    .map_err(|_| Unheeded::Backend)?;

    let answer = match &upstream.identity_provider.single_logout {
        Some(endpoint) => {
            let answered_at = answer_address(endpoint);
            let answer_id = draw_message_id(provider).ok_or(Unheeded::Backend)?;
            let written = write_logout_response(&LogoutResponse {
                id: &answer_id,
                issue_instant: now.timestamp(),
                destination: answered_at,
                issuer: &resolve_entity_id(upstream, &base),
                in_response_to: &requested.id,
            })
            .map_err(|_| Unheeded::Backend)?;
            Some(
                sign_redirect(
                    provider,
                    signing_key,
                    Carried::Response,
                    &written,
                    relay_state.as_deref(),
                    answered_at,
                )
                .ok_or(Unheeded::Backend)?,
            )
        }
        None => None,
    };
    Ok(HeededLogout { sessions, answer })
}

/// Where a provider takes the answers to its logout requests: the address it gave
/// for them, or else its logout address.
fn answer_address(endpoint: &Endpoint) -> &str {
    endpoint
        .response_location
        .as_deref()
        .unwrap_or(&endpoint.location)
}

#[cfg(test)]
mod tests {
    use super::{SamlUpstream, UnusableSaml, is_saml};
    use super::{Undescribed, compose_saml_address, describe_realm};
    use crypto::jose::jwk::KeyPair;
    use crypto::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
    use crypto::jose::jwk::alg::ed::{EdCurve, EdKeyPair};
    use crypto::jose::jwk::alg::rsa::RsaKeyPair;
    use crypto::provider::SignAlg;
    use crypto::provider::{PrivateKey, PublicKey};
    use crypto::x509::{Issuance, issue_certificate};
    use models::auditable::AuditableModel;
    use models::entities::attributes::{AttributeValue, AttributesMap};
    use models::entities::authz::{IdentityProviderModel, IdentityProviderMutationModel};
    use models::entities::keys::{
        JweAlgorithm, KeyStatus, KeyUse, RealmEncryptionKey, RealmSigningKey,
    };
    use saml::metadata::Misread;
    use saml::xml::{Limits, read_message};

    const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

    fn rsa_key(bits: u32) -> RsaKeyPair {
        RsaKeyPair::generate(bits).expect("an RSA key")
    }

    /// A certificate for the subject's key, issued by the crypto crate under an RSA
    /// issuer, in base64 as metadata carries it.
    fn certificate_for(subject: &dyn KeyPair, issuer: &RsaKeyPair) -> String {
        let der = issue_certificate(&Issuance {
            subject_key: &PublicKey::from_der(subject.to_der_public_key()),
            subject_name: "idp.test",
            issuer_key: &PrivateKey::from_der(issuer.to_der_private_key()),
            issuer_name: "idp.test",
            serial: &[1],
            not_before: 1_789_372_800,
            not_after: 2_104_992_000,
        })
        .expect("a certificate");
        data_encoding::BASE64.encode(&der)
    }

    /// Metadata signing with one certificate, at the addresses given.
    fn metadata(certificate: &str, sign_on: &str, logout: &str, answers: &str) -> String {
        format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.test/metadata"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{logout}" ResponseLocation="{answers}"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sign_on}"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
        )
    }

    fn secure_metadata(certificate: &str) -> String {
        metadata(
            certificate,
            "https://idp.test/sso",
            "https://idp.test/slo",
            "https://idp.test/slo/answers",
        )
    }

    fn provider(said: &[(&str, &str)]) -> IdentityProviderModel {
        let configs: AttributesMap = said
            .iter()
            .map(|(key, value)| ((*key).to_owned(), AttributeValue::Str((*value).to_owned())))
            .collect();
        IdentityProviderMutationModel {
            provider_id: "corp".into(),
            name: "corp".into(),
            display_name: "Corp".into(),
            description: String::new(),
            enabled: Some(true),
            trust_email: Some(false),
            configs: Some(configs),
        }
        .into_model(
            "idp-1".into(),
            "main".into(),
            AuditableModel::from_creator("local".into(), "root".into()),
        )
    }

    fn saml_provider(idp_metadata: &str, more: &[(&str, &str)]) -> IdentityProviderModel {
        let mut said = vec![("protocol", "saml"), ("idp_metadata", idp_metadata)];
        said.extend_from_slice(more);
        provider(&said)
    }

    /// A SAML provider is read with what the administrator chose, or with a
    /// persistent name and nothing else when they chose nothing, an empty value
    /// counting as none; an elliptic key on a named curve and loopback addresses in
    /// clear are taken, and only a provider naming SAML is read as one.
    #[test]
    fn a_saml_provider_is_read_with_what_the_administrator_chose() {
        let issuer = rsa_key(2048);
        let strong = certificate_for(&issuer, &issuer);
        let elliptic = certificate_for(
            &EcKeyPair::generate(EcCurve::P256).expect("a P-256 key"),
            &issuer,
        );
        let upstream = SamlUpstream::parse(&saml_provider(&secure_metadata(&strong), &[]))
            .expect("a usable provider");
        assert_eq!(
            upstream.identity_provider.entity_id,
            "https://idp.test/metadata"
        );
        assert_eq!(upstream.name_id_format, PERSISTENT);
        assert_eq!(
            (
                upstream.principal_attribute,
                upstream.username_attribute,
                upstream.email_attribute,
                upstream.sp_entity_id
            ),
            (None, None, None, None)
        );

        let chosen = SamlUpstream::parse(&saml_provider(
            &secure_metadata(&strong),
            &[
                ("name_id_format", TRANSIENT),
                ("principal_attribute", "employeeNumber"),
                ("username_attribute", "uid"),
                ("email_attribute", "mail"),
                ("sp_entity_id", "https://old.example/sp"),
            ],
        ))
        .expect("a usable provider");
        assert_eq!(chosen.name_id_format, TRANSIENT);
        assert_eq!(
            (
                chosen.principal_attribute.as_deref(),
                chosen.username_attribute.as_deref(),
                chosen.email_attribute.as_deref(),
                chosen.sp_entity_id.as_deref()
            ),
            (
                Some("employeeNumber"),
                Some("uid"),
                Some("mail"),
                Some("https://old.example/sp")
            )
        );

        let unsaid = SamlUpstream::parse(&saml_provider(
            &secure_metadata(&strong),
            &[("name_id_format", ""), ("principal_attribute", "")],
        ))
        .expect("a usable provider");
        assert_eq!(
            (unsaid.name_id_format.as_str(), unsaid.principal_attribute),
            (PERSISTENT, None)
        );

        for usable in [
            secure_metadata(&elliptic),
            metadata(
                &strong,
                "http://localhost:8080/sso",
                "http://127.0.0.1/slo",
                "http://[::1]/answers",
            ),
        ] {
            assert!(SamlUpstream::parse(&saml_provider(&usable, &[])).is_ok());
        }

        assert!(is_saml(&saml_provider("", &[])));
        assert!(!is_saml(&provider(&[("protocol", "oidc")])));
        assert!(!is_saml(&provider(&[])));
    }

    /// What a login could not use is refused at the door with its reason: no
    /// metadata, metadata that is no identity provider, an address in clear off
    /// this machine, a key too weak or of a kind not verified here, a name that can
    /// be given to someone else with no principal beside it, the email as the
    /// principal, and an entity identifier that is none.
    #[test]
    fn what_a_login_cannot_use_is_refused_at_the_door() {
        let issuer = rsa_key(2048);
        let strong = certificate_for(&issuer, &issuer);
        let short = certificate_for(&rsa_key(1024), &issuer);
        let unnamed_curve = certificate_for(
            &EcKeyPair::generate(EcCurve::Secp256k1).expect("a secp256k1 key"),
            &issuer,
        );
        let edwards = certificate_for(
            &EdKeyPair::generate(EdCurve::Ed25519).expect("an Ed25519 key"),
            &issuer,
        );
        let secure = secure_metadata(&strong);
        let long = format!("https://sp.example/{}", "a".repeat(1006));
        for (refused, reason) in [
            (
                provider(&[("protocol", "saml")]),
                UnusableSaml::Missing("idp_metadata"),
            ),
            (
                saml_provider(
                    r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>"#,
                    &[],
                ),
                UnusableSaml::Metadata(Misread::NotOneEntity),
            ),
            (
                saml_provider(
                    &metadata(
                        &strong,
                        "http://idp.test/sso",
                        "https://idp.test/slo",
                        "https://idp.test/slo/answers",
                    ),
                    &[],
                ),
                UnusableSaml::Insecure("single sign-on address"),
            ),
            (
                saml_provider(
                    &metadata(
                        &strong,
                        "https://idp.test/sso",
                        "http://idp.test/slo",
                        "https://idp.test/slo/answers",
                    ),
                    &[],
                ),
                UnusableSaml::Insecure("single logout address"),
            ),
            (
                saml_provider(
                    &metadata(
                        &strong,
                        "https://idp.test/sso",
                        "https://idp.test/slo",
                        "http://idp.test/slo/answers",
                    ),
                    &[],
                ),
                UnusableSaml::Insecure("single logout address"),
            ),
            (
                saml_provider(&secure_metadata(&short), &[]),
                UnusableSaml::WeakKey("RSA below 2048 bits"),
            ),
            (
                saml_provider(&secure_metadata(&unnamed_curve), &[]),
                UnusableSaml::WeakKey("a curve other than P-256, P-384 or P-521"),
            ),
            (
                saml_provider(&secure_metadata(&edwards), &[]),
                UnusableSaml::WeakKey("a key of a kind not verified here"),
            ),
            (
                saml_provider(&secure, &[("name_id_format", TRANSIENT)]),
                UnusableSaml::NoPrincipal,
            ),
            (
                saml_provider(
                    &secure,
                    &[("principal_attribute", "mail"), ("email_attribute", "mail")],
                ),
                UnusableSaml::EmailAsPrincipal,
            ),
            (
                saml_provider(&secure, &[("sp_entity_id", " https://sp.example")]),
                UnusableSaml::NotAnEntity("sp_entity_id"),
            ),
            (
                saml_provider(&secure, &[("sp_entity_id", &long)]),
                UnusableSaml::NotAnEntity("sp_entity_id"),
            ),
        ] {
            assert_eq!(SamlUpstream::parse(&refused).err(), Some(reason));
        }
        assert!(
            SamlUpstream::parse(&saml_provider(&secure, &[("sp_entity_id", &long[..1024])]))
                .is_ok()
        );
    }

    /// The realm describes itself to a provider under the entity identifier its
    /// alias gives, or the one an administrator set, with its consumer, its logout
    /// and the format asked, a certificate for its signing key issued by that key and
    /// one for its encryption key issued by the signing key, the same bytes every
    /// time; without an encryption key it offers none, and a key that is not RSA is
    /// not described.
    #[test]
    fn a_realm_describes_itself_with_certificates_for_its_keys() {
        let provider_key = rsa_key(2048);
        let provider_certificate = certificate_for(&provider_key, &provider_key);
        let upstream =
            SamlUpstream::parse(&saml_provider(&secure_metadata(&provider_certificate), &[]))
                .expect("a usable provider");
        let signer = rsa_key(2048);
        let sealed_to = rsa_key(2048);
        let signing_key = RealmSigningKey {
            tenant: "acme".into(),
            realm_id: "main".into(),
            kid: "8PDw8PDw8PDw8PDw8PDw8PDw".into(),
            algorithm: SignAlg::Rs256,
            key_use: KeyUse::Sig,
            status: KeyStatus::Active,
            priority: 100,
            private_pem: signer.to_pem_private_key(),
            public_jwk: serde_json::Value::Null,
            created_at: 1_789_372_800,
        };
        let encryption_key = RealmEncryptionKey {
            kid: "ZW5jcnlwdGlvbi1rZXktdGh1bWJwcmludC0wMDAwMA".into(),
            algorithm: JweAlgorithm::RsaOaep256,
            private_pem: sealed_to.to_pem_private_key(),
            public_jwk: serde_json::Value::Null,
        };
        let issuer = "https://id.test/realms/main";
        let base = "https://id.test/realms/main/broker/corp/saml";
        assert_eq!(compose_saml_address(issuer, "corp"), base);

        let written = describe_realm(
            &upstream,
            issuer,
            "corp",
            "main",
            &signing_key,
            Some(&encryption_key),
        )
        .expect("a description");
        assert_eq!(
            describe_realm(
                &upstream,
                issuer,
                "corp",
                "main",
                &signing_key,
                Some(&encryption_key)
            ),
            Ok(written.clone())
        );
        let document = read_message(&written, Limits::MESSAGE).expect("well-formed");
        let entity = document.root_element();
        assert_eq!(
            entity.attribute("entityID"),
            Some(format!("{base}/metadata").as_str())
        );
        let role = entity.first_element_child().expect("a role");
        let located = |name: &str| {
            role.children()
                .filter(|node| node.tag_name().name() == name)
                .filter_map(|node| node.attribute("Location"))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(located("AssertionConsumerService"), [format!("{base}/acs")]);
        assert_eq!(
            located("SingleLogoutService"),
            [format!("{base}/slo"), format!("{base}/slo")]
        );
        let formats: Vec<_> = role
            .children()
            .filter(|node| node.tag_name().name() == "NameIDFormat")
            .filter_map(|node| node.text())
            .collect();
        assert_eq!(formats, [upstream.name_id_format.as_str()]);

        let published = |usage: &str| {
            role.children()
                .filter(|node| node.attribute("use") == Some(usage))
                .flat_map(|node| node.descendants())
                .filter(|node| node.tag_name().name() == "X509Certificate")
                .filter_map(|node| node.text())
                .map(|text| {
                    data_encoding::BASE64
                        .decode(text.as_bytes())
                        .expect("base64")
                })
                .collect::<Vec<_>>()
        };
        let issued_by_signer = |subject: &RsaKeyPair, kid: &str| {
            issue_certificate(&Issuance {
                subject_key: &PublicKey::from_der(subject.to_der_public_key()),
                subject_name: "main",
                issuer_key: &PrivateKey::from_der(signer.to_der_private_key()),
                issuer_name: "main",
                serial: &super::derive_serial(kid),
                not_before: 1_789_372_800,
                not_after: 253_402_300_799,
            })
            .expect("a certificate")
        };
        assert_eq!(
            published("signing"),
            [issued_by_signer(&signer, &signing_key.kid)]
        );
        assert_eq!(
            published("encryption"),
            [issued_by_signer(&sealed_to, &encryption_key.kid)]
        );
        let serial = super::derive_serial(&signing_key.kid);
        assert_eq!((serial.len(), serial[0] & 0xc0), (16, 0x40));

        let overridden = SamlUpstream {
            sp_entity_id: Some("https://old.example/sp".into()),
            ..upstream.clone()
        };
        let written = describe_realm(&overridden, issuer, "corp", "main", &signing_key, None)
            .expect("a description");
        let document = read_message(&written, Limits::MESSAGE).expect("well-formed");
        assert_eq!(
            document.root_element().attribute("entityID"),
            Some("https://old.example/sp")
        );
        assert_eq!(
            document
                .descendants()
                .filter(|node| node.tag_name().name() == "KeyDescriptor")
                .count(),
            1
        );

        let elliptic = RealmSigningKey {
            private_pem: EcKeyPair::generate(EcCurve::P256)
                .expect("a P-256 key")
                .to_pem_private_key(),
            ..signing_key.clone()
        };
        assert_eq!(
            describe_realm(&upstream, issuer, "corp", "main", &elliptic, None),
            Err(Undescribed::UnreadableKey)
        );
    }

    /// A login leaves for a SAML provider at its sign-on address, carrying an
    /// authentication request under a fresh identifier, issued by the realm's entity
    /// for that provider, asking for its format and for the answer at its consumer,
    /// on a query the realm's key signs; the row keeps the identifier, the provider,
    /// the login and a brokered login's expiry; an overriding entity identifier is
    /// the issuer, and a sign-on address that already holds a query is extended.
    #[test]
    fn a_login_leaves_for_a_saml_provider_on_a_signed_request() {
        use super::depart;
        use chrono::DateTime;
        use crypto::provider::CryptoConfig;
        use crypto::provider::openssl::OpenSslProvider;
        use saml::redirect::{Carried, decode_query, verify_query_signature};

        let crypto = OpenSslProvider::new(&CryptoConfig::default()).expect("a provider");
        let provider_key = rsa_key(2048);
        let upstream = SamlUpstream::parse(&saml_provider(
            &secure_metadata(&certificate_for(&provider_key, &provider_key)),
            &[],
        ))
        .expect("a usable provider");
        let signer = rsa_key(2048);
        let signing_key = RealmSigningKey {
            tenant: "acme".into(),
            realm_id: "main".into(),
            kid: "8PDw8PDw8PDw8PDw8PDw8PDw".into(),
            algorithm: SignAlg::Rs256,
            key_use: KeyUse::Sig,
            status: KeyStatus::Active,
            priority: 100,
            private_pem: signer.to_pem_private_key(),
            public_jwk: serde_json::Value::Null,
            created_at: 1_789_372_800,
        };
        let now = DateTime::from_timestamp(1_789_372_800, 0).expect("a time");
        let issuer = "https://id.test/realms/main";
        let base = "https://id.test/realms/main/broker/corp/saml";
        let departure = depart(
            &crypto,
            &upstream,
            issuer,
            "corp",
            &signing_key,
            "auth-7",
            now,
        )
        .expect("a departure");

        let (address, query) = departure.location.split_once('?').expect("a query");
        assert_eq!(address, "https://idp.test/sso");
        let received = decode_query(query, Limits::MESSAGE).expect("a Redirect query");
        assert_eq!(received.carried, Carried::Request);
        let signature = received.signature.as_ref().expect("a signature");
        assert_eq!(
            verify_query_signature(
                &crypto,
                signature,
                &[PublicKey::from_der(signer.to_der_public_key())]
            ),
            Ok(())
        );
        let document = read_message(&received.message, Limits::MESSAGE).expect("well-formed");
        let request = document.root_element();
        assert_eq!(request.tag_name().name(), "AuthnRequest");
        let consumer = format!("{base}/acs");
        for (name, value) in [
            ("ID", departure.request.request_id.as_str()),
            ("Destination", "https://idp.test/sso"),
            ("AssertionConsumerServiceURL", consumer.as_str()),
            ("IssueInstant", "2026-09-14T08:00:00Z"),
        ] {
            assert_eq!(request.attribute(name), Some(value), "{name}");
        }
        let child = |name: &str| {
            request
                .children()
                .find(|node| node.tag_name().name() == name)
                .expect("a child")
        };
        assert_eq!(
            child("Issuer").text(),
            Some(format!("{base}/metadata").as_str())
        );
        assert_eq!(child("NameIDPolicy").attribute("Format"), Some(PERSISTENT));

        let id = &departure.request.request_id;
        assert!(
            id.len() == 65
                && id.starts_with('_')
                && id[1..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{id}"
        );
        assert_eq!(
            (
                departure.request.provider_alias.as_str(),
                departure.request.auth_session.as_str(),
                departure.request.expires_at
            ),
            ("corp", "auth-7", now + chrono::Duration::minutes(10))
        );
        let again = depart(
            &crypto,
            &upstream,
            issuer,
            "corp",
            &signing_key,
            "auth-7",
            now,
        )
        .expect("a departure");
        assert_ne!(again.request.request_id, departure.request.request_id);

        let elsewhere = SamlUpstream {
            sp_entity_id: Some("https://old.example/sp".into()),
            identity_provider: saml::metadata::IdentityProvider {
                single_sign_on: "https://idp.test/sso?tenant=acme".into(),
                ..upstream.identity_provider.clone()
            },
            ..upstream.clone()
        };
        let departure = depart(
            &crypto,
            &elsewhere,
            issuer,
            "corp",
            &signing_key,
            "auth-7",
            now,
        )
        .expect("a departure");
        assert!(
            departure
                .location
                .starts_with("https://idp.test/sso?tenant=acme&SAMLRequest="),
            "{}",
            departure.location
        );
        let received = decode_query(
            departure.location.split_once('?').expect("a query").1,
            Limits::MESSAGE,
        )
        .expect("a Redirect query");
        let document = read_message(&received.message, Limits::MESSAGE).expect("well-formed");
        let issued_by = document
            .root_element()
            .children()
            .find(|node| node.tag_name().name() == "Issuer")
            .and_then(|node| node.text())
            .map(str::to_owned);
        assert_eq!(issued_by.as_deref(), Some("https://old.example/sp"));
    }

    fn accepted(
        name_id: &str,
        format: Option<&str>,
        attributes: &[(&str, &[&str])],
    ) -> saml::response::Accepted {
        saml::response::Accepted {
            assertion_id: "_assertion".into(),
            replayable_until: 1_789_373_100,
            name_id: saml::name_id::NameId {
                value: name_id.into(),
                format: format.map(str::to_owned),
                name_qualifier: None,
                sp_name_qualifier: None,
            },
            session_index: Some("_session-1".into()),
            session_not_on_or_after: None,
            authn_instant: 1_789_372_790,
            authn_context_class: None,
            attributes: attributes
                .iter()
                .map(|(name, values)| {
                    (
                        (*name).to_owned(),
                        values.iter().map(|value| (*value).to_owned()).collect(),
                    )
                })
                .collect(),
        }
    }

    /// An assertion names the person only by a name that stays theirs: the
    /// persistent name when the provider was set up for one, and never a transient
    /// name or one in no format in its place; otherwise the one value of the
    /// attribute set to name them, and never none, two or an empty one. The username
    /// and the address are single values, the address counts as verified when given,
    /// and every attribute is kept as a claim, a value once and several as a list.
    #[test]
    fn an_assertion_names_the_person_only_by_a_name_that_stays_theirs() {
        use super::arrive;
        use crate::brokering::Unbrokered;

        let provider_key = rsa_key(2048);
        let metadata = secure_metadata(&certificate_for(&provider_key, &provider_key));
        let persistent = SamlUpstream::parse(&saml_provider(
            &metadata,
            &[("username_attribute", "uid"), ("email_attribute", "mail")],
        ))
        .expect("a usable provider");
        let arrival = arrive(
            &persistent,
            &accepted(
                "AAdzZWNyZXQx",
                Some(PERSISTENT),
                &[
                    ("uid", &["ada"][..]),
                    ("mail", &["ada@idp.test"][..]),
                    ("groups", &["staff", "admins"][..]),
                    ("groups", &["ops"][..]),
                    ("empty", &[][..]),
                ],
            ),
        )
        .expect("an arrival");
        assert_eq!(arrival.external_user_id, "AAdzZWNyZXQx");
        assert_eq!(arrival.username.as_deref(), Some("ada"));
        assert_eq!(
            (arrival.email.as_deref(), arrival.email_verified),
            (Some("ada@idp.test"), true)
        );
        assert_eq!(
            arrival.claims.get("groups"),
            Some(&serde_json::json!(["staff", "admins", "ops"]))
        );
        assert_eq!(arrival.claims.get("uid"), Some(&serde_json::json!("ada")));
        assert!(!arrival.claims.contains_key("empty"));

        for format in [Some(TRANSIENT), None] {
            assert!(
                matches!(
                    arrive(&persistent, &accepted("AAdzZWNyZXQx", format, &[])),
                    Err(Unbrokered::Refused)
                ),
                "{format:?}"
            );
        }
        let doubled = arrive(
            &persistent,
            &accepted(
                "AAdzZWNyZXQx",
                Some(PERSISTENT),
                &[
                    ("mail", &["one@idp.test", "two@idp.test"][..]),
                    ("uid", &["ada", "lovelace"][..]),
                ],
            ),
        )
        .expect("an arrival");
        assert_eq!(
            (doubled.email, doubled.email_verified, doubled.username),
            (None, false, None)
        );

        let by_attribute = SamlUpstream::parse(&saml_provider(
            &metadata,
            &[
                ("name_id_format", TRANSIENT),
                ("principal_attribute", "employeeNumber"),
            ],
        ))
        .expect("a usable provider");
        let arrival = arrive(
            &by_attribute,
            &accepted(
                "transient-1",
                Some(TRANSIENT),
                &[("employeeNumber", &["E-42"][..])],
            ),
        )
        .expect("an arrival");
        assert_eq!(arrival.external_user_id, "E-42");
        let none: &[(&str, &[&str])] = &[];
        let two: &[(&str, &[&str])] = &[("employeeNumber", &["E-42", "E-43"][..])];
        let empty: &[(&str, &[&str])] = &[("employeeNumber", &[""][..])];
        for attributes in [none, two, empty] {
            assert!(
                matches!(
                    arrive(
                        &by_attribute,
                        &accepted("transient-1", Some(TRANSIENT), attributes)
                    ),
                    Err(Unbrokered::Refused)
                ),
                "{attributes:?}"
            );
        }
    }

    /// Every RSA encryption key the realm holds decrypts, whatever its OAEP variant,
    /// while a key of another kind and one that does not read are left out.
    #[test]
    fn every_rsa_encryption_key_the_realm_holds_decrypts() {
        use super::read_decryption_keys;

        let first = rsa_key(2048);
        let second = rsa_key(2048);
        let key = |kid: &str, algorithm: JweAlgorithm, private_pem: Vec<u8>| RealmEncryptionKey {
            kid: kid.into(),
            algorithm,
            private_pem,
            public_jwk: serde_json::Value::Null,
        };
        let held = [
            key(
                "active",
                JweAlgorithm::RsaOaep256,
                first.to_pem_private_key(),
            ),
            key(
                "rotated",
                JweAlgorithm::RsaOaep,
                second.to_pem_private_key(),
            ),
            key(
                "elliptic",
                JweAlgorithm::EcdhEs,
                EcKeyPair::generate(EcCurve::P256)
                    .expect("a P-256 key")
                    .to_pem_private_key(),
            ),
            key(
                "unreadable",
                JweAlgorithm::RsaOaep256,
                b"not a key".to_vec(),
            ),
        ];
        let read: Vec<Vec<u8>> = read_decryption_keys(&held)
            .iter()
            .map(|private| private.der().to_vec())
            .collect();
        assert_eq!(
            read,
            [first.to_der_private_key(), second.to_der_private_key()]
        );
    }

    /// A provider's logout answers go where it takes answers, and to its logout
    /// address when it named no other.
    #[test]
    fn a_logout_answer_goes_where_the_provider_takes_answers() {
        let mut endpoint = saml::metadata::Endpoint {
            location: "https://idp.test/slo".to_owned(),
            response_location: Some("https://idp.test/slo/answers".to_owned()),
        };
        assert_eq!(
            super::answer_address(&endpoint),
            "https://idp.test/slo/answers"
        );
        endpoint.response_location = None;
        assert_eq!(super::answer_address(&endpoint), "https://idp.test/slo");
    }
}
