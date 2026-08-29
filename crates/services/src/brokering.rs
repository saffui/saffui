use chrono::{DateTime, Duration, Utc};
use crypto::provider::{CryptoProvider, HashAlg, SignAlg};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use deadpool_postgres::Transaction;
use models::entities::attributes::{AttributeValue, AttributesMap};
use models::entities::authz::IdentityProviderModel;
use models::entities::brokering::{BrokerLoginState, FederatedIdentityModel};
use serde_json::Value;
use store::providers::{brokering, users};

/// How long what left for the upstream is honoured on the way back.
pub const STATE_LIFESPAN: Duration = Duration::minutes(10);

/// The upstream, read out of the stored bag once and typed, fail closed:
/// what decides whether a token is trusted does not stay a string in a bag.
#[derive(Debug, Clone)]
pub struct Upstream {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    /// Space separated, `openid` unless the operator said more.
    pub scope: String,
    /// The algorithms an upstream token may be signed with. Bounded by
    /// configuration, never by the token's own header.
    pub allowed_algs: Vec<SignAlg>,
}

/// Why a provider's configuration cannot be used, each naming the field.
#[derive(Debug, thiserror::Error)]
pub enum Unusable {
    #[error("the provider names no {0}")]
    Missing(&'static str),
    #[error("{0} is not an https address")]
    Insecure(&'static str),
    #[error("no signing algorithm answers to {0}")]
    UnknownAlgorithm(String),
}

fn text<'a>(bag: &'a AttributesMap, key: &str) -> Option<&'a str> {
    bag.get(key).and_then(AttributeValue::as_str)
}

/// An endpoint an operator may point at: https, or loopback for a bench.
fn addressed(bag: &AttributesMap, key: &'static str) -> Result<String, Unusable> {
    let given = text(bag, key).ok_or(Unusable::Missing(key))?;
    let secure = given.starts_with("https://")
        || given.starts_with("http://127.0.0.1")
        || given.starts_with("http://localhost");
    if !secure {
        return Err(Unusable::Insecure(key));
    }
    Ok(given.to_owned())
}

impl Upstream {
    /// Read the stored bag, refusing what cannot be used rather than
    /// deferring the failure to somebody's login.
    pub fn parse(provider: &IdentityProviderModel) -> Result<Self, Unusable> {
        let empty = AttributesMap::new();
        let bag = provider.configs.as_ref().unwrap_or(&empty);
        let allowed_algs = match text(bag, "allowed_algs") {
            None => vec![SignAlg::Rs256, SignAlg::Es256],
            Some(named) => named
                .split_whitespace()
                .map(|name| {
                    serde_json::from_value(Value::String(name.to_owned()))
                        .map_err(|_| Unusable::UnknownAlgorithm(name.to_owned()))
                })
                .collect::<Result<Vec<SignAlg>, _>>()?,
        };
        Ok(Self {
            issuer: text(bag, "issuer")
                .ok_or(Unusable::Missing("issuer"))?
                .to_owned(),
            authorization_endpoint: addressed(bag, "authorization_endpoint")?,
            token_endpoint: addressed(bag, "token_endpoint")?,
            jwks_uri: addressed(bag, "jwks_uri")?,
            client_id: text(bag, "client_id")
                .ok_or(Unusable::Missing("client_id"))?
                .to_owned(),
            scope: text(bag, "scope").unwrap_or("openid").to_owned(),
            allowed_algs,
        })
    }
}

/// What leaves for the upstream: where the browser goes, and the row that
/// ties the way back to this departure. The verifier and the nonce are in
/// the row and never in the browser.
pub struct Departure {
    pub location: String,
    pub state: BrokerLoginState,
}

/// Why a brokered login could not begin or end. One public face: everything
/// reaching the callback is attacker supplied, and telling a browser which
/// check failed tells an attacker which constraint to work around next.
#[derive(Debug, thiserror::Error)]
pub enum Unbrokered {
    #[error("the brokered login was refused")]
    Refused,
    #[error("the store could not be read or written")]
    Backend,
}

pub fn depart(
    provider: &dyn CryptoProvider,
    upstream: &Upstream,
    alias: &str,
    auth_session: &str,
    redirect_uri: &str,
    now: DateTime<Utc>,
) -> Result<Departure, Unbrokered> {
    let state = drawn(provider)?;
    let nonce = drawn(provider)?;
    let verifier = drawn(provider)?;
    let challenge = BASE64URL_NOPAD.encode(
        &provider
            .digest()
            .hash(HashAlg::Sha256, verifier.as_bytes())
            .map_err(|_| Unbrokered::Backend)?,
    );

    let location = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        upstream.authorization_endpoint,
        encoded(&upstream.client_id),
        encoded(redirect_uri),
        encoded(&upstream.scope),
        encoded(&state),
        encoded(&nonce),
        encoded(&challenge),
    );
    Ok(Departure {
        location,
        state: BrokerLoginState {
            state_hash: hashed(provider, &state)?,
            provider_alias: alias.to_owned(),
            auth_session: auth_session.to_owned(),
            code_verifier: verifier,
            nonce,
            expires_at: now + STATE_LIFESPAN,
        },
    })
}

/// Spend the state the way back names, exactly once, on this provider only.
pub async fn returned(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    alias: &str,
    state: &str,
    now: DateTime<Utc>,
) -> Result<BrokerLoginState, Unbrokered> {
    brokering::consume_state(transaction, &hashed(provider, state)?, alias, now)
        .await
        .map_err(|_| Unbrokered::Backend)?
        .ok_or(Unbrokered::Refused)
}

/// Who the upstream says arrived.
#[derive(Debug)]
pub struct Arrival {
    pub external_user_id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
}

/// Read the upstream's identity token against its published keys, bounded
/// by configuration: the algorithm comes from the allow list, the key from
/// the fetched set, and the claims from this departure's own nonce.
pub fn arrived(
    upstream: &Upstream,
    keys: &Value,
    id_token: &str,
    state: &BrokerLoginState,
    now: DateTime<Utc>,
) -> Result<Arrival, Unbrokered> {
    let claims = crate::assertion::read_against(keys, id_token, &upstream.allowed_algs)
        .map_err(|_| Unbrokered::Refused)?;

    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    if text("iss") != Some(upstream.issuer.as_str()) {
        return Err(Unbrokered::Refused);
    }
    let audience_holds = match claims.get("aud") {
        Some(Value::String(one)) => one == &upstream.client_id,
        Some(Value::Array(many)) => many
            .iter()
            .any(|one| one.as_str() == Some(upstream.client_id.as_str())),
        _ => false,
    };
    if !audience_holds {
        return Err(Unbrokered::Refused);
    }
    let expires = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
    if expires <= now.timestamp() {
        return Err(Unbrokered::Refused);
    }
    if text("nonce") != Some(state.nonce.as_str()) {
        return Err(Unbrokered::Refused);
    }

    Ok(Arrival {
        external_user_id: text("sub").ok_or(Unbrokered::Refused)?.to_owned(),
        username: text("preferred_username").map(str::to_owned),
        email: text("email").map(str::to_owned),
        email_verified: claims
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// The local account this arrival is, decided by policy rather than by
/// default.
///
/// A standing link answers first. Failing that, an existing account is
/// linked by email only when the upstream asserts the address verified and
/// the operator marked the provider trusted for it: silent linking on an
/// unverified email hands the local account to whoever can register the
/// address upstream. Failing both, a person is created, through the same
/// door every user creation goes through.
pub async fn decide_link(
    transaction: &Transaction<'_>,
    tenant: &str,
    realm_id: &str,
    provider: &IdentityProviderModel,
    arrival: &Arrival,
    now: DateTime<Utc>,
) -> Result<String, Unbrokered> {
    if let Some(user_id) = brokering::linked_user(
        transaction,
        &provider.provider_id,
        &arrival.external_user_id,
    )
    .await
    .map_err(|_| Unbrokered::Backend)?
    {
        return Ok(user_id);
    }

    let trusted = provider.trust_email.unwrap_or(false) && arrival.email_verified;
    if trusted
        && let Some(email) = &arrival.email
        && let Some(standing) = users::load_by_email(transaction, email)
            .await
            .map_err(|_| Unbrokered::Backend)?
    {
        remember(transaction, provider, arrival, &standing.user_id, now).await?;
        return Ok(standing.user_id);
    }

    let named = arrival
        .username
        .clone()
        .or_else(|| arrival.email.clone())
        .unwrap_or_else(|| format!("{}-{}", provider.provider_id, arrival.external_user_id));
    let spec = crate::admin::users::Spec {
        email: arrival.email.clone().filter(|_| trusted),
        email_verified: Some(trusted),
        enabled: Some(true),
        given_name: None,
        family_name: None,
        phone: None,
        required_actions: None,
        attributes: Vec::new(),
    };
    let made = crate::admin::users::create(
        transaction,
        tenant,
        realm_id,
        &format!("broker:{}", provider.provider_id),
        &named,
        &spec,
    )
    .await
    .map_err(|_| Unbrokered::Refused)?;
    remember(transaction, provider, arrival, &made.user_id, now).await?;
    Ok(made.user_id)
}

async fn remember(
    transaction: &Transaction<'_>,
    provider: &IdentityProviderModel,
    arrival: &Arrival,
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<(), Unbrokered> {
    brokering::link(
        transaction,
        &FederatedIdentityModel {
            realm_id: provider.realm_id.clone(),
            user_id: user_id.to_owned(),
            provider_alias: provider.provider_id.clone(),
            external_user_id: arrival.external_user_id.clone(),
            external_username: arrival.username.clone().unwrap_or_default(),
            created_at: now,
        },
    )
    .await
    .map_err(|_| Unbrokered::Backend)
}

/// Percent-encode one query value: RFC 3986 unreserved stays, all else goes
/// as bytes.
fn encoded(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

fn drawn(provider: &dyn CryptoProvider) -> Result<String, Unbrokered> {
    let mut bytes = [0_u8; 32];
    provider
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Unbrokered::Backend)?;
    Ok(BASE64URL_NOPAD.encode(&bytes))
}

fn hashed(provider: &dyn CryptoProvider, state: &str) -> Result<String, Unbrokered> {
    Ok(HEXLOWER.encode(
        &provider
            .digest()
            .hash(HashAlg::Sha256, state.as_bytes())
            .map_err(|_| Unbrokered::Backend)?,
    ))
}
