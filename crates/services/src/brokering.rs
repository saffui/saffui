use chrono::{DateTime, Duration, Utc};
use crypto::provider::{CryptoProvider, HashAlg, SignAlg};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use deadpool_postgres::Transaction;
use models::entities::attributes::{AttributeValue, AttributesMap};
use models::entities::authz::IdentityProviderModel;
use models::entities::brokering::{BrokerLoginState, FederatedIdentityModel, IdpMapperModel};
use serde_json::{Map, Value};
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
    /// Every verified claim, whole: what the named fields above read from,
    /// and what the provider's mappers read beside them.
    pub claims: Map<String, Value>,
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
        claims,
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
) -> Result<(String, bool), Unbrokered> {
    if let Some(user_id) = brokering::linked_user(
        transaction,
        &provider.provider_id,
        &arrival.external_user_id,
    )
    .await
    .map_err(|_| Unbrokered::Backend)?
    {
        return Ok((user_id, false));
    }

    let trusted = provider.trust_email.unwrap_or(false) && arrival.email_verified;
    if trusted
        && let Some(email) = &arrival.email
        && let Some(standing) = users::load_by_email(transaction, email)
            .await
            .map_err(|_| Unbrokered::Backend)?
    {
        remember(transaction, provider, arrival, &standing.user_id, now).await?;
        return Ok((standing.user_id, true));
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
    Ok((made.user_id, true))
}

/// Write an upstream claim onto the arriving user as an attribute.
pub const ATTRIBUTE_IDP_MAPPER: &str = "oidc-user-attribute-idp-mapper";
/// Grant the arriving user a named local role.
pub const ROLE_IDP_MAPPER: &str = "oidc-hardcoded-role-idp-mapper";

/// Every rule this build applies on arrival. The plane refuses names
/// outside it rather than recording rules nothing runs.
pub const KNOWN_IDP_MAPPERS: [&str; 2] = [ATTRIBUTE_IDP_MAPPER, ROLE_IDP_MAPPER];

/// What a rule reads from its bag.
pub const CLAIM: &str = "claim";
pub const USER_ATTRIBUTE: &str = "user.attribute";
pub const ROLE: &str = "role";
pub const SYNC_MODE: &str = "syncMode";

fn config_str<'a>(
    configs: &'a Option<models::entities::attributes::AttributesMap>,
    key: &str,
) -> Option<&'a str> {
    configs
        .as_ref()
        .and_then(|bag| bag.get(key))
        .and_then(models::entities::attributes::AttributeValue::as_str)
}

/// Whether a rule runs again for somebody already known: `import`, the
/// resting mode, writes once at the first arrival; `force` writes on every
/// one, taking the upstream as authoritative.
fn forced(mapper: &IdpMapperModel) -> bool {
    config_str(&mapper.configs, SYNC_MODE) == Some("force")
}

/// Run the provider's rules on who arrived.
///
/// A rule that no longer resolves is skipped with a line for the operator
/// rather than failing the login: the person at the door proved who they
/// are, and a stale rule is the operator's to mend, not theirs to be
/// locked out over.
pub async fn apply_mappers(
    transaction: &Transaction<'_>,
    provider: &IdentityProviderModel,
    user_id: &str,
    arrival: &Arrival,
    first_login: bool,
) -> Result<(), Unbrokered> {
    let rules = brokering::mappers_of(transaction, &provider.provider_id)
        .await
        .map_err(|_| Unbrokered::Backend)?;
    if rules.is_empty() {
        return Ok(());
    }

    let mut person: Option<models::entities::user::UserModel> = None;
    let mut rewritten = false;
    for rule in &rules {
        if !first_login && !forced(rule) {
            continue;
        }
        match rule.mapper_type.as_str() {
            ATTRIBUTE_IDP_MAPPER => {
                let (Some(claim), Some(attribute)) = (
                    config_str(&rule.configs, CLAIM),
                    config_str(&rule.configs, USER_ATTRIBUTE),
                ) else {
                    continue;
                };
                let value = match arrival.claims.get(claim) {
                    Some(Value::String(text)) => {
                        models::entities::attributes::AttributeValue::Str(text.clone())
                    }
                    Some(Value::Bool(flag)) => {
                        models::entities::attributes::AttributeValue::Bool(*flag)
                    }
                    Some(Value::Number(number)) if number.as_i64().is_some() => {
                        models::entities::attributes::AttributeValue::Int(
                            number.as_i64().unwrap_or_default(),
                        )
                    }
                    // Absent, or a shape no attribute holds: nothing to write.
                    _ => continue,
                };
                if person.is_none() {
                    person = users::load(transaction, user_id)
                        .await
                        .map_err(|_| Unbrokered::Backend)?;
                }
                let Some(held) = person.as_mut() else {
                    continue;
                };
                held.attributes
                    .get_or_insert_with(Default::default)
                    .insert(attribute.to_owned(), value);
                rewritten = true;
            }
            ROLE_IDP_MAPPER => {
                let Some(role_id) = config_str(&rule.configs, ROLE) else {
                    continue;
                };
                // The plane checked the role when the rule was written; one
                // deleted since is the operator's to mend, not a reason to
                // lock the person out.
                if store::providers::roles::load(transaction, role_id)
                    .await
                    .map_err(|_| Unbrokered::Backend)?
                    .is_none()
                {
                    tracing::warn!(rule = %rule.name, role_id, "an idp mapper names a role nobody holds anymore");
                    continue;
                }
                store::providers::roles::grant_to_user(transaction, user_id, role_id)
                    .await
                    .map_err(|_| Unbrokered::Backend)?;
            }
            _ => {}
        }
    }
    if rewritten && let Some(held) = person.as_ref() {
        users::update(transaction, held)
            .await
            .map_err(|_| Unbrokered::Backend)?;
    }
    Ok(())
}

/// The names an upstream's document answers for: what it asserts about the
/// person, the protocol's own plumbing left out. `sub` stays out too: it
/// names the person at the upstream, and locally that is the link's job.
const SPOKEN_FOR_NOBODY: [&str; 17] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "nonce",
    "auth_time",
    "acr",
    "amr",
    "azp",
    "sid",
    "at_hash",
    "c_hash",
    "jti",
    "typ",
    "scope",
];

/// Keep the upstream's own signed assertion as this person's aggregated
/// claim source, OIDC Core 5.6.2: carried, never restated.
///
/// One source per provider per person, replaced on every arrival, because
/// the document expires with the login that brought it. Names another
/// source of the person already answers for stay with that source; and an
/// arrival asserting nothing person-shaped takes the stale source away
/// rather than leaving a document with nothing to say.
pub async fn keep_assertions(
    transaction: &Transaction<'_>,
    provider: &IdentityProviderModel,
    user_id: &str,
    id_token: &str,
    arrival: &Arrival,
) -> Result<(), Unbrokered> {
    let source_id = format!("idp-{}-{user_id}", provider.provider_id);
    let standing = brokering::claim_sources_of(transaction, user_id)
        .await
        .map_err(|_| Unbrokered::Backend)?;
    let taken_elsewhere = |name: &str| {
        standing.iter().any(|source| {
            source.source_id != source_id && source.claims.iter().any(|held| held == name)
        })
    };
    let spoken: Vec<String> = arrival
        .claims
        .keys()
        .filter(|name| !SPOKEN_FOR_NOBODY.contains(&name.as_str()))
        .filter(|name| !taken_elsewhere(name))
        .cloned()
        .collect();

    brokering::delete_claim_source(transaction, user_id, &source_id)
        .await
        .map_err(|_| Unbrokered::Backend)?;
    if spoken.is_empty() {
        return Ok(());
    }
    brokering::create_claim_source(
        transaction,
        &models::entities::brokering::UserClaimSourceModel {
            source_id,
            realm_id: provider.realm_id.clone(),
            user_id: user_id.to_owned(),
            claims: spoken,
            kind: models::entities::brokering::ClaimSourceKind::Jwt,
            jwt: Some(id_token.to_owned()),
            endpoint: None,
            endpoint_token: None,
            metadata: models::auditable::AuditableModel::from_creator(
                provider.metadata.tenant.clone(),
                format!("broker:{}", provider.provider_id),
            ),
        },
    )
    .await
    .map_err(|_| Unbrokered::Backend)
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

/// Who an upstream logout dismisses.
#[derive(Debug)]
pub struct Dismissal {
    pub external_user_id: String,
}

/// Read an upstream's logout token against its published keys, Back-Channel
/// Logout 1.0 §2.6, with this realm standing where a relying party stands.
///
/// The algorithm is bounded by configuration, the issuer and audience by
/// what the provider registered, the events member by the one this token
/// exists to carry, and a nonce by its absence: a logout token carrying one
/// is an identity token trying to be replayed as a logout. The subject is
/// required outright; a token naming only a session says which login ended
/// at the upstream, and this realm never learned upstream session names, so
/// it is refused with that reason rather than quietly closing nothing.
pub fn dismissed(
    upstream: &Upstream,
    keys: &Value,
    logout_token: &str,
    now: DateTime<Utc>,
) -> Result<Dismissal, Unbrokered> {
    let claims = crate::assertion::read_against(keys, logout_token, &upstream.allowed_algs)
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
    if claims.get("iat").and_then(Value::as_i64).is_none() {
        return Err(Unbrokered::Refused);
    }
    if let Some(expires) = claims.get("exp").and_then(Value::as_i64)
        && expires <= now.timestamp()
    {
        return Err(Unbrokered::Refused);
    }
    let carries_event = claims
        .get("events")
        .and_then(Value::as_object)
        .is_some_and(|events| {
            events.contains_key("http://schemas.openid.net/event/backchannel-logout")
        });
    if !carries_event {
        return Err(Unbrokered::Refused);
    }
    if claims.get("nonce").is_some() {
        return Err(Unbrokered::Refused);
    }
    let Some(subject) = text("sub").filter(|held| !held.is_empty()) else {
        tracing::warn!(
            "an upstream logout token names only a session, which this realm never learned"
        );
        return Err(Unbrokered::Refused);
    };
    Ok(Dismissal {
        external_user_id: subject.to_owned(),
    })
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
