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
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    /// Space separated: `openid` for OpenID Connect unless the operator said
    /// more, nothing for plain OAuth 2.0.
    pub scope: String,
    pub token_auth: TokenAuth,
    /// Whether the departure carries a PKCE challenge: on, unless the operator
    /// turned it off for a provider that mishandles it.
    pub pkce: bool,
    pub identity: Identity,
}

/// How this server proves itself at the upstream's token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuth {
    /// The client id and secret in a Basic authorization header.
    Basic,
    /// The client id and secret as form fields.
    Post,
}

/// How the upstream says who arrived.
#[derive(Debug, Clone)]
pub enum Identity {
    /// OpenID Connect: an identity token signed with the provider's keys.
    Signed(SignedIdentity),
    /// Plain OAuth 2.0: the provider's account API, asked with the access token.
    Asked(AccountApi),
}

#[derive(Debug, Clone)]
pub struct SignedIdentity {
    pub issuer: String,
    pub jwks_uri: String,
    /// The algorithms an upstream token may be signed with. Bounded by
    /// configuration, never by the token's own header.
    pub allowed_algs: Vec<SignAlg>,
}

/// Where a plain OAuth 2.0 provider says who holds an access token, and the
/// JSON pointers into its answer that say it.
#[derive(Debug, Clone)]
pub struct AccountApi {
    pub userinfo_endpoint: String,
    /// An identifier the provider gives no one else and never changes: a
    /// number or an opaque id, never a login a person can rename.
    pub subject: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<String>,
    pub emails: Option<EmailList>,
}

/// A second call listing the account's addresses, for a provider that marks
/// only there which one is verified.
#[derive(Debug, Clone)]
pub struct EmailList {
    pub endpoint: String,
    pub list: String,
    pub address: String,
    pub verified: String,
    pub primary: String,
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
    #[error("no protocol answers to {0}")]
    UnknownProtocol(String),
    #[error("no token endpoint authentication answers to {0}")]
    UnknownTokenAuth(String),
    #[error("{0} is not a JSON pointer")]
    NotAPointer(&'static str),
}

pub(crate) fn text<'a>(bag: &'a AttributesMap, key: &str) -> Option<&'a str> {
    bag.get(key).and_then(AttributeValue::as_str)
}

/// An endpoint an operator may point at: https, or loopback for a bench.
fn addressed(bag: &AttributesMap, key: &'static str) -> Result<String, Unusable> {
    let given = text(bag, key).ok_or(Unusable::Missing(key))?;
    if !commons::address::is_https_or_loopback(given) {
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
        let identity = match text(bag, "protocol").unwrap_or("oidc") {
            "oidc" => Identity::Signed(SignedIdentity::parse(bag)?),
            "oauth2" => Identity::Asked(AccountApi::parse(bag)?),
            other => return Err(Unusable::UnknownProtocol(other.to_owned())),
        };
        let token_auth = match text(bag, "token_auth").unwrap_or("client_secret_basic") {
            "client_secret_basic" => TokenAuth::Basic,
            "client_secret_post" => TokenAuth::Post,
            other => return Err(Unusable::UnknownTokenAuth(other.to_owned())),
        };
        let unsaid_scope = match identity {
            Identity::Signed(_) => "openid",
            Identity::Asked(_) => "",
        };
        Ok(Self {
            authorization_endpoint: addressed(bag, "authorization_endpoint")?,
            token_endpoint: addressed(bag, "token_endpoint")?,
            client_id: text(bag, "client_id")
                .ok_or(Unusable::Missing("client_id"))?
                .to_owned(),
            scope: text(bag, "scope").unwrap_or(unsaid_scope).to_owned(),
            token_auth,
            pkce: !matches!(bag.get("pkce"), Some(AttributeValue::Bool(false)))
                && text(bag, "pkce") != Some("false"),
            identity,
        })
    }
}

impl SignedIdentity {
    fn parse(bag: &AttributesMap) -> Result<Self, Unusable> {
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
            jwks_uri: addressed(bag, "jwks_uri")?,
            allowed_algs,
        })
    }
}

impl AccountApi {
    fn parse(bag: &AttributesMap) -> Result<Self, Unusable> {
        let emails = match text(bag, "emails_endpoint") {
            None => None,
            Some(_) => Some(EmailList {
                endpoint: addressed(bag, "emails_endpoint")?,
                list: pointer(bag, "emails_list_pointer")?.unwrap_or_default(),
                address: pointer(bag, "emails_address_pointer")?
                    .unwrap_or_else(|| "/email".to_owned()),
                verified: pointer(bag, "emails_verified_pointer")?
                    .unwrap_or_else(|| "/verified".to_owned()),
                primary: pointer(bag, "emails_primary_pointer")?
                    .unwrap_or_else(|| "/primary".to_owned()),
            }),
        };
        Ok(Self {
            userinfo_endpoint: addressed(bag, "userinfo_endpoint")?,
            subject: pointer(bag, "subject_pointer")?
                .ok_or(Unusable::Missing("subject_pointer"))?,
            username: pointer(bag, "username_pointer")?,
            email: pointer(bag, "email_pointer")?,
            email_verified: pointer(bag, "email_verified_pointer")?,
            emails,
        })
    }
}

/// A JSON pointer the operator named, when they named one: `/` first, or it is
/// refused rather than read as a field name.
fn pointer(bag: &AttributesMap, key: &'static str) -> Result<Option<String>, Unusable> {
    match text(bag, key).filter(|given| !given.is_empty()) {
        None => Ok(None),
        Some(given) if given.starts_with('/') => Ok(Some(given.to_owned())),
        Some(_) => Err(Unusable::NotAPointer(key)),
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

    let mut location = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&state={}",
        upstream.authorization_endpoint,
        encoded(&upstream.client_id),
        encoded(redirect_uri),
        encoded(&state),
    );
    if !upstream.scope.is_empty() {
        location.push_str(&format!("&scope={}", encoded(&upstream.scope)));
    }
    // A nonce is for an identity token to echo, and a plain OAuth 2.0 answer
    // carries none.
    if matches!(upstream.identity, Identity::Signed(_)) {
        location.push_str(&format!("&nonce={}", encoded(&nonce)));
    }
    if upstream.pkce {
        location.push_str(&format!(
            "&code_challenge={}&code_challenge_method=S256",
            encoded(&challenge)
        ));
    }
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
    let Identity::Signed(signed) = &upstream.identity else {
        return Err(Unbrokered::Refused);
    };
    let claims = crate::assertion::read_against(keys, id_token, &signed.allowed_algs)
        .map_err(|_| Unbrokered::Refused)?;

    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    if text("iss") != Some(signed.issuer.as_str()) {
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

/// What redeems a code at the upstream's token endpoint.
pub struct CodeExchange {
    pub form: Vec<(String, String)>,
    /// The client id and secret, when they travel in a Basic header.
    pub basic: Option<(String, String)>,
}

/// The code exchange for this upstream: the verifier only when the departure
/// carried its challenge, and the secret where the provider reads it.
pub fn compose_code_exchange(
    upstream: &Upstream,
    code: String,
    redirect_uri: String,
    verifier: &str,
    secret: Option<String>,
) -> CodeExchange {
    let mut form = vec![
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), code),
        ("redirect_uri".to_owned(), redirect_uri),
    ];
    if upstream.pkce {
        form.push(("code_verifier".to_owned(), verifier.to_owned()));
    }
    let basic = match (upstream.token_auth, secret) {
        (TokenAuth::Basic, Some(held)) => Some((upstream.client_id.clone(), held)),
        (TokenAuth::Post, Some(held)) => {
            form.push(("client_id".to_owned(), upstream.client_id.clone()));
            form.push(("client_secret".to_owned(), held));
            None
        }
        (_, None) => {
            form.push(("client_id".to_owned(), upstream.client_id.clone()));
            None
        }
    };
    CodeExchange { form, basic }
}

/// The token endpoint's answer as fields: JSON as the standard asks, or the
/// form encoding a provider answers with when it is not told otherwise.
pub fn read_token_answer(body: &str) -> Option<Map<String, Value>> {
    if let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(body) {
        return Some(fields);
    }
    let fields: Map<String, Value> = url::form_urlencoded::parse(body.trim().as_bytes())
        .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
        .collect();
    (!fields.is_empty()).then_some(fields)
}

/// Who a plain OAuth 2.0 provider says holds the access token, read from its
/// account answer, and from its list of addresses when it keeps one.
///
/// The subject is the provider's own identifier for the account, a string or
/// a number. An address counts as verified only when the list marks it both
/// primary and verified, or when the account answer says so where named.
pub fn answered_by_account(
    api: &AccountApi,
    account: &Value,
    listed: Option<&Value>,
) -> Result<Arrival, Unbrokered> {
    let Value::Object(claims) = account else {
        return Err(Unbrokered::Refused);
    };
    let external_user_id = match account.pointer(&api.subject) {
        Some(Value::String(held)) if !held.is_empty() => held.clone(),
        Some(Value::Number(held)) => held.to_string(),
        _ => return Err(Unbrokered::Refused),
    };
    let named = |at: &Option<String>| {
        at.as_deref()
            .and_then(|at| account.pointer(at))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let (email, email_verified) = match (&api.emails, listed) {
        (Some(list), Some(listed)) => primary_verified_address(list, listed),
        _ => (
            named(&api.email),
            api.email_verified
                .as_deref()
                .and_then(|at| account.pointer(at))
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
    };
    Ok(Arrival {
        external_user_id,
        username: named(&api.username),
        email,
        email_verified,
        claims: claims.clone(),
    })
}

/// The address a list marks both primary and verified, when one is.
fn primary_verified_address(list: &EmailList, listed: &Value) -> (Option<String>, bool) {
    let marked = |entry: &Value, at: &str| entry.pointer(at).and_then(Value::as_bool) == Some(true);
    let chosen = listed
        .pointer(&list.list)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|entry| marked(entry, &list.primary) && marked(entry, &list.verified))
        .and_then(|entry| entry.pointer(&list.address))
        .and_then(Value::as_str);
    match chosen {
        Some(address) => (Some(address.to_owned()), true),
        None => (None, false),
    }
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
    crypto: &dyn crypto::provider::CryptoProvider,
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
        user_name: None,
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
        crypto,
        tenant,
        realm_id,
        &format!("broker:{}", provider.provider_id),
        &named,
        &spec,
    )
    .await
    .map_err(|why| match why {
        // A store that could not write is not a refusal the person should hear.
        crate::admin::users::Uncreatable::Unwritable => Unbrokered::Backend,
        _ => Unbrokered::Refused,
    })?;
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
                // A role that would put the person in breach of a separation
                // is withheld and the sign-in goes on: the rule is the
                // operator's to mend, as a role deleted since is.
                match crate::sod::weigh_grant(transaction, user_id, role_id).await {
                    Ok(()) => {}
                    Err(crate::sod::Toxic::Refused(said)) => {
                        tracing::warn!(rule = %rule.name, role_id, %said, "an idp mapper's role was withheld: separation of duties");
                        continue;
                    }
                    Err(crate::sod::Toxic::Backend) => return Err(Unbrokered::Backend),
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
        None,
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
    /// The token's own identifier, for the replay guard at the door.
    pub jti: String,
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
    let Identity::Signed(signed) = &upstream.identity else {
        return Err(Unbrokered::Refused);
    };
    let claims = crate::assertion::read_against(keys, logout_token, &signed.allowed_algs)
        .map_err(|_| Unbrokered::Refused)?;

    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    if text("iss") != Some(signed.issuer.as_str()) {
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
    // §2.4: the identifier is required, and it is what the replay guard
    // remembers.
    let Some(jti) = text("jti").filter(|held| !held.is_empty()) else {
        return Err(Unbrokered::Refused);
    };
    Ok(Dismissal {
        external_user_id: subject.to_owned(),
        jti: jti.to_owned(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use models::auditable::AuditableModel;
    use models::entities::authz::IdentityProviderMutationModel;

    const ENDPOINTS: [&str; 3] = ["authorization_endpoint", "token_endpoint", "jwks_uri"];

    fn provider_with(endpoint: &str, address: &str) -> IdentityProviderModel {
        let mut configs: AttributesMap = [
            ("issuer", "https://idp.example"),
            ("client_id", "saffui"),
            ("authorization_endpoint", "https://idp.example/auth"),
            ("token_endpoint", "https://idp.example/token"),
            ("jwks_uri", "https://idp.example/certs"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), AttributeValue::Str(value.to_owned())))
        .collect();
        configs.insert(endpoint.to_owned(), AttributeValue::Str(address.to_owned()));
        IdentityProviderMutationModel {
            provider_id: "upstream".into(),
            name: "upstream".into(),
            display_name: "Upstream".into(),
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

    /// Every endpoint is dialled over https, or in clear only on this machine:
    /// never on a host that merely begins like loopback, or hides behind one.
    #[test]
    fn plain_http_reaches_only_a_loopback_upstream() {
        for endpoint in ENDPOINTS {
            for accepted in [
                "https://idp.example",
                "http://localhost:8080/x",
                "http://127.0.0.1:3000",
                "http://[::1]:8080/",
            ] {
                let parsed = Upstream::parse(&provider_with(endpoint, accepted));
                assert!(parsed.is_ok(), "{endpoint} at {accepted} was refused");
            }
            for refused in [
                "http://localhost.evil.example/token",
                "http://127.0.0.1.evil.example/token",
                "http://localhost@evil.example/token",
                "http://localhost:8080@evil.example/token",
                "http://[::1].evil.example/token",
                "http://idp.example",
                "https://",
                "javascript:alert(1)",
            ] {
                let parsed = Upstream::parse(&provider_with(endpoint, refused));
                assert!(
                    matches!(parsed, Err(Unusable::Insecure(named)) if named == endpoint),
                    "{endpoint} at {refused} was not refused as insecure: {parsed:?}"
                );
            }
        }
    }

    fn plain_provider(said: &[(&str, &str)]) -> IdentityProviderModel {
        let configs: AttributesMap = [
            ("protocol", "oauth2"),
            ("client_id", "saffui"),
            (
                "authorization_endpoint",
                "https://git.example/login/oauth/authorize",
            ),
            (
                "token_endpoint",
                "https://git.example/login/oauth/access_token",
            ),
            ("userinfo_endpoint", "https://api.git.example/user"),
            ("subject_pointer", "/id"),
        ]
        .iter()
        .chain(said.iter())
        .map(|(key, value)| ((*key).to_owned(), AttributeValue::Str((*value).to_owned())))
        .collect();
        IdentityProviderMutationModel {
            provider_id: "git".into(),
            name: "git".into(),
            display_name: "Git".into(),
            description: String::new(),
            enabled: Some(true),
            trust_email: Some(false),
            configs: Some(configs),
        }
        .into_model(
            "idp-2".into(),
            "main".into(),
            AuditableModel::from_creator("local".into(), "root".into()),
        )
    }

    fn account_api(said: &[(&str, &str)]) -> AccountApi {
        match Upstream::parse(&plain_provider(said))
            .expect("a plain provider")
            .identity
        {
            Identity::Asked(api) => api,
            Identity::Signed(_) => panic!("a plain provider read as OpenID Connect"),
        }
    }

    /// A plain OAuth 2.0 provider is read with its own fields and knobs, and
    /// refused, naming the field, when one cannot be used.
    #[test]
    fn a_plain_oauth2_provider_names_its_account_api() {
        let upstream = Upstream::parse(&plain_provider(&[])).expect("a plain provider");
        assert_eq!(upstream.token_auth, TokenAuth::Basic);
        assert!(upstream.pkce);
        assert_eq!(upstream.scope, "");
        let api = account_api(&[]);
        assert_eq!(api.subject, "/id");
        assert!(api.emails.is_none());

        let tuned = Upstream::parse(&plain_provider(&[
            ("token_auth", "client_secret_post"),
            ("pkce", "false"),
        ]))
        .expect("a tuned provider");
        assert_eq!(tuned.token_auth, TokenAuth::Post);
        assert!(!tuned.pkce);
        let listed = account_api(&[("emails_endpoint", "https://api.git.example/user/emails")]);
        let list = listed.emails.expect("an address list");
        assert_eq!(
            (
                list.list.as_str(),
                list.address.as_str(),
                list.verified.as_str(),
                list.primary.as_str()
            ),
            ("", "/email", "/verified", "/primary")
        );

        for (said, refusal) in [
            (
                ("subject_pointer", ""),
                "the provider names no subject_pointer",
            ),
            (
                ("subject_pointer", "id"),
                "subject_pointer is not a JSON pointer",
            ),
            (
                ("userinfo_endpoint", "http://api.git.example/user"),
                "userinfo_endpoint is not an https address",
            ),
            (("protocol", "saml"), "no protocol answers to saml"),
            (
                ("token_auth", "private_key_jwt"),
                "no token endpoint authentication answers to private_key_jwt",
            ),
        ] {
            let refused = Upstream::parse(&plain_provider(&[said])).expect_err("a refusal");
            assert_eq!(refused.to_string(), refusal);
        }
    }

    /// The token endpoint's answer is read as JSON, or as the form encoding a
    /// provider answers with by default.
    #[test]
    fn the_token_answer_is_read_in_either_encoding() {
        let json = read_token_answer(r#"{"access_token":"gho_abc","token_type":"bearer"}"#)
            .expect("a JSON answer");
        assert_eq!(json["access_token"], "gho_abc");
        let form = read_token_answer("access_token=gho_abc&scope=read%3Auser&token_type=bearer")
            .expect("a form answer");
        assert_eq!(form["access_token"], "gho_abc");
        assert_eq!(form["scope"], "read:user");
        assert!(read_token_answer("").is_none());
    }

    /// The code is redeemed with the verifier only when the departure carried
    /// a challenge, and with the secret where the provider reads it.
    #[test]
    fn the_code_exchange_carries_the_verifier_and_the_secret_where_told() {
        let exchanged = |said: &[(&str, &str)], secret: Option<&str>| {
            let upstream = Upstream::parse(&plain_provider(said)).expect("a plain provider");
            compose_code_exchange(
                &upstream,
                "the-code".into(),
                "https://id.example/landing".into(),
                "the-verifier",
                secret.map(str::to_owned),
            )
        };
        let field = |exchange: &CodeExchange, key: &str| {
            exchange
                .form
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
        };

        let basic = exchanged(&[], Some("s3cret"));
        assert_eq!(field(&basic, "code").as_deref(), Some("the-code"));
        assert_eq!(
            field(&basic, "code_verifier").as_deref(),
            Some("the-verifier")
        );
        assert_eq!(
            basic.basic,
            Some(("saffui".to_owned(), "s3cret".to_owned()))
        );
        assert!(field(&basic, "client_secret").is_none());

        let posted = exchanged(
            &[("token_auth", "client_secret_post"), ("pkce", "false")],
            Some("s3cret"),
        );
        assert!(field(&posted, "code_verifier").is_none());
        assert!(posted.basic.is_none());
        assert_eq!(field(&posted, "client_id").as_deref(), Some("saffui"));
        assert_eq!(field(&posted, "client_secret").as_deref(), Some("s3cret"));

        let unheld = exchanged(&[], None);
        assert!(unheld.basic.is_none());
        assert_eq!(field(&unheld, "client_id").as_deref(), Some("saffui"));
        assert!(field(&unheld, "client_secret").is_none());
    }

    /// An account answer names the arrival by the provider's stable subject,
    /// and an address counts as verified only when the list says so.
    #[test]
    fn an_account_answer_names_the_arrival_by_its_stable_subject() {
        let api = account_api(&[
            ("username_pointer", "/login"),
            ("email_pointer", "/email"),
            ("emails_endpoint", "https://api.git.example/user/emails"),
        ]);
        let account = serde_json::json!({ "id": 583231, "login": "octocat", "email": "public@octocat.example" });
        let listed = serde_json::json!([
            { "email": "old@octocat.example", "primary": false, "verified": true },
            { "email": "main@octocat.example", "primary": true, "verified": true },
        ]);
        let arrival = answered_by_account(&api, &account, Some(&listed)).expect("an arrival");
        assert_eq!(arrival.external_user_id, "583231");
        assert_eq!(arrival.username.as_deref(), Some("octocat"));
        assert_eq!(arrival.email.as_deref(), Some("main@octocat.example"));
        assert!(arrival.email_verified);
        assert_eq!(arrival.claims["login"], "octocat");

        let unverified = serde_json::json!([
            { "email": "main@octocat.example", "primary": true, "verified": false },
        ]);
        let arrival = answered_by_account(&api, &account, Some(&unverified)).expect("an arrival");
        assert_eq!((arrival.email, arrival.email_verified), (None, false));

        for nobody in [
            serde_json::json!({ "login": "octocat" }),
            serde_json::json!({ "id": { "nested": 1 } }),
            serde_json::json!(["not", "an", "account"]),
        ] {
            assert!(
                answered_by_account(&api, &nobody, Some(&listed)).is_err(),
                "{nobody}"
            );
        }
    }

    /// Nested pointers read an account the provider wraps, and an address the
    /// answer does not say is verified is not.
    #[test]
    fn nested_pointers_read_a_wrapped_account() {
        let api = account_api(&[
            ("subject_pointer", "/data/id"),
            ("username_pointer", "/data/username"),
            ("email_pointer", "/data/email"),
            ("email_verified_pointer", "/data/email_verified"),
        ]);
        let account = serde_json::json!({ "data": {
            "id": "2244994945", "username": "xdevelopers",
            "email": "dev@x.example", "email_verified": true,
        } });
        let arrival = answered_by_account(&api, &account, None).expect("an arrival");
        assert_eq!(arrival.external_user_id, "2244994945");
        assert_eq!(arrival.username.as_deref(), Some("xdevelopers"));
        assert_eq!(arrival.email.as_deref(), Some("dev@x.example"));
        assert!(arrival.email_verified);
        let unsaid =
            serde_json::json!({ "data": { "id": "2244994945", "email": "dev@x.example" } });
        assert!(
            !answered_by_account(&api, &unsaid, None)
                .expect("an arrival")
                .email_verified
        );
    }
}
