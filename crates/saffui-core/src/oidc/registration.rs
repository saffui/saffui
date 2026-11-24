//! Registration of a client through the protocol (RFC 7591), and the
//! management of what was registered (RFC 7592). Closed unless the realm
//! opens it. A client registered so asks each person before it acts in
//! their name, holds no capability, and is managed with a token that serves
//! once and is replaced by the next at each use. A request is counted
//! against its caller, and refused what costs nothing to refuse, before any
//! key of it is checked.

use std::net::IpAddr;

use serde_json::{Value, json};
use time::Duration;
use uuid::Uuid;

use super::discovery::name_issuer;
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::admin::AdminCaller;
use crate::authz::roles::describe_actor;
use crate::clients::authenticate::is_current_secret;
use crate::clients::metadata::{WantedMetadata, judge_wanted_metadata, read_client_metadata};
use crate::clients::register::{
    CheckedClient, ClientChecker, NewClient, check_new_client, insert_checked_client,
    rewrite_client,
};
use crate::clients::registration::{draw_bearer_token, draw_client_identifier};
use crate::clients::store::RegistrationCounts;
use crate::clients::{
    Client, ClientAuthMethod, check_client_identifier, read_client_keys, read_redirect_host,
};
use crate::error::{ErrorCode, ErrorKind, Failure};
use crate::keys::rotate::list_active_algorithms;
use crate::login::throttle::{admit_client_change, admit_registration, admit_registration_change};
use crate::ports::storage::{StorageError, UnitOfWork};
use crate::secret::Secret;
use crate::tenancy::resolve::resolve_realm;
use crate::tenancy::settings::{
    RealmSettings, RegistrationPolicy, check_registration_budget, check_registration_quota,
    read_settings_closed,
};
use crate::tenancy::{RealmName, RealmScope};

/// How many of the families, and of the offline sessions, the end of a
/// registration took back its event names: the rest are counted.
const MOST_NAMED_FAMILIES: u32 = 100;

/// The day of the budget of registrations of a realm.
const REGISTRATION_DAY: Duration = Duration::days(1);

/// The dialect of the registration endpoints (RFC 7591, section 3.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationError {
    InvalidRedirectUri,
    InvalidClientMetadata,
    InvalidSoftwareStatement,
    /// A token missing, unknown, spent or expired, or a client the token
    /// does not manage (RFC 6750 and RFC 7592, section 2).
    InvalidToken,
    AccessDenied,
    ServerError,
    TemporarilyUnavailable,
}

impl RegistrationError {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidClientMetadata => "invalid_client_metadata",
            Self::InvalidSoftwareStatement => "invalid_software_statement",
            Self::InvalidToken => "invalid_token",
            Self::AccessDenied => "access_denied",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

/// A refusal of the registration endpoints, and the refusal of the catalog
/// behind it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationFailure {
    pub error: RegistrationError,
    pub cause: Failure,
}

impl From<Failure> for RegistrationFailure {
    fn from(cause: Failure) -> Self {
        let error = match cause.code {
            ErrorCode::RedirectUriInvalid => RegistrationError::InvalidRedirectUri,
            ErrorCode::SoftwareStatementRefused => RegistrationError::InvalidSoftwareStatement,
            // A realm or a client that does not exist answers as a token
            // nobody handed out.
            ErrorCode::RealmNotFound | ErrorCode::ClientNotFound => RegistrationError::InvalidToken,
            other => match other.kind() {
                ErrorKind::Unauthenticated => RegistrationError::InvalidToken,
                ErrorKind::Forbidden => RegistrationError::AccessDenied,
                ErrorKind::Unavailable => RegistrationError::TemporarilyUnavailable,
                ErrorKind::Internal | ErrorKind::Conflict => RegistrationError::ServerError,
                ErrorKind::Invalid | ErrorKind::NotFound => {
                    RegistrationError::InvalidClientMetadata
                }
            },
        };
        Self { error, cause }
    }
}

impl From<ErrorCode> for RegistrationFailure {
    fn from(code: ErrorCode) -> Self {
        Failure::new(code).into()
    }
}

impl From<StorageError> for RegistrationFailure {
    fn from(error: StorageError) -> Self {
        Failure::from(error).into()
    }
}

/// What a request to register a client, or to change a registration,
/// carried, as the endpoint read it.
pub struct RegistrationRequest<'a> {
    /// Where it comes from, for the brake. Unknown, nothing is counted.
    pub caller: Option<IpAddr>,
    /// Its bearer token: an initial access token at a registration, the
    /// token of the registration at a change.
    pub token: Option<&'a str>,
    /// Its body, unread: no member of it is read before the request is
    /// counted, and its token spent at a registration or proven at a
    /// change, where it is replaced with what the change writes.
    pub body: &'a [u8],
}

/// What the endpoints say of a registered client (RFC 7591, section 3.2.1):
/// its metadata as registered, where it is managed, the token that manages
/// it next, and its secret the one time it is shown.
// No `Debug`: it carries a token, and a secret once.
pub struct RegistrationAnswer(Value);

impl RegistrationAnswer {
    #[must_use]
    pub fn into_document(self) -> Value {
        self.0
    }
}

/// Checks that a request that carries metadata says it is JSON, as RFC
/// 7591, section 3.1, sends it: a page of another site posts a form or
/// text without asking the browser first, never JSON. A parameter such as
/// a charset is allowed.
///
/// # Errors
///
/// Returns [`RegistrationError::InvalidClientMetadata`].
pub fn check_metadata_media_type(content_type: Option<&str>) -> Result<(), RegistrationFailure> {
    let essence = content_type
        .and_then(|written| written.split(';').next())
        .unwrap_or_default()
        .trim();
    if essence.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(Failure::with_detail(ErrorCode::ClientMetadataInvalid, "not application/json").into())
    }
}

/// Reads a body as JSON. A body that is not is metadata that cannot be read.
fn read_document(body: &[u8]) -> Result<Value, Failure> {
    serde_json::from_slice(body)
        .map_err(|_| Failure::with_detail(ErrorCode::ClientMetadataInvalid, "not JSON"))
}

/// Checks that a realm under `settings` takes one more registration: below
/// its bound of clients, and of registrations in a day.
fn check_registration_room(
    counts: RegistrationCounts,
    settings: &RealmSettings,
) -> Result<(), Failure> {
    check_registration_quota(counts.registered, settings)?;
    check_registration_budget(counts.since, settings)
}

/// Lets a request to register in, or refuses it, in a first unit of work
/// committed before anything of the request is read: closed, never; past
/// what its caller may register, never. A first look at the bounds of the
/// realm follows, so that a full realm costs no key: the counts taken under
/// the row of the settings are the ones that hold. The initial access token
/// a request must present is spent then, a use being a use whatever the
/// metadata say; a realm without room spends none, and only says whether
/// the token lives. The count of the caller is kept whatever is refused.
/// Returns the policy that let it in, and the token it spent.
async fn admit_registration_request(
    app: &App,
    scope: RealmScope,
    request: &RegistrationRequest<'_>,
) -> Result<(RegistrationPolicy, Option<Uuid>), Failure> {
    let mut work = app.storage.begin(scope).await?;
    let settings = read_settings_closed(work.read_realm_settings().await?);
    let asks_initial_token = match settings.registration {
        RegistrationPolicy::Closed => return Err(Failure::new(ErrorCode::RegistrationClosed)),
        RegistrationPolicy::InitialToken => true,
        RegistrationPolicy::Open => false,
    };
    admit_registration(app, work.as_mut(), request.caller).await?;
    let now = app.now();
    let room = check_registration_room(
        work.count_registrations(now - REGISTRATION_DAY).await?,
        &settings,
    );
    let initial_token = if asks_initial_token {
        let digest = request
            .token
            .map(|token| app.digester.sha256(token.as_bytes()));
        let held = match (&digest, &room) {
            (None, _) => None,
            (Some(digest), Ok(())) => work.spend_initial_access_token(digest, now).await?,
            (Some(digest), Err(_)) => work.find_live_initial_access_token(digest, now).await?,
        };
        if held.is_none() {
            work.commit().await?;
            return Err(Failure::new(ErrorCode::RegistrationTokenInvalid));
        }
        held
    } else {
        None
    };
    work.commit().await?;
    room?;
    Ok((settings.registration, initial_token))
}

/// A first look at the algorithm of the identity tokens of a client whose
/// keys are to be checked, so that one the realm cannot sign in costs no
/// check: the look taken where the client is written is the one that holds.
/// A client without keys costs nothing more, and is looked at there alone.
async fn look_at_id_token_algorithm(
    app: &App,
    scope: RealmScope,
    wanted: &WantedMetadata,
) -> Result<(), Failure> {
    if wanted.jwks.is_none() {
        return Ok(());
    }
    let keys = app
        .storage
        .begin_snapshot(scope)
        .await?
        .list_signing_keys()
        .await?;
    if list_active_algorithms(app.signer.as_ref(), &keys).contains(&wanted.id_token_alg) {
        Ok(())
    } else {
        Err(Failure::new(ErrorCode::KeyAlgorithmUnavailable))
    }
}

/// Checks what a client asks of its registration as any client is checked,
/// by [`check_new_client`]: its addresses, name, method, keys with the share
/// of the realm, and algorithms. Registered by anyone the realm let in, it
/// asks each person before it acts in their name, and holds no capability.
/// Its scopes are judged on the settings held where it is written.
async fn check_registered_metadata<'a>(
    app: &App,
    scope: RealmScope,
    client_id: &'a str,
    wanted: &'a WantedMetadata,
) -> Result<CheckedClient<'a>, Failure> {
    let wanted = NewClient {
        client_id,
        name: wanted.name.as_deref().unwrap_or(client_id),
        scopes: &[],
        capabilities: &[],
        redirect_uris: &wanted.redirect_uris,
        post_logout_redirect_uris: &wanted.post_logout_redirect_uris,
        public: wanted.method == ClientAuthMethod::None,
        requires_consent: true,
        id_token_signed_response_alg: Some(wanted.id_token_alg),
        auth_method: Some(wanted.method),
        jwks: wanted.jwks.as_ref(),
        jwks_uri: None,
        auth_signing_alg: wanted.signing,
        created_by: None,
    };
    check_new_client(app, ClientChecker::Registration(scope.realm()), wanted).await
}

/// Registers a client through the protocol, as the realm allows: never when
/// it is closed, with an initial access token when it asks for one. The
/// request is counted against its caller first, its token is spent next,
/// and only then is its body read.
///
/// # Errors
///
/// Returns the refusal in the words of RFC 7591, with the refusal of the
/// catalog behind it.
pub async fn register_dynamic_client(
    app: &App,
    realm: &str,
    request: RegistrationRequest<'_>,
) -> Result<RegistrationAnswer, RegistrationFailure> {
    let (realm_name, scope) = resolve_realm(app, realm).await?;
    let (policy, initial_token) = admit_registration_request(app, scope, &request).await?;

    let wanted = read_client_metadata(&read_document(request.body)?)?;
    look_at_id_token_algorithm(app, scope, &wanted).await?;
    let client_id = draw_client_identifier(app)?;
    let checked = check_registered_metadata(app, scope, &client_id, &wanted).await?;
    let keys = checked.kept_keys().cloned();
    let (token, token_digest) = draw_bearer_token(app)?;

    let mut work = app.storage.begin(scope).await?;
    // Counted under the row of the settings: two registrations of the realm
    // count one after the other, and a change of the settings waits.
    let held = read_settings_closed(work.read_realm_settings_for_update().await?);
    // Changed since the request was let in: it was let in under another rule.
    if held.registration != policy {
        return Err(ErrorCode::RegistrationClosed.into());
    }
    let now = app.now();
    check_registration_room(
        work.count_registrations(now - REGISTRATION_DAY).await?,
        &held,
    )?;
    let scopes = judge_wanted_metadata(&wanted, &held)?;
    let (client, secret, mut told) =
        insert_checked_client(app, work.as_mut(), checked.with_scopes(&scopes)?).await?;
    work.insert_client_registration(&client.client_id, &token_digest, now)
        .await?;
    told["actor"] = match initial_token {
        Some(token_id) => json!({ "initial_token_id": token_id.to_string() }),
        None => json!({ "client_id": client.client_id }),
    };
    record_event(app, work.as_mut(), EventKind::ClientRegistered, told).await?;
    work.commit().await?;
    Ok(describe_registered_client(
        app,
        &realm_name,
        &client,
        secret.as_ref(),
        keys.as_ref(),
        &token,
    ))
}

/// The digest of the token a request presents to manage `client_id`. What
/// is not written as a client identifier is managed by no token.
fn digest_presented_token(
    app: &App,
    client_id: &str,
    token: Option<&str>,
) -> Result<[u8; 32], Failure> {
    let refused = || Failure::new(ErrorCode::RegistrationTokenInvalid);
    check_client_identifier(client_id).map_err(|_| refused())?;
    let token = token.ok_or_else(refused)?;
    Ok(app.digester.sha256(token.as_bytes()))
}

/// Reads what was registered, with the token of the registration, and
/// returns it with the next token: the one presented is spent.
///
/// # Errors
///
/// Returns [`RegistrationError::InvalidToken`] for a token that does not
/// manage this client, whether the client exists or not, or the storage
/// failure.
pub async fn read_registered_client(
    app: &App,
    realm: &str,
    client_id: &str,
    token: Option<&str>,
) -> Result<RegistrationAnswer, RegistrationFailure> {
    let (realm_name, scope) = resolve_realm(app, realm).await?;
    let presented = digest_presented_token(app, client_id, token)?;
    let (next, next_digest) = draw_bearer_token(app)?;
    let mut work = app.storage.begin(scope).await?;
    if !work
        .rotate_registration_token(client_id, &presented, &next_digest)
        .await?
    {
        return Err(ErrorCode::RegistrationTokenInvalid.into());
    }
    let client = work
        .read_client(client_id)
        .await?
        .filter(|client| client.enabled)
        .ok_or(ErrorCode::RegistrationTokenInvalid)?;
    let keys = read_client_keys(work.as_mut(), &client).await?;
    work.commit().await?;
    Ok(describe_registered_client(
        app,
        &realm_name,
        &client,
        None,
        keys.as_ref(),
        &next,
    ))
}

/// Whether a change makes each person answer again for the client: it is
/// to be sent codes on a host they never allowed, or it proves itself with
/// other keys than those it held when they did.
fn is_consent_to_renew(
    kept: &Client,
    kept_keys: Option<&Value>,
    redirect_uris: &[String],
    keys: Option<&Value>,
) -> bool {
    let kept_hosts: Vec<&str> = kept
        .redirect_uris
        .iter()
        .map(|uri| read_redirect_host(uri))
        .collect();
    let adds_host = redirect_uris
        .iter()
        .any(|uri| !kept_hosts.contains(&read_redirect_host(uri)));
    adds_host || kept_keys != keys
}

/// Withdraws every consent a client was given, and takes back what it
/// holds in the name of each person, as a withdrawal does: its refresh
/// tokens are revoked and their offline sessions end. Returns what the
/// event says of it.
async fn withdraw_client_consents(
    app: &App,
    work: &mut dyn UnitOfWork,
    client_id: &str,
) -> Result<Value, Failure> {
    let withdrawn = work.delete_consents_of_client(client_id).await?;
    let mut told = revoke_client_grants(app, work, client_id).await?;
    told["consents_withdrawn"] = json!(withdrawn);
    Ok(told)
}

/// Revokes every refresh token a client holds, for whoever it is, and ends
/// the offline sessions they lived in. Returns what the event says of it,
/// bounded however many there were.
async fn revoke_client_grants(
    app: &App,
    work: &mut dyn UnitOfWork,
    client_id: &str,
) -> Result<Value, Failure> {
    let revoked = work
        .revoke_every_refresh_family_of_client(client_id, app.now(), MOST_NAMED_FAMILIES)
        .await?;
    let named: Vec<String> = revoked.named.iter().map(Uuid::to_string).collect();
    let offline: Vec<String> = revoked
        .named_offline_sessions
        .iter()
        .map(Uuid::to_string)
        .collect();
    Ok(json!({
        "offline_sessions": offline,
        "offline_sessions_ended": revoked.offline_sessions,
        "refresh_families": named,
        "refresh_families_revoked": revoked.families,
        "refresh_tokens_revoked": revoked.tokens,
    }))
}

/// Replaces what a registered client says of itself (RFC 7592, section
/// 2.2). The request names the client it changes, and a secret it presents
/// is the one the client keeps. It is counted against its caller and its
/// client before its body is read, and against the changes the realm takes
/// in a day from wherever they come once its body names the client: a body
/// that cannot be read spends nothing of the realm. It is judged by the
/// rule of a registration, on the settings held, and the client keeps its
/// identifier, its method and its secret. A realm closed since takes no
/// change. A change that is refused changes nothing, its token included.
///
/// # Errors
///
/// As [`read_registered_client`], [`RegistrationError::AccessDenied`] past
/// the changes the client or the realm may make in a day, and the refusal
/// of the metadata.
pub async fn update_registered_client(
    app: &App,
    realm: &str,
    client_id: &str,
    request: RegistrationRequest<'_>,
) -> Result<RegistrationAnswer, RegistrationFailure> {
    let (realm_name, scope) = resolve_realm(app, realm).await?;
    let presented = digest_presented_token(app, client_id, request.token)?;
    let mut work = app.storage.begin(scope).await?;
    if !work
        .matches_registration_token(client_id, &presented)
        .await?
    {
        return Err(ErrorCode::RegistrationTokenInvalid.into());
    }
    admit_registration(app, work.as_mut(), request.caller).await?;
    admit_client_change(app, work.as_mut(), client_id).await?;
    work.commit().await?;

    let wanted = read_client_metadata(&read_document(request.body)?)?;
    if wanted.client_id.as_deref() != Some(client_id) {
        return Err(Failure::with_detail(ErrorCode::ClientMetadataInvalid, "client_id").into());
    }
    let mut counting = app.storage.begin(scope).await?;
    let settings = read_settings_closed(counting.read_realm_settings().await?);
    admit_registration_change(app, counting.as_mut(), settings.max_daily_registrations).await?;
    counting.commit().await?;
    look_at_id_token_algorithm(app, scope, &wanted).await?;
    let checked = check_registered_metadata(app, scope, client_id, &wanted).await?;
    let (next, next_digest) = draw_bearer_token(app)?;

    let mut work = app.storage.begin(scope).await?;
    if !work
        .rotate_registration_token(client_id, &presented, &next_digest)
        .await?
    {
        return Err(ErrorCode::RegistrationTokenInvalid.into());
    }
    // Read once, and shared until the commit: a change of the settings
    // waits, and so does a registration, while other changes do not.
    let held = read_settings_closed(work.read_realm_settings_for_share().await?);
    if held.registration == RegistrationPolicy::Closed {
        return Err(ErrorCode::RegistrationClosed.into());
    }
    let scopes = judge_wanted_metadata(&wanted, &held)?;
    // Taken until the commit: what is kept of the client is read once, under
    // its lock, and whether it is enabled is never written back.
    let kept = work
        .read_client_for_update(client_id)
        .await?
        .filter(|client| client.enabled)
        .ok_or(ErrorCode::RegistrationTokenInvalid)?;
    if let Some(secret) = &wanted.client_secret {
        let proof = work
            .read_client_with_proof(client_id)
            .await?
            .map(|(_, proof)| proof)
            .ok_or(ErrorCode::RegistrationTokenInvalid)?;
        if !is_current_secret(app, work.as_mut(), &kept, &proof, secret.expose()).await? {
            return Err(
                Failure::with_detail(ErrorCode::ClientMetadataInvalid, "client_secret").into(),
            );
        }
    }
    let kept_keys = read_client_keys(work.as_mut(), &kept).await?;
    let renewed = is_consent_to_renew(
        &kept,
        kept_keys.as_ref(),
        &wanted.redirect_uris,
        checked.kept_keys(),
    );
    let (client, keys) =
        rewrite_client(app, work.as_mut(), kept, checked.with_scopes(&scopes)?).await?;
    let mut told = json!({
        "actor": { "client_id": client_id },
        "client_id": client_id,
        "redirect_uris": client.redirect_uris,
        "scopes": client.scopes,
    });
    if renewed {
        told["consents_renewed"] = withdraw_client_consents(app, work.as_mut(), client_id).await?;
    }
    record_event(
        app,
        work.as_mut(),
        EventKind::ClientRegistrationUpdated,
        told,
    )
    .await?;
    work.commit().await?;
    Ok(describe_registered_client(
        app,
        &realm_name,
        &client,
        None,
        keys.as_ref(),
        &next,
    ))
}

/// What the end of a registration leaves of its client, once the
/// registration is ended in `work`: the client disabled, and every refresh
/// token it holds revoked with the offline sessions they lived in. A client
/// disabled already is refused with `refused`. Returns what the event says.
async fn end_registered_client(
    app: &App,
    work: &mut dyn UnitOfWork,
    client_id: &str,
    refused: ErrorCode,
) -> Result<Value, Failure> {
    if !work.disable_client(client_id).await? {
        return Err(Failure::new(refused));
    }
    let mut told = revoke_client_grants(app, work, client_id).await?;
    told["client_id"] = json!(client_id);
    Ok(told)
}

/// Ends a registration (RFC 7592, section 2.3): its token goes, its client
/// is disabled, and every refresh token the client holds is revoked with
/// the offline sessions they lived in, in one unit of work. It is counted
/// against its caller as a registration is, in a short unit of work of its
/// own committed first: a token refused is counted too, and the counters
/// are not held while the grants are taken back.
///
/// # Errors
///
/// As [`read_registered_client`], and
/// [`RegistrationError::TemporarilyUnavailable`] past what the caller may
/// register.
pub async fn delete_registered_client(
    app: &App,
    realm: &str,
    client_id: &str,
    caller: Option<IpAddr>,
    token: Option<&str>,
) -> Result<(), RegistrationFailure> {
    let (_, scope) = resolve_realm(app, realm).await?;
    let presented = digest_presented_token(app, client_id, token)?;
    if caller.is_some() {
        let mut counting = app.storage.begin(scope).await?;
        admit_registration(app, counting.as_mut(), caller).await?;
        counting.commit().await?;
    }
    let mut work = app.storage.begin(scope).await?;
    if !work
        .end_client_registration(client_id, &presented, app.now())
        .await?
    {
        return Err(ErrorCode::RegistrationTokenInvalid.into());
    }
    let mut told = end_registered_client(
        app,
        work.as_mut(),
        client_id,
        ErrorCode::RegistrationTokenInvalid,
    )
    .await?;
    told["actor"] = json!({ "client_id": client_id });
    record_event(
        app,
        work.as_mut(),
        EventKind::ClientRegistrationDeleted,
        told,
    )
    .await?;
    work.commit().await?;
    Ok(())
}

/// Ends the registration of a client, as an administrator of its realm, as
/// [`delete_registered_client`] ends it.
///
/// # Errors
///
/// Returns [`ErrorCode::RegistrationNotFound`] for a client that did not
/// register itself, or whose registration ended, or the storage failure.
pub async fn end_registration_as_administrator(
    app: &App,
    caller: &AdminCaller,
    client_id: &str,
) -> Result<(), Failure> {
    let refused = || Failure::new(ErrorCode::RegistrationNotFound);
    check_client_identifier(client_id).map_err(|_| refused())?;
    let mut work = app.storage.begin(caller.scope).await?;
    if !work
        .end_client_registration_as_administrator(client_id, app.now())
        .await?
    {
        return Err(refused());
    }
    let mut told = end_registered_client(
        app,
        work.as_mut(),
        client_id,
        ErrorCode::RegistrationNotFound,
    )
    .await?;
    told["actor"] = describe_actor(caller);
    record_event(
        app,
        work.as_mut(),
        EventKind::ClientRegistrationDeleted,
        told,
    )
    .await?;
    work.commit().await?;
    Ok(())
}

/// What the endpoints say of a registered client. A token or a secret was
/// drawn as base64url text: its bytes are its text.
fn describe_registered_client(
    app: &App,
    realm: &RealmName,
    client: &Client,
    client_secret: Option<&Secret>,
    keys: Option<&Value>,
    registration_access_token: &Secret,
) -> RegistrationAnswer {
    let issuer = name_issuer(&app.settings, realm);
    let as_text = |secret: &Secret| String::from_utf8_lossy(secret.expose()).into_owned();
    let mut described = json!({
        "client_id": client.client_id,
        "client_id_issued_at": client.created_at.unix_timestamp(),
        "client_name": client.name,
        "redirect_uris": client.redirect_uris,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": client.auth_method.name(),
        "scope": client.scopes.join(" "),
        "registration_client_uri": format!("{issuer}/oauth2/register/{}", client.client_id),
        "registration_access_token": as_text(registration_access_token),
    });
    if let Some(algorithm) = client.id_token_signed_response_alg {
        described["id_token_signed_response_alg"] = json!(algorithm.name());
    }
    if let Some(algorithm) = client.auth_signing_alg {
        described["token_endpoint_auth_signing_alg"] = json!(algorithm.name());
    }
    if let Some(keys) = keys {
        described["jwks"] = keys.clone();
    }
    if let Some(secret) = client_secret {
        described["client_secret"] = json!(as_text(secret));
        described["client_secret_expires_at"] = json!(0);
    }
    RegistrationAnswer(described)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::{Value, json};

    use super::{
        RegistrationError, RegistrationRequest, delete_registered_client, read_registered_client,
        register_dynamic_client, update_registered_client,
    };
    use crate::authz::admin::AdminCaller;
    use crate::authz::admin::authorize_admin_call;
    use crate::authz::capability::Capability;
    use crate::clients::authenticate::{PresentedProof, PresentedSecret};
    use crate::clients::registration::create_initial_access_token;
    use crate::error::ErrorCode;
    use crate::login::throttle::MAX_RECENT_REGISTRATIONS_PER_ADDRESS;
    use crate::oidc::authorize::{
        Authorization, AuthorizationParameters, AuthorizationRefusal, begin_authorization,
    };
    use crate::oidc::discovery::read_provider_metadata;
    use crate::oidc::errors::OAuthError;
    use crate::oidc::scenario::{CALLBACK, Scenario, VERIFIER};
    use crate::oidc::token::{TokenRequest, TokenResponse, grant_token};
    use crate::ports::crypto::SignatureAlgorithm;
    use crate::secret::Secret;
    use crate::tenancy::settings::{
        RealmSettings, RegistrationPolicy, WantedSettings, change_realm_settings,
    };
    use crate::testkit::crypto::WeakSigner;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::create_administrator;

    /// What an administrator writes to have `settings`, every bound named.
    fn want(settings: RealmSettings) -> WantedSettings {
        WantedSettings {
            registration: settings.registration,
            registrable_scopes: Some(settings.registrable_scopes),
            max_registered_clients: Some(settings.max_registered_clients),
            max_redirect_uris: Some(settings.max_redirect_uris),
            max_daily_registrations: Some(settings.max_daily_registrations),
        }
    }

    /// Opens `acme` to registration with these settings, and returns the
    /// administrator who did.
    fn open_with(scenario: &Scenario, settings: RealmSettings) -> AdminCaller {
        let operator = scenario.name_operator(&[Capability::RealmWrite, Capability::UserRead]);
        complete(change_realm_settings(
            &scenario.app,
            &operator,
            want(settings),
        ))
        .expect("settings");
        operator
    }

    /// An administrator of `acme` other than the one who opened it.
    fn name_administrator(
        scenario: &Scenario,
        client_id: &str,
        capabilities: &[Capability],
    ) -> AdminCaller {
        let token = complete(create_administrator(
            &scenario.app,
            "acme",
            scenario.scope,
            client_id,
            capabilities,
        ));
        complete(authorize_admin_call(
            &scenario.app,
            "acme",
            Some(&token),
            capabilities[0],
        ))
        .expect("an administrator")
    }

    fn open(scenario: &Scenario, policy: RegistrationPolicy) -> AdminCaller {
        open_with(
            scenario,
            RealmSettings {
                registration: policy,
                ..RealmSettings::default()
            },
        )
    }

    /// Registers, and tells a refusal with the refusal of the catalog behind
    /// it: closed, full and spent all answer `access_denied`.
    fn register_with_cause(
        scenario: &Scenario,
        caller: Option<IpAddr>,
        token: Option<&str>,
        body: &[u8],
    ) -> Result<Value, (RegistrationError, ErrorCode)> {
        let request = RegistrationRequest {
            caller,
            token,
            body,
        };
        complete(register_dynamic_client(&scenario.app, "acme", request))
            .map(super::RegistrationAnswer::into_document)
            .map_err(|failure| (failure.error, failure.cause.code))
    }

    fn register_as(
        scenario: &Scenario,
        caller: Option<IpAddr>,
        token: Option<&str>,
        body: &[u8],
    ) -> Result<Value, RegistrationError> {
        register_with_cause(scenario, caller, token, body).map_err(|(error, _)| error)
    }

    fn register(scenario: &Scenario, metadata: &Value) -> Result<Value, RegistrationError> {
        register_as(scenario, None, None, metadata.to_string().as_bytes())
    }

    fn read_as(
        scenario: &Scenario,
        client_id: &str,
        token: &str,
    ) -> Result<Value, RegistrationError> {
        complete(read_registered_client(
            &scenario.app,
            "acme",
            client_id,
            Some(token),
        ))
        .map(super::RegistrationAnswer::into_document)
        .map_err(|failure| failure.error)
    }

    fn update_as(
        scenario: &Scenario,
        client_id: &str,
        token: &str,
        metadata: &Value,
    ) -> Result<Value, RegistrationError> {
        let body = metadata.to_string();
        let request = RegistrationRequest {
            caller: None,
            token: Some(token),
            body: body.as_bytes(),
        };
        complete(update_registered_client(
            &scenario.app,
            "acme",
            client_id,
            request,
        ))
        .map(super::RegistrationAnswer::into_document)
        .map_err(|failure| failure.error)
    }

    fn text(document: &Value, name: &str) -> String {
        document[name].as_str().expect(name).to_owned()
    }

    fn read_client(scenario: &Scenario, client_id: &str) -> crate::clients::Client {
        let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
        complete(work.read_client(client_id))
            .expect("a read")
            .expect("the client")
    }

    /// The algorithm a compact token says it is signed in.
    fn read_algorithm(token: &str) -> String {
        let header = token.split('.').next().expect("a header");
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).expect("base64url"))
                .expect("JSON");
        text(&header, "alg")
    }

    /// Exchanges `code` as the confidential client `client_id`.
    fn exchange_with_secret(
        scenario: &Scenario,
        client_id: &str,
        secret: &str,
        code: &str,
    ) -> Result<TokenResponse, OAuthError> {
        let exchange = TokenRequest {
            grant_type: Some("authorization_code"),
            client_id: Some(client_id),
            client_secret: Some(PresentedSecret::Basic(Secret::new(
                secret.as_bytes().to_vec(),
            ))),
            code: Some(code),
            redirect_uri: Some(CALLBACK),
            code_verifier: Some(VERIFIER),
            ..TokenRequest::default()
        };
        complete(grant_token(&scenario.app, "acme", exchange)).map_err(|failure| failure.error)
    }

    #[test]
    fn a_realm_is_closed_to_registration_until_it_opens_and_only_then_says_where() {
        let scenario = Scenario::start();
        let metadata = json!({ "redirect_uris": [CALLBACK] }).to_string();
        assert_eq!(
            register_with_cause(&scenario, None, None, metadata.as_bytes()).map(|_| ()),
            Err((
                RegistrationError::AccessDenied,
                ErrorCode::RegistrationClosed
            ))
        );
        let closed = complete(read_provider_metadata(&scenario.app, "acme")).expect("a document");
        assert_eq!(closed.registration_endpoint, None);

        open(&scenario, RegistrationPolicy::Open);
        let opened = complete(read_provider_metadata(&scenario.app, "acme")).expect("a document");
        assert_eq!(
            opened.registration_endpoint.as_deref(),
            Some("https://id.example.test/realms/acme/oauth2/register")
        );
        let registered = register(
            &scenario,
            &json!({
                "redirect_uris": [CALLBACK],
                "client_name": "Registered",
                "logo_uri": "https://registered.example.org/logo.png",
            }),
        )
        .expect("a registered client");

        let client_id = text(&registered, "client_id");
        assert_eq!(
            registered["token_endpoint_auth_method"],
            "client_secret_basic"
        );
        assert_eq!(registered["id_token_signed_response_alg"], "RS256");
        assert_eq!(registered["scope"], "openid profile email");
        assert_eq!(
            registered["grant_types"],
            json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(registered["client_secret_expires_at"], 0);
        assert_eq!(
            registered["registration_client_uri"],
            format!("https://id.example.test/realms/acme/oauth2/register/{client_id}")
        );
        assert!(
            registered.get("logo_uri").is_none(),
            "what is not kept is not said"
        );
        let kept = read_client(&scenario, &client_id);
        assert!(kept.requires_consent, "anyone may have registered it");
        assert!(kept.self_registered);
        assert!(kept.capabilities.is_empty() && !kept.allows_client_credentials);
        let kinds = scenario.read_event_kinds();
        assert_eq!(
            kinds[kinds.len() - 2..],
            [
                "realm.settings_changed".to_owned(),
                "client.registered".to_owned()
            ],
            "one event for one registration"
        );
        let registered = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .next_back()
            .expect("an event");
        assert_eq!(registered["kind"], "client.registered");
        assert_eq!(
            registered["payload"],
            json!({
                "actor": { "client_id": client_id },
                "auth_method": "client_secret_basic",
                "capabilities": [],
                "client_id": client_id,
                "id_token_signed_response_alg": "RS256",
                "public": false,
                "requires_consent": true,
                "scopes": ["openid", "profile", "email"],
            }),
            "what the creation of a client says, and who registered it"
        );
    }

    #[test]
    fn an_initial_access_token_registers_as_many_clients_as_it_was_made_for_until_it_expires() {
        let scenario = Scenario::start();
        let operator = open(&scenario, RegistrationPolicy::InitialToken);
        let metadata = json!({ "redirect_uris": [CALLBACK] }).to_string();
        let with = |token: Option<&str>| {
            register_as(&scenario, None, token, metadata.as_bytes()).map(|_| ())
        };
        assert_eq!(with(None), Err(RegistrationError::InvalidToken));
        let made = |uses| {
            let (_, token) = complete(create_initial_access_token(
                &scenario.app,
                &operator,
                uses,
                3600,
            ))
            .expect("a token");
            String::from_utf8(token.expose().to_vec()).expect("text")
        };
        let once = made(1);

        assert_eq!(with(Some(&once)), Ok(()));
        assert_eq!(
            with(Some(&once)),
            Err(RegistrationError::InvalidToken),
            "one use, spent"
        );
        assert_eq!(with(Some("made-up")), Err(RegistrationError::InvalidToken));
        let late = made(5);
        scenario.clock.advance(std::time::Duration::from_hours(1));
        assert_eq!(
            with(Some(&late)),
            Err(RegistrationError::InvalidToken),
            "expired"
        );
        let registered = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "client.registered")
            .expect("a registration in the chain");
        assert!(
            registered["payload"]["actor"]["initial_token_id"].is_string(),
            "{registered}"
        );
    }

    #[test]
    fn an_initial_token_is_spent_before_the_metadata_is_read() {
        let scenario = Scenario::start();
        let operator = open(&scenario, RegistrationPolicy::InitialToken);
        let (_, token) = complete(create_initial_access_token(
            &scenario.app,
            &operator,
            2,
            3600,
        ))
        .expect("a token");
        let token = String::from_utf8(token.expose().to_vec()).expect("text");
        let metadata = json!({ "redirect_uris": [CALLBACK] }).to_string();

        assert_eq!(
            register_as(&scenario, None, Some(&token), b"not JSON").map(|_| ()),
            Err(RegistrationError::InvalidClientMetadata)
        );
        assert_eq!(
            register_as(&scenario, None, Some(&token), metadata.as_bytes()).map(|_| ()),
            Ok(())
        );
        assert_eq!(
            register_as(&scenario, None, Some(&token), metadata.as_bytes()).map(|_| ()),
            Err(RegistrationError::InvalidToken),
            "the refused request spent the first use"
        );
    }

    #[test]
    fn what_cannot_be_honored_is_refused_in_the_words_of_registration() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        for (metadata, error) in [
            (
                json!({ "redirect_uris": ["http://elsewhere.example.org/cb"] }),
                RegistrationError::InvalidRedirectUri,
            ),
            (json!({}), RegistrationError::InvalidRedirectUri),
            (
                json!({ "redirect_uris": [CALLBACK], "scope": "openid offline_access" }),
                RegistrationError::InvalidClientMetadata,
            ),
            (
                json!({ "redirect_uris": [CALLBACK], "scope": "openid admin" }),
                RegistrationError::InvalidClientMetadata,
            ),
            (
                json!({
                    "redirect_uris": [CALLBACK],
                    "grant_types": ["authorization_code", "client_credentials"],
                }),
                RegistrationError::InvalidClientMetadata,
            ),
            (
                json!({ "redirect_uris": [CALLBACK], "dpop_bound_access_tokens": true }),
                RegistrationError::InvalidClientMetadata,
            ),
            (
                json!({ "redirect_uris": [CALLBACK], "token_endpoint_auth_method": "private_key_jwt" }),
                RegistrationError::InvalidClientMetadata,
            ),
            (
                json!({ "redirect_uris": [CALLBACK], "client_name": "Pay\u{202e}lap" }),
                RegistrationError::InvalidClientMetadata,
            ),
            (
                json!({ "redirect_uris": [CALLBACK], "software_statement": "eyJ9.e30.c2ln" }),
                RegistrationError::InvalidSoftwareStatement,
            ),
        ] {
            assert_eq!(
                register(&scenario, &metadata).map(|_| ()),
                Err(error),
                "{metadata}"
            );
        }
    }

    #[test]
    fn a_registered_client_signs_in_rs256_and_one_an_administrator_made_keeps_es256() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered = register(
            &scenario,
            &json!({ "redirect_uris": [CALLBACK], "token_endpoint_auth_method": "none" }),
        )
        .expect("a public client");
        let client_id = text(&registered, "client_id");

        let signed_in = scenario.sign_in_and_consent(&client_id, "openid");
        let made_by_an_administrator = scenario.sign_in("openid");

        assert_eq!(
            read_algorithm(
                signed_in
                    .tokens
                    .id_token
                    .as_deref()
                    .expect("an identity token")
            ),
            "RS256"
        );
        assert_eq!(
            read_algorithm(
                made_by_an_administrator
                    .tokens
                    .id_token
                    .as_deref()
                    .expect("an identity token")
            ),
            "ES256"
        );
    }

    #[test]
    fn a_client_of_a_key_gives_its_keys_inline_and_is_told_them_back_without_a_secret() {
        use crate::ports::crypto::Signer;

        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let key =
            complete(WeakSigner::default().generate_key(SignatureAlgorithm::Es256, Box::new(())))
                .expect("a key")
                .public_jwk;
        let registered = register(
            &scenario,
            &json!({
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": { "keys": [key] },
            }),
        )
        .expect("a client of a key");

        assert!(registered.get("client_secret").is_none(), "it keeps none");
        assert_eq!(registered["jwks"]["keys"][0]["alg"], "ES256");
        let read = read_as(
            &scenario,
            &text(&registered, "client_id"),
            &text(&registered, "registration_access_token"),
        )
        .expect("the registration");
        assert_eq!(read["jwks"], registered["jwks"]);
        assert_eq!(
            register(
                &scenario,
                &json!({
                    "redirect_uris": [CALLBACK],
                    "token_endpoint_auth_method": "private_key_jwt",
                    "jwks": { "keys": [{ "kty": "RSA", "n": "AQAB", "e": "AQAB" }] },
                }),
            )
            .map(|_| ()),
            Err(RegistrationError::InvalidClientMetadata),
            "a key the signer does not read is refused"
        );
    }

    #[test]
    fn a_realm_without_an_active_rs256_key_refuses_a_client_that_names_no_algorithm() {
        let mut scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        // As a realm whose RS256 key this build no longer signs with.
        scenario.app.signer = Arc::new(WeakSigner::refusing(SignatureAlgorithm::Rs256));

        assert_eq!(
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).map(|_| ()),
            Err(RegistrationError::InvalidClientMetadata)
        );
        assert_eq!(
            register(
                &scenario,
                &json!({ "redirect_uris": [CALLBACK], "id_token_signed_response_alg": "ES256" })
            )
            .map(|registered| registered["id_token_signed_response_alg"].clone()),
            Ok(json!("ES256")),
            "it may name another the realm signs in"
        );
    }

    #[test]
    fn a_client_registered_by_anyone_gets_no_code_from_a_session_without_the_persons_answer() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered = register(
            &scenario,
            &json!({ "redirect_uris": [CALLBACK], "token_endpoint_auth_method": "none" }),
        )
        .expect("a public client");
        let client_id = text(&registered, "client_id");
        let session = scenario.sign_in("openid");
        let challenge = URL_SAFE_NO_PAD.encode(scenario.app.digester.sha256(VERIFIER.as_bytes()));
        let ask = |prompt| AuthorizationParameters {
            response_type: Some("code"),
            client_id: Some(&client_id),
            redirect_uri: Some(CALLBACK),
            scope: Some("openid"),
            code_challenge: Some(&challenge),
            code_challenge_method: Some("S256"),
            prompt,
            ..AuthorizationParameters::default()
        };

        let silent = complete(begin_authorization(
            &scenario.app,
            "acme",
            ask(Some("none")),
            Some(&session.ticket),
        ));
        let Err(AuthorizationRefusal::Returned { location }) = silent else {
            panic!("a silent request is answered at the client: {silent:?}");
        };
        assert!(location.contains("error=consent_required"), "{location}");
        let asked = complete(begin_authorization(
            &scenario.app,
            "acme",
            ask(None),
            Some(&session.ticket),
        ));
        assert!(
            matches!(asked, Ok(Authorization::ConsentRequired { .. })),
            "the person answers on a page first: {asked:?}"
        );
    }

    #[test]
    fn a_realm_takes_registered_clients_up_to_its_bound_an_ended_one_counted() {
        let scenario = Scenario::start();
        open_with(
            &scenario,
            RealmSettings {
                registration: RegistrationPolicy::Open,
                max_registered_clients: 2,
                max_redirect_uris: 1,
                ..RealmSettings::default()
            },
        );
        let metadata = json!({ "redirect_uris": [CALLBACK] });
        let first = register(&scenario, &metadata).expect("a first client");
        assert_eq!(
            register(
                &scenario,
                &json!({ "redirect_uris": [CALLBACK, "https://registered.example.org/2"] })
            )
            .map(|_| ()),
            Err(RegistrationError::InvalidClientMetadata),
            "one address of each kind"
        );

        assert_eq!(
            complete(delete_registered_client(
                &scenario.app,
                "acme",
                &text(&first, "client_id"),
                None,
                Some(&text(&first, "registration_access_token")),
            )),
            Ok(())
        );
        register(&scenario, &metadata).expect("a second client");
        assert_eq!(
            register_with_cause(&scenario, None, None, metadata.to_string().as_bytes()).map(|_| ()),
            Err((
                RegistrationError::AccessDenied,
                ErrorCode::RegistrationQuotaReached
            )),
            "the first ended, and counts until retention removes it"
        );
    }

    #[test]
    fn an_address_that_registered_too_often_is_refused_before_anything_of_its_request_is_read() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let caller: IpAddr = "203.0.113.7".parse().expect("an address");
        let metadata = json!({ "redirect_uris": [CALLBACK] }).to_string();
        for _ in 0..MAX_RECENT_REGISTRATIONS_PER_ADDRESS {
            assert_eq!(
                register_as(&scenario, Some(caller), None, b"not JSON").map(|_| ()),
                Err(RegistrationError::InvalidClientMetadata)
            );
        }

        assert_eq!(
            register_as(&scenario, Some(caller), None, b"not JSON").map(|_| ()),
            Err(RegistrationError::TemporarilyUnavailable),
            "refused before its body is read"
        );
        assert_eq!(
            register_as(&scenario, Some(caller), None, metadata.as_bytes()).map(|_| ()),
            Err(RegistrationError::TemporarilyUnavailable)
        );
        let elsewhere: IpAddr = "198.51.100.9".parse().expect("an address");
        let registered = register_as(&scenario, Some(elsewhere), None, metadata.as_bytes())
            .expect("another address is counted apart");
        let change = RegistrationRequest {
            caller: Some(caller),
            token: registered["registration_access_token"].as_str(),
            body: b"not JSON",
        };
        assert_eq!(
            complete(update_registered_client(
                &scenario.app,
                "acme",
                &text(&registered, "client_id"),
                change,
            ))
            .map(|_| ())
            .map_err(|failure| failure.error),
            Err(RegistrationError::TemporarilyUnavailable),
            "a change is counted as a registration"
        );
        scenario.clock.advance(std::time::Duration::from_mins(10));
        assert!(
            register_as(&scenario, Some(caller), None, metadata.as_bytes()).is_ok(),
            "the window moved on"
        );
    }

    #[test]
    fn a_registration_is_managed_with_a_token_that_serves_once() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered =
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let client_id = text(&registered, "client_id");
        let first = text(&registered, "registration_access_token");
        assert!(registered.get("client_secret").is_some());

        let read = read_as(&scenario, &client_id, &first).expect("the registration");
        let second = text(&read, "registration_access_token");
        assert_ne!(first, second);
        assert!(
            read.get("client_secret").is_none(),
            "shown once, at registration"
        );
        assert_eq!(read["client_name"], registered["client_name"]);
        assert_eq!(
            read_as(&scenario, &client_id, &first).map(|_| ()),
            Err(RegistrationError::InvalidToken),
            "a token serves once"
        );
        assert_eq!(
            read_as(&scenario, "someone-else", &second).map(|_| ()),
            Err(RegistrationError::InvalidToken),
            "a client the token does not manage answers as a wrong token"
        );
        assert_eq!(
            read_as(&scenario, "not a client", &second).map(|_| ()),
            Err(RegistrationError::InvalidToken)
        );
        let third = read_as(&scenario, &client_id, &second).expect("the next reads it");
        assert_eq!(
            read_as(&scenario, &client_id, &second).map(|_| ()),
            Err(RegistrationError::InvalidToken),
            "of two requests with one token, the second is refused"
        );
        assert!(
            read_as(
                &scenario,
                &client_id,
                &text(&third, "registration_access_token")
            )
            .is_ok()
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one registration, changed from top to bottom"
    )]
    fn a_change_names_its_client_shows_its_current_secret_and_passes_the_rule_of_a_registration() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered = register(
            &scenario,
            &json!({ "redirect_uris": [CALLBACK], "client_name": "Registered" }),
        )
        .expect("a client");
        let client_id = text(&registered, "client_id");
        let secret = text(&registered, "client_secret");
        let token = text(&registered, "registration_access_token");
        let changed = |extra: Value| {
            let mut document = json!({
                "client_id": client_id,
                "redirect_uris": ["https://registered.example.org/other"],
                "client_name": "Renamed",
            });
            for (name, value) in extra.as_object().expect("members") {
                document[name] = value.clone();
            }
            document
        };

        assert_eq!(
            update_as(&scenario, &client_id, "not its token", &json!({})).map(|_| ()),
            Err(RegistrationError::InvalidToken),
            "the token is proven before the metadata is read"
        );
        for (metadata, error, why) in [
            (
                json!({ "redirect_uris": [CALLBACK] }),
                RegistrationError::InvalidClientMetadata,
                "a change names its client",
            ),
            (
                changed(json!({ "client_id": "another" })),
                RegistrationError::InvalidClientMetadata,
                "the client it changes",
            ),
            (
                changed(json!({ "client_secret": "not its secret" })),
                RegistrationError::InvalidClientMetadata,
                "a secret it shows is the one it keeps",
            ),
            (
                changed(json!({ "token_endpoint_auth_method": "none" })),
                RegistrationError::InvalidClientMetadata,
                "a client never changes how it proves itself here",
            ),
            (
                changed(json!({ "redirect_uris": ["http://elsewhere.example.org/cb"] })),
                RegistrationError::InvalidRedirectUri,
                "an address any registration refuses",
            ),
            (
                changed(json!({ "client_name": "Pay\u{202e}lap" })),
                RegistrationError::InvalidClientMetadata,
                "a name any registration refuses",
            ),
            (
                changed(json!({ "scope": "openid offline_access" })),
                RegistrationError::InvalidClientMetadata,
                "a scope the realm does not let it have",
            ),
            (
                changed(json!({ "jwks_uri": "https://registered.example.org/jwks" })),
                RegistrationError::InvalidClientMetadata,
                "a member any registration refuses",
            ),
        ] {
            assert_eq!(
                update_as(&scenario, &client_id, &token, &metadata).map(|_| ()),
                Err(error),
                "{why}"
            );
        }

        let updated = update_as(
            &scenario,
            &client_id,
            &token,
            &changed(json!({ "client_secret": secret, "require_consent": false })),
        )
        .expect("a change, with the token no refusal spent");
        assert_eq!(updated["client_name"], "Renamed");
        assert_eq!(
            updated["redirect_uris"],
            json!(["https://registered.example.org/other"])
        );
        assert!(updated.get("client_secret").is_none());
        assert_eq!(
            update_as(&scenario, &client_id, &token, &changed(json!({}))).map(|_| ()),
            Err(RegistrationError::InvalidToken),
            "the token of a change is spent"
        );
        let kept = read_client(&scenario, &client_id);
        assert!(
            kept.enabled && kept.requires_consent,
            "neither is a member it writes"
        );
        assert_eq!(kept.name, "Renamed");
        let proved = TokenRequest {
            grant_type: Some("client_credentials"),
            client_id: Some(&client_id),
            client_secret: Some(PresentedSecret::Basic(Secret::new(
                secret.as_bytes().to_vec(),
            ))),
            ..TokenRequest::default()
        };
        assert_eq!(
            complete(grant_token(&scenario.app, "acme", proved))
                .map_err(|failure| failure.error)
                .map(|_| ()),
            Err(OAuthError::UnauthorizedClient),
            "it keeps its secret, and never acts as itself"
        );
        let said = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .filter(|event| event["kind"] == "client.registration_updated")
            .count();
        assert_eq!(said, 1, "a refused change says nothing");
    }

    #[test]
    fn a_deleted_registration_disables_its_client_and_takes_back_every_grant_it_holds() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered =
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let client_id = text(&registered, "client_id");
        let secret = text(&registered, "client_secret");
        let token = text(&registered, "registration_access_token");
        let (code, _ticket) = scenario.allow_on_the_page(&client_id, "openid");
        let tokens = exchange_with_secret(&scenario, &client_id, &secret, &code).expect("tokens");
        let refresh_token = tokens.refresh_token.clone().expect("a refresh token");
        let proof = || PresentedProof {
            secret: Some(PresentedSecret::Basic(Secret::new(
                secret.as_bytes().to_vec(),
            ))),
            ..PresentedProof::default()
        };

        assert_eq!(
            complete(delete_registered_client(
                &scenario.app,
                "acme",
                &client_id,
                None,
                Some(&token),
            )),
            Ok(())
        );

        assert!(!read_client(&scenario, &client_id).enabled);
        let refresh = TokenRequest {
            grant_type: Some("refresh_token"),
            client_id: Some(&client_id),
            client_secret: proof().secret,
            refresh_token: Some(&refresh_token),
            ..TokenRequest::default()
        };
        assert_eq!(
            complete(grant_token(&scenario.app, "acme", refresh))
                .map(|_| ())
                .map_err(|failure| failure.error),
            Err(OAuthError::InvalidClient)
        );
        let (code, _ticket) = scenario.allow_on_the_page("webapp", "openid");
        assert_eq!(
            exchange_with_secret(&scenario, &client_id, &secret, &code).map(|_| ()),
            Err(OAuthError::InvalidClient),
            "its secret proves nothing any more"
        );
        assert_eq!(
            complete(crate::oidc::introspect::introspect_token(
                &scenario.app,
                "acme",
                Some(&client_id),
                proof(),
                Some(&tokens.access_token),
            ))
            .map(|_| ())
            .map_err(|failure| failure.error),
            Err(OAuthError::InvalidClient)
        );
        assert_eq!(
            complete(crate::oidc::revoke::revoke_token(
                &scenario.app,
                "acme",
                Some(&client_id),
                proof(),
                Some(&refresh_token),
            ))
            .map_err(|failure| failure.error),
            Err(OAuthError::InvalidClient)
        );
        let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
        let stored = complete(
            work.read_refresh_token(&scenario.app.digester.sha256(refresh_token.as_bytes())),
        )
        .expect("a read")
        .expect("the token");
        assert!(stored.revoked_at.is_some(), "its family is ended");
        drop(work);
        assert_eq!(
            read_as(&scenario, &client_id, &token).map(|_| ()),
            Err(RegistrationError::InvalidToken),
            "the registration is gone"
        );
        let ended = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "client.registration_deleted")
            .expect("the end is in the chain");
        assert_eq!(ended["payload"]["refresh_families_revoked"], 1);
        assert_eq!(ended["payload"]["actor"]["client_id"], client_id.as_str());
        for event in scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
        {
            let written = event.to_string();
            assert!(
                !written.contains(&token) && !written.contains(&secret),
                "no event holds a token or a secret: {written}"
            );
        }
    }

    /// The secret, or the token, a registration was answered with.
    fn spent_digest(scenario: &Scenario, token: &str) -> [u8; 32] {
        scenario.app.digester.sha256(token.as_bytes())
    }

    /// Whether the registration of `client_id` is still managed by `token`.
    fn is_managed_by(scenario: &Scenario, client_id: &str, token: &str) -> bool {
        let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
        complete(work.matches_registration_token(client_id, &spent_digest(scenario, token)))
            .expect("a read")
    }

    /// Disables a client behind the product, as the owner of the tables would.
    fn disable_behind(scenario: &Scenario, client_id: &str) {
        let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
        assert_eq!(complete(work.disable_client(client_id)), Ok(true));
        complete(work.commit()).expect("a commit");
    }

    fn delete_as(
        scenario: &Scenario,
        caller: Option<IpAddr>,
        client_id: &str,
        token: &str,
    ) -> Result<(), RegistrationError> {
        complete(delete_registered_client(
            &scenario.app,
            "acme",
            client_id,
            caller,
            Some(token),
        ))
        .map_err(|failure| failure.error)
    }

    /// A set of one key, made as a client makes one. Two signers just made
    /// make the same key: `signer` makes another at each call.
    fn make_key_set_with(signer: &WeakSigner) -> Value {
        use crate::ports::crypto::Signer;

        let key = complete(signer.generate_key(SignatureAlgorithm::Es256, Box::new(())))
            .expect("a key")
            .public_jwk;
        json!({ "keys": [key] })
    }

    fn make_key_set() -> Value {
        make_key_set_with(&WeakSigner::default())
    }

    /// The signer of a scenario, which counts the sets of keys of clients it
    /// is asked to check and holds forever each asked by a registration.
    struct HeldChecks {
        signer: Arc<dyn crate::ports::crypto::Signer>,
        holding: std::sync::atomic::AtomicBool,
        checks: std::sync::atomic::AtomicUsize,
        held: std::sync::Mutex<Vec<crate::ports::crypto::KeyMakingGuard>>,
    }

    #[async_trait::async_trait]
    impl crate::ports::crypto::Signer for HeldChecks {
        fn signs_in(&self, algorithm: SignatureAlgorithm) -> bool {
            self.signer.signs_in(algorithm)
        }

        async fn generate_key(
            &self,
            algorithm: SignatureAlgorithm,
            guard: crate::ports::crypto::KeyMakingGuard,
        ) -> Result<crate::ports::crypto::GeneratedSigningKey, crate::ports::crypto::KeyMakingFailure>
        {
            self.signer.generate_key(algorithm, guard).await
        }

        fn sign(
            &self,
            algorithm: SignatureAlgorithm,
            private_key: &Secret,
            message: &[u8],
        ) -> Result<Vec<u8>, crate::ports::crypto::CryptoFailure> {
            self.signer.sign(algorithm, private_key, message)
        }

        async fn check_client_keys(
            &self,
            keys: Vec<(SignatureAlgorithm, Value)>,
            lane: crate::ports::crypto::KeyCheckLane,
            guard: crate::ports::crypto::KeyMakingGuard,
        ) -> Result<bool, crate::ports::crypto::KeyMakingFailure> {
            use std::sync::atomic::Ordering;

            self.checks.fetch_add(1, Ordering::SeqCst);
            if lane == crate::ports::crypto::KeyCheckLane::Registration
                && self.holding.load(Ordering::SeqCst)
            {
                self.held.lock().expect("the guards").push(guard);
                return std::future::pending().await;
            }
            self.signer.check_client_keys(keys, lane, guard).await
        }

        fn verify(
            &self,
            algorithm: SignatureAlgorithm,
            public_jwk: &Value,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, crate::ports::crypto::CryptoFailure> {
            self.signer
                .verify(algorithm, public_jwk, message, signature)
        }
    }

    fn hold_checks(scenario: &mut Scenario, holding: bool) -> Arc<HeldChecks> {
        let held = Arc::new(HeldChecks {
            signer: Arc::clone(&scenario.app.signer),
            holding: std::sync::atomic::AtomicBool::new(holding),
            checks: std::sync::atomic::AtomicUsize::new(0),
            held: std::sync::Mutex::default(),
        });
        scenario.app.signer = held.clone();
        held
    }

    #[test]
    fn a_full_realm_or_an_algorithm_it_cannot_sign_in_costs_no_check_of_keys() {
        use std::sync::atomic::Ordering;

        let mut scenario = Scenario::start();
        open_with(
            &scenario,
            RealmSettings {
                registration: RegistrationPolicy::Open,
                max_registered_clients: 2,
                ..RealmSettings::default()
            },
        );
        let checks = hold_checks(&mut scenario, false);
        let keyed = |algorithm: &str| {
            json!({
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": make_key_set(),
                "id_token_signed_response_alg": algorithm,
            })
        };

        assert_eq!(
            register(&scenario, &keyed("PS256")).map(|_| ()),
            Err(RegistrationError::InvalidClientMetadata),
            "the realm holds no active PS256 key"
        );
        assert_eq!(checks.checks.load(Ordering::SeqCst), 0);
        register(&scenario, &keyed("RS256")).expect("a client of a key");
        assert_eq!(checks.checks.load(Ordering::SeqCst), 1);
        register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a second client");
        assert_eq!(
            register_with_cause(&scenario, None, None, keyed("RS256").to_string().as_bytes())
                .map(|_| ()),
            Err((
                RegistrationError::AccessDenied,
                ErrorCode::RegistrationQuotaReached
            )),
            "the realm is full"
        );
        assert_eq!(
            checks.checks.load(Ordering::SeqCst),
            1,
            "refused before its keys were checked"
        );
    }

    #[test]
    fn a_realm_takes_as_many_registrations_in_a_day_as_its_budget_from_wherever_they_come() {
        use std::sync::atomic::Ordering;

        let mut scenario = Scenario::start();
        open_with(
            &scenario,
            RealmSettings {
                registration: RegistrationPolicy::Open,
                max_daily_registrations: 2,
                ..RealmSettings::default()
            },
        );
        let checks = hold_checks(&mut scenario, false);
        let metadata = json!({ "redirect_uris": [CALLBACK] }).to_string();
        let from = |address: &str| {
            let caller: IpAddr = address.parse().expect("an address");
            register_with_cause(&scenario, Some(caller), None, metadata.as_bytes()).map(|_| ())
        };
        let spent = Err((
            RegistrationError::AccessDenied,
            ErrorCode::RegistrationBudgetSpent,
        ));

        assert_eq!(from("203.0.113.1"), Ok(()));
        assert_eq!(from("203.0.113.2"), Ok(()));
        assert_eq!(from("203.0.113.3"), spent, "a third address, the same day");
        let keyed = json!({
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": make_key_set(),
        });
        assert_eq!(
            register_with_cause(&scenario, None, None, keyed.to_string().as_bytes()).map(|_| ()),
            spent
        );
        assert_eq!(
            checks.checks.load(Ordering::SeqCst),
            0,
            "refused before its keys were checked"
        );
        scenario.clock.advance(std::time::Duration::from_hours(24));
        assert_eq!(
            from("203.0.113.3"),
            spent,
            "a day to the second still holds them"
        );
        scenario.clock.advance(std::time::Duration::from_secs(1));
        assert_eq!(from("203.0.113.3"), Ok(()), "the day after");
    }

    #[test]
    fn a_registration_checking_keys_holds_up_neither_its_tenant_nor_its_administrators() {
        use std::pin::pin;
        use std::task::{Context, Waker};

        use crate::clients::ClientAuthMethod;
        use crate::clients::manage::create_client;
        use crate::clients::register::NewClient;
        use crate::keys::rotate::rotate_signing_key;

        let mut scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let keeper = name_administrator(
            &scenario,
            "keeper",
            &[Capability::KeyWrite, Capability::ClientWrite],
        );
        let held = hold_checks(&mut scenario, true);
        let body = json!({
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": make_key_set(),
        })
        .to_string();
        let request = || RegistrationRequest {
            caller: None,
            token: None,
            body: body.as_bytes(),
        };

        let mut checking = pin!(register_dynamic_client(&scenario.app, "acme", request()));
        let polled = checking
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        assert!(polled.is_pending(), "its keys are being checked");
        assert_eq!(held.held.lock().expect("the guards").len(), 1);

        assert_eq!(
            complete(register_dynamic_client(&scenario.app, "acme", request()))
                .map(|_| ())
                .map_err(|failure| failure.error),
            Err(RegistrationError::TemporarilyUnavailable),
            "one set of keys at a time in a realm"
        );
        assert!(
            complete(rotate_signing_key(
                &scenario.app,
                &keeper,
                SignatureAlgorithm::Es384
            ))
            .is_ok(),
            "the tenant makes its keys"
        );
        let keys = make_key_set();
        let made = complete(create_client(
            &scenario.app,
            &keeper,
            NewClient {
                client_id: "keyed-service",
                name: "A service of a key",
                scopes: &[],
                capabilities: &[],
                redirect_uris: &[],
                post_logout_redirect_uris: &[],
                public: false,
                requires_consent: false,
                id_token_signed_response_alg: None,
                auth_method: Some(ClientAuthMethod::PrivateKeyJwt),
                jwks: Some(&keys),
                jwks_uri: None,
                auth_signing_alg: None,
                created_by: None,
            },
        ));
        assert!(made.is_ok(), "an administrator checks keys: {made:?}");
    }

    #[test]
    fn a_network_of_ipv6_addresses_registers_no_more_than_its_bound_whatever_its_addresses() {
        use crate::login::throttle::MAX_RECENT_REGISTRATIONS_PER_NETWORK;

        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let metadata = json!({ "redirect_uris": [CALLBACK] }).to_string();
        let from = |address: String| {
            let caller: IpAddr = address.parse().expect("an address");
            register_as(&scenario, Some(caller), None, metadata.as_bytes()).map(|_| ())
        };
        let per_address = MAX_RECENT_REGISTRATIONS_PER_ADDRESS;
        let subscribers = MAX_RECENT_REGISTRATIONS_PER_NETWORK / per_address;

        for subscriber in 0..subscribers {
            for _ in 0..per_address {
                assert_eq!(from(format!("2001:db8:7:{subscriber}::1")), Ok(()));
            }
        }
        assert_eq!(
            from(format!("2001:db8:7:{subscribers}::1")),
            Err(RegistrationError::TemporarilyUnavailable),
            "a /64 that never registered, in a /48 that did enough"
        );
        assert_eq!(
            from("2001:db8:8::1".to_owned()),
            Ok(()),
            "another /48 is counted apart"
        );
    }

    #[test]
    fn the_end_of_a_registration_is_counted_against_its_caller_as_a_registration_is() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered =
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let caller: IpAddr = "203.0.113.7".parse().expect("an address");
        for _ in 0..MAX_RECENT_REGISTRATIONS_PER_ADDRESS {
            assert_eq!(
                register_as(&scenario, Some(caller), None, b"not JSON").map(|_| ()),
                Err(RegistrationError::InvalidClientMetadata)
            );
        }

        let token = text(&registered, "registration_access_token");
        let client_id = text(&registered, "client_id");
        assert_eq!(
            delete_as(&scenario, Some(caller), &client_id, &token),
            Err(RegistrationError::TemporarilyUnavailable)
        );
        assert!(
            is_managed_by(&scenario, &client_id, &token),
            "refused, it ended nothing"
        );
        let elsewhere: IpAddr = "198.51.100.9".parse().expect("an address");
        assert_eq!(
            delete_as(&scenario, Some(elsewhere), &client_id, &token),
            Ok(())
        );
    }

    #[test]
    fn a_refused_initial_token_is_counted_against_its_caller() {
        let scenario = Scenario::start();
        let operator = open(&scenario, RegistrationPolicy::InitialToken);
        let (_, token) = complete(create_initial_access_token(
            &scenario.app,
            &operator,
            1,
            3600,
        ))
        .expect("a token");
        let token = String::from_utf8(token.expose().to_vec()).expect("text");
        let caller: IpAddr = "203.0.113.7".parse().expect("an address");
        let metadata = json!({ "redirect_uris": [CALLBACK] }).to_string();
        for presented in [None, Some("made-up")]
            .into_iter()
            .cycle()
            .take(usize::try_from(MAX_RECENT_REGISTRATIONS_PER_ADDRESS).expect("a count"))
        {
            assert_eq!(
                register_as(&scenario, Some(caller), presented, metadata.as_bytes()).map(|_| ()),
                Err(RegistrationError::InvalidToken)
            );
        }

        assert_eq!(
            register_as(&scenario, Some(caller), Some(&token), metadata.as_bytes()).map(|_| ()),
            Err(RegistrationError::TemporarilyUnavailable),
            "each refused token was counted"
        );
    }

    #[test]
    fn an_administrator_ends_a_registration_and_no_client_an_administrator_made() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered =
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let client_id = text(&registered, "client_id");
        let (code, _ticket) = scenario.allow_on_the_page(&client_id, "openid");
        let tokens = exchange_with_secret(
            &scenario,
            &client_id,
            &text(&registered, "client_secret"),
            &code,
        )
        .expect("tokens");
        let keeper = name_administrator(&scenario, "keeper", &[Capability::ClientWrite]);
        let end = |client_id: &str| {
            complete(super::end_registration_as_administrator(
                &scenario.app,
                &keeper,
                client_id,
            ))
            .map_err(|failure| failure.code)
        };

        assert_eq!(end("webapp"), Err(ErrorCode::RegistrationNotFound));
        assert_eq!(end("not a client"), Err(ErrorCode::RegistrationNotFound));
        assert_eq!(end(&client_id), Ok(()));
        assert_eq!(
            end(&client_id),
            Err(ErrorCode::RegistrationNotFound),
            "once"
        );

        assert!(!read_client(&scenario, &client_id).enabled);
        assert!(read_client(&scenario, "webapp").enabled);
        assert!(!scenario.is_token_active(&tokens.access_token));
        assert_eq!(
            read_as(
                &scenario,
                &client_id,
                &text(&registered, "registration_access_token")
            )
            .map(|_| ()),
            Err(RegistrationError::InvalidToken)
        );
        let ended = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "client.registration_deleted")
            .expect("the end is in the chain");
        assert_eq!(ended["payload"]["actor"]["client_id"], "keeper");
        assert_eq!(ended["payload"]["refresh_families_revoked"], 1);
    }

    #[test]
    fn a_closed_realm_takes_no_change_and_still_reads_and_ends_a_registration() {
        let scenario = Scenario::start();
        let operator = open(&scenario, RegistrationPolicy::Open);
        let registered =
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let client_id = text(&registered, "client_id");
        complete(change_realm_settings(
            &scenario.app,
            &operator,
            want(RealmSettings::default()),
        ))
        .expect("closed");
        let token = text(&registered, "registration_access_token");

        assert_eq!(
            update_as(
                &scenario,
                &client_id,
                &token,
                &json!({ "client_id": client_id, "redirect_uris": [CALLBACK] })
            )
            .map(|_| ()),
            Err(RegistrationError::AccessDenied)
        );
        let read = read_as(&scenario, &client_id, &token).expect("its registration, read");
        assert_eq!(
            delete_as(
                &scenario,
                None,
                &client_id,
                &text(&read, "registration_access_token")
            ),
            Ok(())
        );
    }

    #[test]
    fn a_change_is_judged_by_the_settings_the_realm_holds_when_it_writes() {
        let scenario = Scenario::start();
        let operator = open_with(
            &scenario,
            RealmSettings {
                registration: RegistrationPolicy::Open,
                max_redirect_uris: 2,
                ..RealmSettings::default()
            },
        );
        let both = [CALLBACK, "https://app.example.org/other"];
        let registered = register(
            &scenario,
            &json!({ "redirect_uris": both, "scope": "openid email" }),
        )
        .expect("a client");
        let client_id = text(&registered, "client_id");
        let token = text(&registered, "registration_access_token");
        complete(change_realm_settings(
            &scenario.app,
            &operator,
            want(RealmSettings {
                registration: RegistrationPolicy::Open,
                max_redirect_uris: 1,
                registrable_scopes: vec!["openid".to_owned()],
                ..RealmSettings::default()
            }),
        ))
        .expect("narrowed");

        for metadata in [
            json!({ "client_id": client_id, "redirect_uris": both, "scope": "openid" }),
            json!({ "client_id": client_id, "redirect_uris": [CALLBACK], "scope": "openid email" }),
        ] {
            assert_eq!(
                update_as(&scenario, &client_id, &token, &metadata).map(|_| ()),
                Err(RegistrationError::InvalidClientMetadata),
                "{metadata}"
            );
        }
        let changed = update_as(
            &scenario,
            &client_id,
            &token,
            &json!({ "client_id": client_id, "redirect_uris": [CALLBACK] }),
        )
        .expect("a change within the settings");
        assert_eq!(
            changed["scope"], "openid",
            "none asked: what the realm allows now"
        );
    }

    #[test]
    fn a_registration_whose_client_was_disabled_answers_as_a_token_nobody_handed_out() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered =
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let client_id = text(&registered, "client_id");
        let token = text(&registered, "registration_access_token");
        disable_behind(&scenario, &client_id);

        assert_eq!(
            read_as(&scenario, &client_id, &token).map(|_| ()),
            Err(RegistrationError::InvalidToken)
        );
        assert!(
            is_managed_by(&scenario, &client_id, &token),
            "a read refused spends nothing"
        );
        assert_eq!(
            update_as(
                &scenario,
                &client_id,
                &token,
                &json!({ "client_id": client_id, "redirect_uris": [CALLBACK] })
            )
            .map(|_| ()),
            Err(RegistrationError::InvalidToken)
        );
        assert!(
            is_managed_by(&scenario, &client_id, &token),
            "a change refused spends nothing"
        );
        assert_eq!(
            delete_as(&scenario, None, &client_id, &token),
            Err(RegistrationError::InvalidToken)
        );
        assert!(
            is_managed_by(&scenario, &client_id, &token),
            "an end refused ends nothing"
        );
    }

    #[test]
    fn a_change_that_names_an_algorithm_the_realm_does_not_sign_in_is_refused() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered =
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let client_id = text(&registered, "client_id");
        let token = text(&registered, "registration_access_token");
        let metadata = |algorithm: &str| {
            json!({
                "client_id": client_id,
                "redirect_uris": [CALLBACK],
                "id_token_signed_response_alg": algorithm,
            })
        };

        assert_eq!(
            update_as(&scenario, &client_id, &token, &metadata("PS256")).map(|_| ()),
            Err(RegistrationError::InvalidClientMetadata),
            "the realm holds no active PS256 key"
        );
        let changed =
            update_as(&scenario, &client_id, &token, &metadata("ES256")).expect("a change");
        assert_eq!(changed["id_token_signed_response_alg"], "ES256");
    }

    #[test]
    fn a_change_of_a_client_that_signs_with_its_secret_or_posts_it_shows_the_one_it_keeps() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        for method in ["client_secret_jwt", "client_secret_post"] {
            let registered = register(
                &scenario,
                &json!({ "redirect_uris": [CALLBACK], "token_endpoint_auth_method": method }),
            )
            .expect("a client");
            let client_id = text(&registered, "client_id");
            let secret = text(&registered, "client_secret");
            let token = text(&registered, "registration_access_token");
            let presenting = |secret: &str| {
                json!({
                    "client_id": client_id,
                    "redirect_uris": [CALLBACK],
                    "token_endpoint_auth_method": method,
                    "client_secret": secret,
                })
            };

            assert_eq!(
                update_as(&scenario, &client_id, &token, &presenting("not its secret")).map(|_| ()),
                Err(RegistrationError::InvalidClientMetadata),
                "{method}"
            );
            assert!(
                update_as(&scenario, &client_id, &token, &presenting(&secret)).is_ok(),
                "{method}"
            );
        }
    }

    /// Whether `client_id` gets a code without a page, in the session of
    /// `ticket`, sent back to `redirect_uri`.
    fn ask_silently(
        scenario: &Scenario,
        client_id: &str,
        redirect_uri: &str,
        ticket: &crate::login::session::SessionTicket,
    ) -> Result<(), String> {
        let challenge = URL_SAFE_NO_PAD.encode(scenario.app.digester.sha256(VERIFIER.as_bytes()));
        let parameters = AuthorizationParameters {
            response_type: Some("code"),
            client_id: Some(client_id),
            redirect_uri: Some(redirect_uri),
            scope: Some("openid"),
            code_challenge: Some(&challenge),
            code_challenge_method: Some("S256"),
            prompt: Some("none"),
            ..AuthorizationParameters::default()
        };
        match complete(begin_authorization(
            &scenario.app,
            "acme",
            parameters,
            Some(ticket),
        )) {
            Ok(Authorization::Granted { .. }) => Ok(()),
            Err(AuthorizationRefusal::Returned { location }) => Err(location),
            other => panic!("a silent request is granted or returned: {other:?}"),
        }
    }

    #[test]
    fn a_change_that_sends_codes_to_another_host_asks_each_person_again() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered = register(
            &scenario,
            &json!({ "redirect_uris": [CALLBACK], "token_endpoint_auth_method": "none" }),
        )
        .expect("a public client");
        let client_id = text(&registered, "client_id");
        let signed_in = scenario.sign_in_and_consent(&client_id, "openid");
        assert_eq!(
            ask_silently(&scenario, &client_id, CALLBACK, &signed_in.ticket),
            Ok(())
        );
        let changed = |token: &str, redirect_uris: Value| {
            let metadata = json!({
                "client_id": client_id,
                "redirect_uris": redirect_uris,
                "token_endpoint_auth_method": "none",
                "client_name": "Renamed",
            });
            update_as(&scenario, &client_id, token, &metadata).expect("a change")
        };

        let renamed = changed(
            &text(&registered, "registration_access_token"),
            json!([CALLBACK]),
        );
        assert_eq!(
            ask_silently(&scenario, &client_id, CALLBACK, &signed_in.ticket),
            Ok(()),
            "a new name on a known host asks nobody again"
        );
        let widened = changed(
            &text(&renamed, "registration_access_token"),
            json!([CALLBACK, "https://app.example.org/elsewhere"]),
        );
        assert_eq!(
            ask_silently(&scenario, &client_id, CALLBACK, &signed_in.ticket),
            Ok(()),
            "a new address on a known host asks nobody again"
        );
        changed(
            &text(&widened, "registration_access_token"),
            json!([CALLBACK, "https://elsewhere.example.org/cb"]),
        );

        let asked = ask_silently(&scenario, &client_id, CALLBACK, &signed_in.ticket);
        assert!(
            asked
                .as_ref()
                .is_err_and(|location| location.contains("error=consent_required")),
            "{asked:?}"
        );
        assert_eq!(
            scenario
                .refresh_as(
                    &client_id,
                    signed_in
                        .tokens
                        .refresh_token
                        .as_deref()
                        .expect("a refresh token"),
                    None
                )
                .map(|_| ()),
            Err(OAuthError::InvalidGrant),
            "what it held in the name of the person is taken back"
        );
        let updated = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "client.registration_updated")
            .expect("the change is in the chain");
        assert_eq!(
            updated["payload"]["consents_renewed"]["consents_withdrawn"],
            1
        );
        assert_eq!(
            updated["payload"]["consents_renewed"]["refresh_families_revoked"],
            1
        );
    }

    #[test]
    fn a_change_that_proves_the_client_with_other_keys_asks_each_person_again() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let signer = WeakSigner::default();
        let keys = make_key_set_with(&signer);
        let keyed = |keys: &Value| {
            json!({
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": keys,
            })
        };
        let registered = register(&scenario, &keyed(&keys)).expect("a client of a key");
        let client_id = text(&registered, "client_id");
        let (_code, ticket) = scenario.allow_on_the_page(&client_id, "openid");
        assert_eq!(
            ask_silently(&scenario, &client_id, CALLBACK, &ticket),
            Ok(())
        );
        let change = |token: &str, keys: &Value| {
            let mut metadata = keyed(keys);
            metadata["client_id"] = json!(client_id);
            update_as(&scenario, &client_id, token, &metadata).expect("a change")
        };

        let same = change(&text(&registered, "registration_access_token"), &keys);
        assert_eq!(
            ask_silently(&scenario, &client_id, CALLBACK, &ticket),
            Ok(()),
            "the same keys ask nobody again"
        );
        change(
            &text(&same, "registration_access_token"),
            &make_key_set_with(&signer),
        );

        let asked = ask_silently(&scenario, &client_id, CALLBACK, &ticket);
        assert!(
            asked
                .as_ref()
                .is_err_and(|location| location.contains("error=consent_required")),
            "{asked:?}"
        );
    }

    #[test]
    fn a_token_of_a_client_whose_registration_ended_is_refused_by_whoever_reads_it() {
        use crate::oidc::userinfo::read_user_info;

        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered = register(
            &scenario,
            &json!({ "redirect_uris": [CALLBACK], "token_endpoint_auth_method": "none" }),
        )
        .expect("a public client");
        let client_id = text(&registered, "client_id");
        let token = scenario
            .sign_in_and_consent(&client_id, "openid")
            .tokens
            .access_token;
        assert!(scenario.is_token_active(&token));
        assert!(complete(read_user_info(&scenario.app, "acme", &token)).is_ok());

        assert_eq!(
            delete_as(
                &scenario,
                None,
                &client_id,
                &text(&registered, "registration_access_token")
            ),
            Ok(())
        );

        assert!(!scenario.is_token_active(&token), "introspection");
        assert_eq!(
            complete(read_user_info(&scenario.app, "acme", &token)).map_err(|failure| failure.code),
            Err(ErrorCode::TokenInvalid),
            "userinfo"
        );
    }

    #[test]
    fn a_client_that_registered_itself_asks_the_point_of_decision_nothing() {
        use crate::authz::decide::{DecisionRequest, decide};

        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered =
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let token = scenario.sign_in("openid").tokens.access_token;
        // Every question of the tenant is held: a client that asks one waits.
        let mut held = Vec::new();
        while let Some(share) = scenario.app.decision_shares.take(scenario.scope.tenant()) {
            held.push(share);
        }
        let attributes = serde_json::Map::new();

        let asked = complete(decide(
            &scenario.app,
            "acme",
            Some(&text(&registered, "client_id")),
            Some(Secret::new(text(&registered, "client_secret").into_bytes())),
            DecisionRequest {
                subject_token: Some(&token),
                action: "read",
                resource_type: "invoice",
                resource_id: None,
                attributes: &attributes,
            },
        ));

        assert_eq!(
            asked.map(|_| ()).map_err(|failure| failure.error),
            Err(OAuthError::UnauthorizedClient),
            "refused before it waits for a share"
        );
        assert!(!held.is_empty());
    }

    #[test]
    fn a_client_that_registered_itself_sends_the_browser_back_only_from_the_sign_out_that_ends_its_session()
     {
        use crate::oidc::logout::{Logout, LogoutParameters, begin_logout};
        use crate::oidc::scenario::GOODBYE;

        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered = register(
            &scenario,
            &json!({
                "redirect_uris": [CALLBACK],
                "post_logout_redirect_uris": [GOODBYE],
                "token_endpoint_auth_method": "none",
            }),
        )
        .expect("a public client");
        let client_id = text(&registered, "client_id");
        let signed_in = scenario.sign_in_and_consent(&client_id, "openid");
        let made_by_the_realm = scenario.sign_in("openid");
        let sign_out = |hint: &str, ticket| {
            let parameters = LogoutParameters {
                id_token_hint: Some(hint),
                post_logout_redirect_uri: Some(GOODBYE),
                state: None,
            };
            complete(begin_logout(&scenario.app, "acme", parameters, ticket)).expect("an answer")
        };
        let hint = signed_in
            .tokens
            .id_token
            .clone()
            .expect("an identity token");

        assert_eq!(
            sign_out(&hint, Some(&signed_in.ticket)),
            Logout::SignedOut {
                location: Some(GOODBYE.to_owned())
            },
            "this request ended the session the token names"
        );
        assert_eq!(
            sign_out(&hint, None),
            Logout::SignedOut { location: None },
            "a token of a session over sends the browser nowhere"
        );
        scenario.end_session(&made_by_the_realm.ticket);
        assert_eq!(
            sign_out(
                made_by_the_realm
                    .tokens
                    .id_token
                    .as_deref()
                    .expect("an identity token"),
                None
            ),
            Logout::SignedOut {
                location: Some(GOODBYE.to_owned())
            },
            "a client the realm made is trusted with its address"
        );
    }

    #[test]
    fn a_page_of_consent_tells_a_client_that_registered_itself_from_one_the_realm_made() {
        use crate::clients::register::NewClient;
        use crate::consent::answer::{ClientOrigin, describe_consent};
        use crate::testkit::fixtures::check_and_register_client;

        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        // Its second host is a name outside ASCII, written as it is
        // registered and as a browser reads it.
        let second = "https://xn--bcher-kva.example/cb";
        let registered = register(
            &scenario,
            &json!({
                "redirect_uris": ["https://registered.example.org/cb", second],
                "client_name": "Partner",
                "token_endpoint_auth_method": "none",
            }),
        )
        .expect("a public client");
        let client_id = text(&registered, "client_id");
        let callbacks = [CALLBACK.to_owned()];
        let scopes = ["openid".to_owned()];
        let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
        complete(check_and_register_client(
            &scenario.app,
            work.as_mut(),
            NewClient {
                client_id: "partner",
                name: "Partner",
                scopes: &scopes,
                capabilities: &[],
                redirect_uris: &callbacks,
                post_logout_redirect_uris: &[],
                public: true,
                requires_consent: true,
                id_token_signed_response_alg: None,
                auth_method: None,
                jwks: None,
                jwks_uri: None,
                auth_signing_alg: None,
                created_by: Some("operator"),
            },
        ))
        .expect("a client the realm made");
        complete(work.commit()).expect("a commit");
        let ticket = scenario.sign_in("openid").ticket;
        let describe = |client_id: &str, redirect_uri: &str| {
            let challenge =
                URL_SAFE_NO_PAD.encode(scenario.app.digester.sha256(VERIFIER.as_bytes()));
            let parameters = AuthorizationParameters {
                response_type: Some("code"),
                client_id: Some(client_id),
                redirect_uri: Some(redirect_uri),
                scope: Some("openid"),
                code_challenge: Some(&challenge),
                code_challenge_method: Some("S256"),
                ..AuthorizationParameters::default()
            };
            let Ok(Authorization::ConsentRequired {
                request,
                browser_secret,
            }) = complete(begin_authorization(
                &scenario.app,
                "acme",
                parameters,
                Some(&ticket),
            ))
            else {
                panic!("each asks the person first");
            };
            complete(describe_consent(
                &scenario.app,
                "acme",
                request,
                &browser_secret,
                Some(&ticket),
            ))
            .expect("a page")
        };
        let made = describe("partner", CALLBACK);
        let self_made = describe(&client_id, second);

        assert_eq!(made.origin, ClientOrigin::Realm);
        assert_eq!(
            self_made.origin,
            ClientOrigin::SelfRegistered {
                client_id: client_id.clone(),
                return_host: "xn--bcher-kva.example".to_owned(),
                other_hosts: vec!["registered.example.org".to_owned()],
            },
            "the host of this request, and every other its answer covers"
        );
        assert_eq!(self_made.client_name, "Partner");
        assert_eq!(
            (made.client_name, made.scopes),
            (self_made.client_name, self_made.scopes),
            "the same name, and the same scopes"
        );
    }

    /// Asks for a code for `client_id` in the session of `ticket`, sent back
    /// to `redirect_uri`, which the person is to answer on the page.
    fn ask_on_the_page(
        scenario: &Scenario,
        client_id: &str,
        redirect_uri: &str,
        ticket: &crate::login::session::SessionTicket,
    ) -> (uuid::Uuid, Secret) {
        let challenge = URL_SAFE_NO_PAD.encode(scenario.app.digester.sha256(VERIFIER.as_bytes()));
        let parameters = AuthorizationParameters {
            response_type: Some("code"),
            client_id: Some(client_id),
            redirect_uri: Some(redirect_uri),
            scope: Some("openid"),
            code_challenge: Some(&challenge),
            code_challenge_method: Some("S256"),
            ..AuthorizationParameters::default()
        };
        let Ok(Authorization::ConsentRequired {
            request,
            browser_secret,
        }) = complete(begin_authorization(
            &scenario.app,
            "acme",
            parameters,
            Some(ticket),
        ))
        else {
            panic!("the person answers on the page");
        };
        (request, browser_secret)
    }

    #[test]
    fn an_answer_holds_only_for_the_hosts_and_keys_its_page_showed() {
        use crate::consent::answer::{
            ClientOrigin, ConsentDecision, answer_consent, describe_consent,
        };

        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let ticket = scenario.sign_in("openid").ticket;
        let page = |request, browser_secret: &Secret| {
            complete(describe_consent(
                &scenario.app,
                "acme",
                request,
                browser_secret,
                Some(&ticket),
            ))
            .expect("a page")
        };
        let allow = |request, browser_secret: &Secret, shown: String| {
            complete(answer_consent(
                &scenario.app,
                "acme",
                request,
                browser_secret,
                Some(&ticket),
                ConsentDecision::Allow { shown },
            ))
            .map_err(|failure| failure.code)
        };
        let signer = WeakSigner::default();
        for (method, before, after) in [
            ("none", json!(null), json!(null)),
            (
                "private_key_jwt",
                make_key_set_with(&signer),
                make_key_set_with(&signer),
            ),
        ] {
            let metadata = |redirect_uris: Value, keys: &Value| {
                let mut metadata = json!({
                    "redirect_uris": redirect_uris,
                    "token_endpoint_auth_method": method,
                });
                if !keys.is_null() {
                    metadata["jwks"] = keys.clone();
                }
                metadata
            };
            let registered =
                register(&scenario, &metadata(json!([CALLBACK]), &before)).expect("a client");
            let client_id = text(&registered, "client_id");
            let (request, browser_secret) =
                ask_on_the_page(&scenario, &client_id, CALLBACK, &ticket);
            let shown = page(request, &browser_secret).shown;
            // Between the page and the answer, another host or other keys.
            let mut changed = if after.is_null() {
                metadata(
                    json!([CALLBACK, "https://elsewhere.example.org/cb"]),
                    &after,
                )
            } else {
                metadata(json!([CALLBACK]), &after)
            };
            changed["client_id"] = json!(client_id);
            update_as(
                &scenario,
                &client_id,
                &text(&registered, "registration_access_token"),
                &changed,
            )
            .expect("a change");

            assert_eq!(
                allow(request, &browser_secret, shown),
                Err(ErrorCode::ConsentPageOutdated),
                "{method}: the page did not show what the answer would cover"
            );
            let again = page(request, &browser_secret);
            if after.is_null() {
                assert_eq!(
                    again.origin,
                    ClientOrigin::SelfRegistered {
                        client_id: client_id.clone(),
                        return_host: "app.example.org".to_owned(),
                        other_hosts: vec!["elsewhere.example.org".to_owned()],
                    },
                    "the request still waits, and its page says what it now covers"
                );
            }
            assert!(
                allow(request, &browser_secret, again.shown).is_ok(),
                "{method}: answered on the page as it is"
            );
        }
    }

    #[test]
    fn an_answer_holds_when_the_same_hosts_come_back_in_another_order() {
        use crate::consent::answer::{ConsentDecision, answer_consent, describe_consent};

        const ELSEWHERE: &str = "https://elsewhere.example.org/cb";
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let ticket = scenario.sign_in("openid").ticket;
        let metadata = |redirect_uris: Value| {
            json!({
                "redirect_uris": redirect_uris,
                "token_endpoint_auth_method": "none",
            })
        };
        let registered =
            register(&scenario, &metadata(json!([CALLBACK, ELSEWHERE]))).expect("a client");
        let client_id = text(&registered, "client_id");
        let (request, browser_secret) = ask_on_the_page(&scenario, &client_id, CALLBACK, &ticket);
        let shown = complete(describe_consent(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            Some(&ticket),
        ))
        .expect("a page")
        .shown;
        let mut reordered = metadata(json!([ELSEWHERE, CALLBACK]));
        reordered["client_id"] = json!(client_id);
        update_as(
            &scenario,
            &client_id,
            &text(&registered, "registration_access_token"),
            &reordered,
        )
        .expect("a change");
        assert_eq!(
            read_client(&scenario, &client_id).redirect_uris,
            [ELSEWHERE, CALLBACK],
            "the same hosts, in another order"
        );

        let answered = complete(answer_consent(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Allow { shown },
        ));
        assert!(
            answered.is_ok(),
            "the page showed every host the answer covers: {answered:?}"
        );
    }

    #[test]
    fn a_token_a_person_gave_a_client_that_registered_itself_speaks_for_nobody_at_the_point_of_decision()
     {
        use crate::authz::decide::{DecisionRequest, decide};
        use crate::authz::relations::{
            ObjectRef, RelationTuple, SubjectRef, write_relation, write_relation_guard,
            write_relation_schema,
        };

        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let keeper = name_administrator(
            &scenario,
            "keeper",
            &[Capability::PolicyWrite, Capability::RoleWrite],
        );
        complete(write_relation_schema(
            &scenario.app,
            &keeper,
            "definition user {}
             definition document {
                 relation reader: user
                 permission read = reader
             }",
        ))
        .expect("a schema");
        complete(write_relation_guard(
            &scenario.app,
            &keeper,
            "document",
            "billing",
        ))
        .expect("a guard");
        let ada = scenario.find_ada().to_string();
        let holds = RelationTuple {
            object: ObjectRef {
                object_type: "document".to_owned(),
                object_id: "q3".to_owned(),
            },
            relation: "reader".to_owned(),
            subject: SubjectRef {
                object: ObjectRef {
                    object_type: "user".to_owned(),
                    object_id: ada,
                },
                member: None,
            },
        };
        complete(write_relation(&scenario.app, &keeper, &holds)).expect("a relation");
        let registered = register(
            &scenario,
            &json!({ "redirect_uris": [CALLBACK], "token_endpoint_auth_method": "none" }),
        )
        .expect("a public client");
        let of_registered = scenario
            .sign_in_and_consent(&text(&registered, "client_id"), "openid")
            .tokens
            .access_token;
        let of_webapp = scenario.sign_in("openid").tokens.access_token;
        let attributes = serde_json::Map::new();
        let ask = |token: &str| {
            complete(decide(
                &scenario.app,
                "acme",
                Some("billing"),
                Some(scenario.copy_service_secret()),
                DecisionRequest {
                    subject_token: Some(token),
                    action: "read",
                    resource_type: "document",
                    resource_id: Some("q3"),
                    attributes: &attributes,
                },
            ))
            .map(|decision| (decision.decision, decision.reason))
            .map_err(|failure| failure.error)
        };

        assert_eq!(
            ask(&of_webapp),
            Ok(("permit", "relation".to_owned())),
            "a client of the realm speaks for her"
        );
        assert_eq!(
            ask(&of_registered),
            Ok(("deny", "subject_unknown".to_owned())),
            "she allowed it openid, not her authority"
        );
        scenario.storage.disable_client("webapp");
        assert_eq!(
            ask(&of_webapp),
            Ok(("deny", "subject_unknown".to_owned())),
            "a client disabled since speaks for nobody"
        );
    }

    #[test]
    fn a_client_that_registered_itself_learns_of_its_own_tokens_only() {
        use crate::clients::authenticate::PresentedProof;
        use crate::oidc::introspect::introspect_token;

        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered =
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let client_id = text(&registered, "client_id");
        let secret = text(&registered, "client_secret");
        let (code, _ticket) = scenario.allow_on_the_page(&client_id, "openid");
        let own = exchange_with_secret(&scenario, &client_id, &secret, &code)
            .expect("tokens")
            .access_token;
        let of_webapp = scenario.sign_in("openid").tokens.access_token;
        let ask = |token: &str| {
            let proof = PresentedProof {
                secret: Some(PresentedSecret::Basic(Secret::new(
                    secret.as_bytes().to_vec(),
                ))),
                ..PresentedProof::default()
            };
            complete(introspect_token(
                &scenario.app,
                "acme",
                Some(&client_id),
                proof,
                Some(token),
            ))
            .expect("an answer")
            .active
        };

        assert!(ask(&own), "its own token");
        assert!(
            !ask(&of_webapp),
            "the token of another client stands, unsaid"
        );
        assert!(
            scenario.is_token_active(&of_webapp),
            "a client of the realm is told"
        );
    }

    #[test]
    fn a_realm_takes_as_many_changes_of_registrations_in_a_day_as_registrations() {
        let scenario = Scenario::start();
        open_with(
            &scenario,
            RealmSettings {
                registration: RegistrationPolicy::Open,
                max_daily_registrations: 1,
                ..RealmSettings::default()
            },
        );
        let registered =
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let client_id = text(&registered, "client_id");
        let body = json!({ "client_id": client_id, "redirect_uris": [CALLBACK] }).to_string();
        let change = |address: &str, token: &str| {
            let request = RegistrationRequest {
                caller: Some(address.parse().expect("an address")),
                token: Some(token),
                body: body.as_bytes(),
            };
            complete(update_registered_client(
                &scenario.app,
                "acme",
                &client_id,
                request,
            ))
            .map(super::RegistrationAnswer::into_document)
            .map_err(|failure| (failure.error, failure.cause.code))
        };
        let changes_told = || {
            scenario
                .storage
                .read_audit_envelopes(scenario.scope.realm())
                .into_iter()
                .filter(|event| event["kind"] == "client.registration_updated")
                .count()
        };

        let changed = change(
            "203.0.113.1",
            &text(&registered, "registration_access_token"),
        )
        .expect("a first change");
        let next = text(&changed, "registration_access_token");
        assert_eq!(
            change("198.51.100.2", &next).map(|_| ()),
            Err((
                RegistrationError::AccessDenied,
                ErrorCode::RegistrationBudgetSpent
            )),
            "a second, from another address"
        );
        assert_eq!(changes_told(), 1, "the refused change wrote nothing");
        assert!(
            is_managed_by(&scenario, &client_id, &next),
            "and spent no token"
        );
    }

    #[test]
    fn a_body_that_cannot_be_read_spends_the_changes_of_its_client_and_none_of_the_realm() {
        let scenario = Scenario::start();
        open_with(
            &scenario,
            RealmSettings {
                registration: RegistrationPolicy::Open,
                max_daily_registrations: 2,
                ..RealmSettings::default()
            },
        );
        let first = register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let second =
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let change = |registered: &Value, token: &str, body: &[u8]| {
            let request = RegistrationRequest {
                caller: None,
                token: Some(token),
                body,
            };
            complete(update_registered_client(
                &scenario.app,
                "acme",
                &text(registered, "client_id"),
                request,
            ))
            .map(super::RegistrationAnswer::into_document)
            .map_err(|failure| (failure.error, failure.cause.code))
        };
        let readable = |registered: &Value| {
            json!({ "client_id": registered["client_id"], "redirect_uris": [CALLBACK] }).to_string()
        };
        let first_token = text(&first, "registration_access_token");
        let unreadable = Err((
            RegistrationError::InvalidClientMetadata,
            ErrorCode::ClientMetadataInvalid,
        ));
        for _ in 0..3 {
            assert_eq!(
                change(&first, &first_token, b"{not JSON").map(|_| ()),
                unreadable
            );
        }

        let changed = change(
            &second,
            &text(&second, "registration_access_token"),
            readable(&second).as_bytes(),
        )
        .expect("the realm took none of the bodies it could not read");
        for _ in 3..20 {
            assert_eq!(
                change(&first, &first_token, b"{not JSON").map(|_| ()),
                unreadable
            );
        }
        let spent = Err((
            RegistrationError::AccessDenied,
            ErrorCode::RegistrationChangesSpent,
        ));
        assert_eq!(
            change(&first, &first_token, readable(&first).as_bytes()).map(|_| ()),
            spent,
            "its twenty-first change of the day"
        );
        assert!(
            change(
                &second,
                &text(&changed, "registration_access_token"),
                readable(&second).as_bytes(),
            )
            .is_ok(),
            "the other client counts its own"
        );
        scenario.clock.advance(std::time::Duration::from_hours(1));
        assert_eq!(
            change(&first, &first_token, readable(&first).as_bytes()).map(|_| ()),
            spent,
            "an hour later, the same day"
        );
        scenario.clock.advance(std::time::Duration::from_hours(23));
        assert!(
            change(&first, &first_token, readable(&first).as_bytes()).is_ok(),
            "a day later"
        );
    }

    #[test]
    fn a_realm_without_room_spends_no_use_of_an_initial_token() {
        let scenario = Scenario::start();
        let operator = open_with(
            &scenario,
            RealmSettings {
                registration: RegistrationPolicy::InitialToken,
                max_daily_registrations: 1,
                ..RealmSettings::default()
            },
        );
        let (_, token) = complete(create_initial_access_token(
            &scenario.app,
            &operator,
            2,
            3 * 86_400,
        ))
        .expect("a token");
        let token = String::from_utf8(token.expose().to_vec()).expect("text");
        let metadata = json!({ "redirect_uris": [CALLBACK] }).to_string();
        let with = |token: &str| {
            register_with_cause(&scenario, None, Some(token), metadata.as_bytes()).map(|_| ())
        };

        assert_eq!(with(&token), Ok(()), "one use spent");
        assert_eq!(
            with(&token),
            Err((
                RegistrationError::AccessDenied,
                ErrorCode::RegistrationBudgetSpent
            )),
            "no room today"
        );
        assert_eq!(
            with("made-up"),
            Err((
                RegistrationError::InvalidToken,
                ErrorCode::RegistrationTokenInvalid
            )),
            "a token nobody handed out is told so, room or not"
        );
        scenario
            .clock
            .advance(std::time::Duration::from_secs(86_401));
        assert_eq!(
            with(&token),
            Ok(()),
            "its second use waited for a day with room"
        );
    }

    #[test]
    fn the_end_of_a_registration_counts_its_caller_even_with_a_token_refused() {
        let scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let registered =
            register(&scenario, &json!({ "redirect_uris": [CALLBACK] })).expect("a client");
        let client_id = text(&registered, "client_id");
        let caller: IpAddr = "203.0.113.7".parse().expect("an address");
        for _ in 0..MAX_RECENT_REGISTRATIONS_PER_ADDRESS {
            assert_eq!(
                delete_as(&scenario, Some(caller), &client_id, "not its token"),
                Err(RegistrationError::InvalidToken)
            );
        }

        assert_eq!(
            delete_as(
                &scenario,
                Some(caller),
                &client_id,
                &text(&registered, "registration_access_token")
            ),
            Err(RegistrationError::TemporarilyUnavailable),
            "each refused token was counted"
        );
    }

    #[test]
    fn a_change_that_names_an_algorithm_the_realm_cannot_sign_in_costs_no_check_of_keys() {
        use std::sync::atomic::Ordering;

        let mut scenario = Scenario::start();
        open(&scenario, RegistrationPolicy::Open);
        let checks = hold_checks(&mut scenario, false);
        let keyed = |algorithm: &str| {
            json!({
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": make_key_set(),
                "id_token_signed_response_alg": algorithm,
            })
        };
        let registered = register(&scenario, &keyed("RS256")).expect("a client of a key");
        assert_eq!(checks.checks.load(Ordering::SeqCst), 1);
        let mut changed = keyed("PS256");
        changed["client_id"] = registered["client_id"].clone();

        assert_eq!(
            update_as(
                &scenario,
                &text(&registered, "client_id"),
                &text(&registered, "registration_access_token"),
                &changed,
            )
            .map(|_| ()),
            Err(RegistrationError::InvalidClientMetadata),
            "the realm holds no active PS256 key"
        );
        assert_eq!(
            checks.checks.load(Ordering::SeqCst),
            1,
            "refused before its keys were checked"
        );
    }

    #[test]
    fn metadata_says_it_is_json_however_its_parameters_are_spaced() {
        use super::check_metadata_media_type;

        for written in [
            "application/json",
            "Application/JSON",
            "application/json; charset=utf-8",
            "application/json ; charset=utf-8",
            " application/json",
        ] {
            assert!(
                check_metadata_media_type(Some(written)).is_ok(),
                "{written:?}"
            );
        }
        for written in [
            None,
            Some("text/plain"),
            Some("application/jsonx"),
            Some("application/x-www-form-urlencoded"),
        ] {
            assert!(check_metadata_media_type(written).is_err(), "{written:?}");
        }
    }
}
