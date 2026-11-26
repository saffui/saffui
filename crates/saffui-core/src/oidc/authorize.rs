//! The authorization endpoint: the code flow with PKCE, and the implicit and
//! hybrid flows a client declared.
//!
//! The order of the checks is the security of this file. Until the client
//! and its redirect URI are trusted, a refusal is shown to the person and
//! nothing is sent anywhere. Only after that may a refusal travel to the
//! client, on the redirect URI it registered, as its answer would have.

use std::fmt::{self, Write as _};
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use time::Duration;
use uuid::Uuid;

use super::code::{AuthorizationCode, PendingAuthorization, PendingKeyProof};
use super::discovery::name_issuer;
use super::errors::OAuthError;
use super::implicit::{AnswerSubject, AuthorizationSigning, sign_at_authorization};
use super::pkce::is_well_formed_challenge;
use super::request_object::{CarriedParameters, read_signed_request};
use super::response::{
    AuthorizationResponse, ResponseMode, ResponseType, choose_refusal_mode, choose_response_mode,
};
use super::token::OFFLINE_ACCESS_SCOPE;
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::claims::request::{ClaimsRequest, read_claims_parameter};
use crate::claims::rules::list_claims_owing_consent;
use crate::clients::{
    Client, KeptProof, check_scope_token, is_loopback_host, is_on_origin, read_named_client,
    read_named_client_with_proof, read_redirect_host,
};
use crate::consent::{Allowance, ConsentHold, ConsentTerms, is_consent_owed, list_covering_scopes};
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::login::assurance::{Assurance, RequiredLevel};
use crate::login::device::DeviceMark;
use crate::login::flow::{
    FirstStep, SignedIn, finish_sign_in_with_code, finish_sign_in_with_key, sign_in_with_password,
};
use crate::login::session::{Session, SessionTicket, close_session, find_answering_session};
use crate::login::store::ServedRecord;
use crate::login::throttle::admit_pending_sign_in;
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;
use crate::tenancy::resolve::resolve_realm;
use crate::tenancy::{RealmName, RealmScope};
use crate::tokens::verify::read_identity_hint;

/// How long a code lives: the time of one redirect and one request.
const CODE_LIFETIME: Duration = Duration::seconds(60);
/// How long a request waits for its person to sign in.
const PENDING_LIFETIME: Duration = Duration::minutes(10);
/// The longest `state` or `nonce` a client may send.
const OPAQUE_VALUE_MAX_BYTES: usize = 512;

/// What a client sent to the authorization endpoint, as read from the query.
#[derive(Clone, Copy, Default)]
pub struct AuthorizationParameters<'a> {
    pub response_type: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub redirect_uri: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub state: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    /// How the answer travels: `query`, `fragment` or `form_post`.
    pub response_mode: Option<&'a str>,
    /// `none`, `login`, `consent`, `select_account`, separated by spaces.
    pub prompt: Option<&'a str>,
    /// The longest time, in seconds, since the person last proved who they are.
    pub max_age: Option<&'a str>,
    /// An identity token the client was given earlier: the person it expects.
    pub id_token_hint: Option<&'a str>,
    /// The request itself, signed by its client: read in place of the rest.
    pub request: Option<&'a str>,
    /// An address to fetch the request from: refused, it is never fetched.
    pub request_uri: Option<&'a str>,
    /// The claims the client names one by one, as JSON.
    pub claims: Option<&'a str>,
    /// The address of the browser, as a believed proxy said: the sign-ins
    /// it leaves waiting are counted under it.
    pub caller: Option<IpAddr>,
    /// The marks the browser keeps: a browser the realm knows leaves its
    /// sign-ins waiting under its device, not under the address.
    pub known_browsers: &'a [DeviceMark],
}

pub enum Authorization {
    /// The person is signed in: the browser goes back to the client with
    /// what it asked for.
    Granted { response: AuthorizationResponse },
    /// The person must sign in. The request waits under this identifier, and
    /// only the browser that holds this secret can finish it.
    SignInRequired {
        request: Uuid,
        browser_secret: Secret,
    },
    /// The person is signed in and must allow the client first. The request
    /// waits for their answer as one waits for a sign-in.
    ConsentRequired {
        request: Uuid,
        browser_secret: Secret,
    },
}

#[derive(Debug)]
pub enum AuthorizationRefusal {
    /// Told to the person: the client or its redirect URI is not trusted.
    Shown(Failure),
    /// Sent to the client, on the redirect URI it registered.
    Returned { response: AuthorizationResponse },
}

// Written by hand: the secret of a waiting request is not printed.
impl fmt::Debug for Authorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted { response } => formatter
                .debug_struct("Granted")
                .field("response", response)
                .finish(),
            Self::SignInRequired { request, .. } => formatter
                .debug_struct("SignInRequired")
                .field("request", request)
                .finish_non_exhaustive(),
            Self::ConsentRequired { request, .. } => formatter
                .debug_struct("ConsentRequired")
                .field("request", request)
                .finish_non_exhaustive(),
        }
    }
}

// Written by hand: an identity token hint says who the person is, and so
// may a request object or the claims it names.
impl fmt::Debug for AuthorizationParameters<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationParameters")
            .field("response_type", &self.response_type)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("state", &self.state)
            .field("nonce", &self.nonce)
            .field("code_challenge", &self.code_challenge)
            .field("code_challenge_method", &self.code_challenge_method)
            .field("response_mode", &self.response_mode)
            .field("prompt", &self.prompt)
            .field("max_age", &self.max_age)
            .field("id_token_hint", &self.id_token_hint.map(|_| ".."))
            .field("request", &self.request.map(|_| ".."))
            .field("request_uri", &self.request_uri)
            .field("claims", &self.claims.map(|_| ".."))
            .field("caller", &self.caller)
            .field("known_browsers", &self.known_browsers)
            .finish()
    }
}

impl From<Failure> for AuthorizationRefusal {
    fn from(failure: Failure) -> Self {
        Self::Shown(failure)
    }
}

struct TrustedRequest {
    realm: RealmName,
    client: Client,
    redirect_uri: String,
    scopes: Vec<String>,
    state: Option<String>,
    nonce: Option<String>,
    response_type: ResponseType,
    response_mode: ResponseMode,
    /// None for a request that asks for no code.
    code_challenge: Option<String>,
    /// How the person must have proved who they are for a session to serve.
    proof: ProofAsked,
    /// The identity token that names the person the client expects.
    id_token_hint: Option<String>,
    /// The claims the request names one by one, when it names any.
    claims: Option<ClaimsRequest>,
}

/// What `prompt` and `max_age` ask of the session that would answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProofAsked {
    /// A sign-in now, whatever session there is.
    fresh: bool,
    /// No page: a session answers, or the client is told one is needed.
    silent: bool,
    /// The person is asked to allow the client again, even what they allowed.
    consent: bool,
    /// A session older than this many seconds does not answer.
    max_age: Option<i64>,
}

/// Reads `prompt` and `max_age`. A value this realm does not know, `none`
/// beside another, or an age that is not a count of seconds is refused. An
/// age too long to be held is read as the longest that is: no session is
/// that old, and it asks nothing more of one.
fn read_proof_asked(prompt: Option<&str>, max_age: Option<&str>) -> Option<ProofAsked> {
    let mut asked = ProofAsked {
        fresh: false,
        silent: false,
        consent: false,
        max_age: None,
    };
    let prompts: Vec<&str> = prompt
        .unwrap_or_default()
        .split(' ')
        .filter(|value| !value.is_empty())
        .collect();
    for value in &prompts {
        match *value {
            "none" => asked.silent = true,
            // No account picker yet: the person picks the account by its name.
            "login" | "select_account" => asked.fresh = true,
            "consent" => asked.consent = true,
            _ => return None,
        }
    }
    if asked.silent && prompts.len() > 1 {
        return None;
    }
    // A parameter sent without a value is one that was not sent (RFC 6749, 3.1).
    if let Some(written) = max_age.filter(|written| !written.is_empty()) {
        if !written.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        // Digits alone fail to parse only past the largest count held.
        asked.max_age = Some(written.parse().unwrap_or(i64::MAX));
    }
    Some(asked)
}

/// What a code grants of the scopes asked when the person was shown no page
/// in this request: all but `offline_access`, which only a consent given on
/// the page of the request itself grants (OpenID Connect Core 1.0, section
/// 11). A request that asked it without one is not refused for it.
pub(crate) fn leave_out_offline_access(scopes: &[String]) -> Vec<String> {
    scopes
        .iter()
        .filter(|scope| *scope != OFFLINE_ACCESS_SCOPE)
        .cloned()
        .collect()
}

/// Percent-encodes a value for a query string.
pub(super) fn write_query_value(location: &mut String, value: &str) {
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            location.push(char::from(byte));
        } else {
            let _ = write!(location, "%{byte:02X}");
        }
    }
}

/// The scopes a request asks, each once and in its order. Nothing when one
/// is not written as a scope, or is not one the client may be given.
fn read_asked_scopes(asked: Option<&str>, client: &Client) -> Option<Vec<String>> {
    let mut scopes = Vec::new();
    for token in asked
        .unwrap_or_default()
        .split(' ')
        .filter(|token| !token.is_empty())
    {
        if check_scope_token(token).is_err()
            || !client.scopes.iter().any(|allowed| allowed == token)
        {
            return None;
        }
        if !scopes.iter().any(|known| known == token) {
            scopes.push(token.to_owned());
        }
    }
    Some(scopes)
}

/// The redirect URI a request is answered on: one its client registered,
/// compared by equality. Posted from this origin to its own host, a form
/// carries the cookies of the person to whichever of its pages the address
/// names, as if that page sent it: no page that posts there is served, a
/// refusal included.
fn trust_redirect_uri(
    app: &App,
    client: &Client,
    parameters: &AuthorizationParameters<'_>,
) -> Result<String, Failure> {
    let redirect_uri = parameters
        .redirect_uri
        .filter(|asked| {
            client
                .redirect_uris
                .iter()
                .any(|registered| registered == asked)
        })
        .ok_or(Failure::new(ErrorCode::RedirectUriMismatch))?;
    let posted =
        parameters.response_mode.and_then(ResponseMode::parse) == Some(ResponseMode::FormPost);
    if posted && is_on_origin(redirect_uri, &app.settings.public_origin) {
        return Err(Failure::new(ErrorCode::AnswerPostedToDeployment));
    }
    Ok(redirect_uri.to_owned())
}

/// Whether a value a client sends to be kept and echoed back is too long,
/// or holds a character no client writes on purpose: such a value is
/// neither kept nor echoed back.
fn is_unacceptable_value(value: &str) -> bool {
    value.len() > OPAQUE_VALUE_MAX_BYTES || value.chars().any(char::is_control)
}

/// The refusal of a request whose redirect URI is trusted, sent there as
/// its answer would have gone, with the `state` it sent when it may be
/// echoed back.
fn write_refusal(
    redirect_uri: &str,
    parameters: &AuthorizationParameters<'_>,
    declared: &[ResponseType],
    issuer: &str,
    error: OAuthError,
) -> AuthorizationRefusal {
    let refused_in = choose_refusal_mode(
        parameters.response_mode,
        parameters.response_type.and_then(ResponseType::read),
        declared,
        redirect_uri,
    );
    AuthorizationRefusal::Returned {
        response: AuthorizationResponse::write(
            redirect_uri,
            refused_in,
            issuer,
            parameters
                .state
                .filter(|state| !is_unacceptable_value(state)),
            vec![("error", error.name().to_owned())],
        ),
    }
}

/// Refuses a request on what its query says, before anything it carries is
/// believed: sent to the redirect URI of the query when its client
/// registered it, else shown as `shown`.
fn refuse_on_query(
    app: &App,
    client: &Client,
    query: &AuthorizationParameters<'_>,
    issuer: &str,
    error: OAuthError,
    shown: ErrorCode,
) -> AuthorizationRefusal {
    match trust_redirect_uri(app, client, query) {
        Ok(redirect_uri) => {
            write_refusal(&redirect_uri, query, &client.response_types, issuer, error)
        }
        Err(_) => Failure::new(shown).into(),
    }
}

/// Reads the client a request names, enabled and sending people through
/// this endpoint, with what proves it when the request is signed: read by
/// the one statement that identifies a client.
async fn read_requesting_client(
    work: &mut dyn UnitOfWork,
    query: &AuthorizationParameters<'_>,
) -> Result<(Client, Option<KeptProof>), Failure> {
    let client_id = query
        .client_id
        .ok_or(Failure::new(ErrorCode::ClientNotFound))?;
    let found = match query.request {
        Some(_) => read_named_client_with_proof(work, client_id)
            .await?
            .map(|(client, kept)| (client, Some(kept))),
        None => read_named_client(work, client_id)
            .await?
            .map(|client| (client, None)),
    };
    found
        .filter(|(client, _)| client.enabled && client.allows_authorization_code)
        .ok_or(Failure::new(ErrorCode::ClientNotFound))
}

/// Reads what a request carries in place of its query: the parameters of
/// its request object, or nothing when the query is the request. Refused on
/// what the query says, its object believed in nothing.
async fn read_carried_request(
    app: &App,
    work: &mut dyn UnitOfWork,
    client: &Client,
    kept: Option<&KeptProof>,
    issuer: &str,
    query: &AuthorizationParameters<'_>,
) -> Result<Option<CarriedParameters>, AuthorizationRefusal> {
    let refuse = |error, shown| refuse_on_query(app, client, query, issuer, error, shown);
    match (query.request, query.request_uri) {
        // A client that requires its requests signed sends no other (RFC 9101, 10.5).
        (None, None) if client.require_signed_request_object => Err(refuse(
            OAuthError::InvalidRequest,
            ErrorCode::RequestInvalid,
        )),
        (None, None) => Ok(None),
        (Some(_), None) => {
            let kept = kept.ok_or(Failure::new(ErrorCode::Internal))?;
            read_signed_request(app, work, client, kept, issuer, query)
                .await?
                .map(Some)
                .ok_or_else(|| {
                    refuse(
                        OAuthError::InvalidRequestObject,
                        ErrorCode::RequestObjectInvalid,
                    )
                })
        }
        // Fetching an address a caller names is a request made in its name,
        // from inside, to wherever it points.
        (None, Some(_)) => Err(refuse(
            OAuthError::RequestUriNotSupported,
            ErrorCode::RequestInvalid,
        )),
        (Some(_), Some(_)) => Err(refuse(
            OAuthError::InvalidRequest,
            ErrorCode::RequestInvalid,
        )),
    }
}

/// Reads the claims a request names, once: none when it names none. One
/// that cannot be read, or names claims for userinfo with no access token to
/// tell them to (OpenID Connect Core 1.0, section 5.5), is invalid. A level
/// the realm has no name for is out of reach of any sign-in: the client is
/// told before anyone signs in.
fn read_named_claims(
    written: Option<&str>,
    response_type: ResponseType,
) -> Result<Option<ClaimsRequest>, OAuthError> {
    let Some(text) = written.filter(|text| !text.is_empty()) else {
        return Ok(None);
    };
    let claims = read_claims_parameter(text)
        .ok_or(OAuthError::InvalidRequest)?
        .into_named();
    let tells_userinfo = response_type.issues_code() || response_type.issues_access_token();
    if claims
        .as_ref()
        .is_some_and(|asked| !asked.userinfo.is_empty() && !tells_userinfo)
    {
        return Err(OAuthError::InvalidRequest);
    }
    if RequiredLevel::read(claims.as_ref()) == RequiredLevel::Unknown {
        return Err(OAuthError::UnmetAuthenticationRequirements);
    }
    Ok(claims)
}

async fn trust_request(
    app: &App,
    realm: &str,
    query: &AuthorizationParameters<'_>,
    work_slot: &mut Option<Box<dyn UnitOfWork>>,
) -> Result<TrustedRequest, AuthorizationRefusal> {
    let (realm, scope) = resolve_realm(app, realm).await?;
    let work = work_slot.insert(app.storage.begin(scope).await.map_err(Failure::from)?);

    // A parameter sent without a value is one that was not sent (RFC 6749, 3.1).
    let query = AuthorizationParameters {
        request: query.request.filter(|text| !text.is_empty()),
        request_uri: query.request_uri.filter(|text| !text.is_empty()),
        ..*query
    };
    // Shown, never returned: there is nowhere trusted to return to yet.
    let (client, kept) = read_requesting_client(work.as_mut(), &query).await?;
    let issuer = name_issuer(&app.settings, &realm);
    let carried =
        read_carried_request(app, work.as_mut(), &client, kept.as_ref(), &issuer, &query).await?;
    let parameters = carried
        .as_ref()
        .map_or(query, |carried| carried.over(&query));
    let redirect_uri = trust_redirect_uri(app, &client, &parameters)?;

    let state = parameters
        .state
        .filter(|state| !is_unacceptable_value(state));
    let asked_type = parameters.response_type.and_then(ResponseType::read);
    let declared = &client.response_types;
    let returned =
        |error: OAuthError| write_refusal(&redirect_uri, &parameters, declared, &issuer, error);

    if parameters.state.is_some_and(is_unacceptable_value)
        || parameters.nonce.is_some_and(is_unacceptable_value)
    {
        return Err(returned(OAuthError::InvalidRequest));
    }
    let response_type = asked_type.ok_or_else(|| returned(OAuthError::UnsupportedResponseType))?;
    // Declared one by one: a client is handed back nothing it was not given.
    if !declared.contains(&response_type) {
        return Err(returned(OAuthError::UnauthorizedClient));
    }
    let response_mode = choose_response_mode(
        parameters.response_mode,
        response_type,
        declared,
        &redirect_uri,
    )
    .map_err(returned)?;
    let code_challenge = if response_type.issues_code() {
        let challenge = parameters
            .code_challenge
            .filter(|challenge| is_well_formed_challenge(challenge));
        let (Some(challenge), Some("S256")) = (challenge, parameters.code_challenge_method) else {
            return Err(returned(OAuthError::InvalidRequest));
        };
        Some(challenge.to_owned())
    } else {
        None
    };
    // Nothing else binds an identity token signed here to the request that
    // asked for it (OpenID Connect Core 1.0, sections 3.2.2.1 and 3.3.2.11).
    if response_type.issues_id_token() && parameters.nonce.is_none_or(str::is_empty) {
        return Err(returned(OAuthError::InvalidRequest));
    }
    let mut proof = read_proof_asked(parameters.prompt, parameters.max_age)
        .ok_or_else(|| returned(OAuthError::InvalidRequest))?;
    // Sent back to this machine, a public client is whatever listens there
    // (RFC 8252, section 8.6), and to a host kept before it could be read, it
    // may be: the person answers each request.
    let return_host = read_redirect_host(&redirect_uri);
    if client.is_public() && (return_host.is_empty() || is_loopback_host(return_host)) {
        proof.consent = true;
    }
    let mut scopes = read_asked_scopes(parameters.scope, &client)
        .ok_or_else(|| returned(OAuthError::InvalidScope))?;
    // An identity token answers a request of OpenID Connect, and only that.
    if response_type.issues_id_token() && !scopes.iter().any(|scope| scope == "openid") {
        return Err(returned(OAuthError::InvalidRequest));
    }
    // Without a code nothing is ever refreshed: no grant offline is asked.
    if !response_type.issues_code() {
        scopes.retain(|scope| scope != OFFLINE_ACCESS_SCOPE);
    }
    let claims = read_named_claims(parameters.claims, response_type).map_err(returned)?;
    Ok(TrustedRequest {
        realm,
        client,
        redirect_uri,
        scopes,
        state: state.map(str::to_owned),
        nonce: parameters.nonce.map(str::to_owned),
        response_type,
        response_mode,
        code_challenge,
        proof,
        id_token_hint: parameters
            .id_token_hint
            .filter(|hint| !hint.is_empty())
            .map(str::to_owned),
        claims,
    })
}

pub(crate) struct AnswerGrant<'a> {
    pub(crate) realm: &'a RealmName,
    pub(crate) subject: AnswerSubject<'a>,
    pub(crate) redirect_uri: &'a str,
    pub(crate) scopes: &'a [String],
    pub(crate) state: Option<&'a str>,
    pub(crate) nonce: Option<&'a str>,
    pub(crate) response_type: ResponseType,
    pub(crate) response_mode: ResponseMode,
    pub(crate) code_challenge: Option<&'a str>,
    pub(crate) authenticated_at: time::OffsetDateTime,
    pub(crate) claims: Option<&'a ClaimsRequest>,
}

/// The answer to a request, and what the chain is to say of what it signed.
pub(crate) struct IssuedAnswer {
    pub(crate) response: AuthorizationResponse,
    pub(crate) told: Option<Value>,
}

/// Mints a code, keeps its digest, and returns it.
async fn issue_code(
    app: &App,
    work: &mut dyn UnitOfWork,
    grant: &AnswerGrant<'_>,
) -> Result<String, Failure> {
    let code_challenge = grant
        .code_challenge
        .ok_or(Failure::new(ErrorCode::Internal))?;
    let mut random = [0_u8; 32];
    app.random
        .fill(&mut random)
        .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
    let code = URL_SAFE_NO_PAD.encode(random);
    work.insert_authorization_code(&AuthorizationCode {
        code_digest: app.digester.sha256(code.as_bytes()).to_vec(),
        client_id: grant.subject.client_id().to_owned(),
        person: grant.subject.person(),
        session: grant.subject.session(),
        redirect_uri: grant.redirect_uri.to_owned(),
        scopes: grant.scopes.to_vec(),
        nonce: grant.nonce.map(str::to_owned),
        code_challenge: code_challenge.to_owned(),
        authenticated_at: grant.authenticated_at,
        expires_at: app.now() + CODE_LIFETIME,
        claims: grant.claims.cloned(),
    })
    .await?;
    Ok(code)
}

/// Issues what the request asked for: a code, the tokens signed here, or
/// both, the code first since the identity token may bind it. Before
/// anything, the session records that it served the client, which only a
/// session still active does: one that ended meanwhile is answered nothing.
/// The caller says in the chain what was signed, last.
///
/// # Errors
///
/// Returns [`ErrorCode::SessionRequired`] for a session that ended or
/// expired meanwhile, or what issuing fails with.
pub(crate) async fn issue_answer(
    app: &App,
    work: &mut dyn UnitOfWork,
    grant: AnswerGrant<'_>,
) -> Result<IssuedAnswer, Failure> {
    let (session, client_id) = (grant.subject.session(), grant.subject.client_id());
    match work
        .record_served_client(session, client_id, app.now())
        .await?
    {
        ServedRecord::Written | ServedRecord::AlreadyWritten => {}
        ServedRecord::SessionEnded => return Err(Failure::new(ErrorCode::SessionRequired)),
    }
    let issuer = name_issuer(&app.settings, grant.realm);
    let code = if grant.response_type.issues_code() {
        Some(issue_code(app, work, &grant).await?)
    } else {
        None
    };
    let mut answer: Vec<(&'static str, String)> =
        code.iter().map(|code| ("code", code.clone())).collect();
    let mut told = None;
    if grant.response_type.issues_token() {
        let signed = sign_at_authorization(
            app,
            work,
            AuthorizationSigning {
                issuer: &issuer,
                subject: grant.subject,
                scopes: grant.scopes,
                nonce: grant.nonce,
                response_type: grant.response_type,
                code: code.as_deref(),
                claims: grant.claims,
            },
        )
        .await?;
        answer.extend(signed.parameters);
        told = Some(signed.told);
    }
    let response = AuthorizationResponse::write(
        grant.redirect_uri,
        grant.response_mode,
        &issuer,
        grant.state,
        answer,
    );
    Ok(IssuedAnswer { response, told })
}

/// Says in the chain what an answer signed, if it signed anything. Called
/// last: the head of the chain stays locked from the event to the commit.
pub(crate) async fn record_signed_answer(
    app: &App,
    work: &mut dyn UnitOfWork,
    told: Option<Value>,
) -> Result<(), Failure> {
    match told {
        Some(told) => record_event(app, work, EventKind::TokenIssued, told).await,
        None => Ok(()),
    }
}

/// The person a hint names: the one the client expects, whom the session of
/// someone else does not answer for. A hint that is not an identity token
/// this realm gave this very client is refused, whatever session there is.
async fn read_hinted_person(
    app: &App,
    work: &mut dyn UnitOfWork,
    trusted: &TrustedRequest,
    issuer: &str,
    hint: &str,
) -> Result<Uuid, AuthorizationRefusal> {
    read_identity_hint(app, work, issuer, hint)
        .await?
        .filter(|named| named.client_id == trusted.client.client_id)
        .and_then(|named| Uuid::parse_str(&named.subject).ok())
        .ok_or_else(|| tell_client(trusted, issuer, OAuthError::InvalidRequest))
}

/// The claims a request names that its person must allow one by one: those
/// the client may be given, in `entitled`, that none of the `covering` scopes
/// says. Read only for a request that names claims.
pub(crate) async fn list_owing_claims(
    work: &mut dyn UnitOfWork,
    client_id: &str,
    entitled: &[String],
    covering: &[String],
    claims: Option<&ClaimsRequest>,
) -> Result<Vec<String>, Failure> {
    let Some(asked) = claims else {
        return Ok(Vec::new());
    };
    let mappers = work.list_mappers(client_id).await?;
    Ok(list_claims_owing_consent(
        asked, &mappers, entitled, covering,
    ))
}

/// Where what a person allowed a client leaves a request of it.
enum ConsentStanding {
    /// They answer on a page first.
    Owed,
    /// Nothing is owed. What they allowed a client that asks them, held or
    /// read in the unit of work that answers; `None` for a client that asks
    /// nobody.
    Given(Option<Allowance>),
}

/// Whether `person` must allow the client before it gets an answer of
/// `response_type`, read in the unit of work that would issue it. What they
/// allowed is read only where it decides: for a client that requires
/// consent, unless it asked again. It is held until the commit when the
/// answer signs tokens here: a withdrawal waits, and nothing reads it again.
async fn judge_consent(
    work: &mut dyn UnitOfWork,
    client: &Client,
    prompted: bool,
    person: Uuid,
    trusted: &TrustedRequest,
) -> Result<ConsentStanding, Failure> {
    let decides = client.requires_consent && !prompted;
    let allowed = match (decides, trusted.response_type.issues_token()) {
        (false, _) => None,
        (true, true) => {
            work.hold_consent(person, &client.client_id, ConsentHold::Shared)
                .await?
        }
        (true, false) => work
            .read_consent(person, &client.client_id)
            .await?
            .map(|held| Allowance {
                scopes: held.scopes,
                claims: held.claims,
            }),
    };
    let owing = if decides {
        let covering = list_covering_scopes(&trusted.scopes, allowed.as_ref());
        let claims = trusted.claims.as_ref();
        list_owing_claims(work, &client.client_id, &client.scopes, &covering, claims).await?
    } else {
        Vec::new()
    };
    let terms = ConsentTerms {
        requires_consent: client.requires_consent,
        allowed,
        client_scopes: client.scopes.clone(),
    };
    if is_consent_owed(&terms, prompted, &trusted.scopes, &owing) {
        return Ok(ConsentStanding::Owed);
    }
    let allowed = terms.allowed.unwrap_or_default();
    Ok(ConsentStanding::Given(
        client.requires_consent.then_some(allowed),
    ))
}

/// Keeps a request until a person signs in for it, or until the person of
/// `consent_session` answers whether they allow the client. Gives back its
/// id and the secret only the browser that asked holds.
async fn keep_pending_authorization(
    app: &App,
    work: &mut dyn UnitOfWork,
    trusted: TrustedRequest,
    expected_person: Option<Uuid>,
    consent_session: Option<Uuid>,
) -> Result<(Uuid, Vec<u8>), Failure> {
    let mut browser_secret = vec![0_u8; 32];
    app.random
        .fill(&mut browser_secret)
        .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
    let pending = PendingAuthorization {
        id: mint_id(app)?,
        browser_digest: app.digester.sha256(&browser_secret).to_vec(),
        client_id: trusted.client.client_id,
        redirect_uri: trusted.redirect_uri,
        scopes: trusted.scopes,
        state: trusted.state,
        nonce: trusted.nonce,
        response_type: trusted.response_type,
        response_mode: trusted.response_mode,
        code_challenge: trusted.code_challenge,
        expires_at: app.now() + PENDING_LIFETIME,
        expected_person,
        first_factor: None,
        key_proof: None,
        consent_prompted: trusted.proof.consent,
        consent_session,
        claims: trusted.claims,
    };
    work.insert_pending_authorization(&pending)
        .await
        .map_err(Failure::from)?;
    Ok((pending.id, browser_secret))
}

/// Leaves a request waiting, as [`keep_pending_authorization`] keeps it, and
/// commits. Each keeps a row for ten minutes: it is counted against the
/// caller first, whether it waits for a sign-in or for a consent.
async fn leave_request_waiting(
    app: &App,
    work_slot: &mut Option<Box<dyn UnitOfWork>>,
    parameters: &AuthorizationParameters<'_>,
    trusted: TrustedRequest,
    expected_person: Option<Uuid>,
    consent_session: Option<Uuid>,
) -> Result<(Uuid, Secret), Failure> {
    let mut work = work_slot.take().ok_or(Failure::new(ErrorCode::Internal))?;
    admit_pending_sign_in(
        app,
        work.as_mut(),
        parameters.caller,
        parameters.known_browsers,
    )
    .await?;
    let (request, browser_secret) = keep_pending_authorization(
        app,
        work.as_mut(),
        trusted,
        expected_person,
        consent_session,
    )
    .await?;
    work.commit().await?;
    Ok((request, Secret::new(browser_secret)))
}

/// Sends the client back the error of a request it got right, as its
/// answer would have gone.
fn tell_client(trusted: &TrustedRequest, issuer: &str, error: OAuthError) -> AuthorizationRefusal {
    AuthorizationRefusal::Returned {
        response: AuthorizationResponse::write(
            &trusted.redirect_uri,
            trusted.response_mode,
            issuer,
            trusted.state.as_deref(),
            vec![("error", error.name().to_owned())],
        ),
    }
}

/// Answers a request that a session answers without a page, and commits.
/// The client, the session and the consent were read in the unit of work
/// it answers in.
async fn answer_with_session(
    app: &App,
    work_slot: &mut Option<Box<dyn UnitOfWork>>,
    trusted: &TrustedRequest,
    session: &Session,
    allowed: Option<&Allowance>,
) -> Result<Authorization, Failure> {
    let mut work = work_slot.take().ok_or(Failure::new(ErrorCode::Internal))?;
    let scopes = leave_out_offline_access(&trusted.scopes);
    let answered = issue_answer(
        app,
        work.as_mut(),
        AnswerGrant {
            realm: &trusted.realm,
            subject: AnswerSubject::Read {
                client: &trusted.client,
                session,
                allowed,
            },
            redirect_uri: &trusted.redirect_uri,
            scopes: &scopes,
            state: trusted.state.as_deref(),
            nonce: trusted.nonce.as_deref(),
            response_type: trusted.response_type,
            response_mode: trusted.response_mode,
            code_challenge: trusted.code_challenge.as_deref(),
            authenticated_at: session.authenticated_at,
            claims: trusted.claims.as_ref(),
        },
    )
    .await?;
    record_signed_answer(app, work.as_mut(), answered.told).await?;
    work.commit().await?;
    Ok(Authorization::Granted {
        response: answered.response,
    })
}

/// Whether a session answers what a request names of its person: the one
/// its hint names, the level it requires, and the subject it names (OpenID
/// Connect Core 1.0, section 3.1.2.2).
fn is_answered_by(trusted: &TrustedRequest, expected: Option<Uuid>, session: &Session) -> bool {
    expected.is_none_or(|expected| session.person == expected)
        && RequiredLevel::read(trusted.claims.as_ref()).is_met_by(Assurance::reached_by(session))
        && trusted
            .claims
            .as_ref()
            .is_none_or(|asked| asked.admits_subject(&session.person.to_string()))
}

/// Handles a request to the authorization endpoint.
///
/// # Errors
///
/// Returns the refusal, and whether it is shown to the person or returned
/// to the client.
pub async fn begin_authorization(
    app: &App,
    realm: &str,
    parameters: AuthorizationParameters<'_>,
    ticket: Option<&SessionTicket>,
) -> Result<Authorization, AuthorizationRefusal> {
    let mut work_slot = None;
    let trusted = trust_request(app, realm, &parameters, &mut work_slot).await?;
    let work = work_slot
        .as_mut()
        .ok_or(Failure::new(ErrorCode::Internal))?;

    let session = match ticket {
        Some(ticket) if !trusted.proof.fresh => {
            find_answering_session(app, work.as_mut(), ticket).await?
        }
        _ => None,
    };
    // A session proven longer ago than the client allows does not answer:
    // `max_age=0` asks a sign-in now, as `prompt=login` does.
    let now = app.now();
    let session = session.filter(|session| {
        trusted
            .proof
            .max_age
            .is_none_or(|max_age| (now - session.authenticated_at).whole_seconds() < max_age)
    });
    let issuer = name_issuer(&app.settings, &trusted.realm);
    let expected_person = match trusted.id_token_hint.as_deref() {
        Some(hint) => Some(read_hinted_person(app, work.as_mut(), &trusted, &issuer, hint).await?),
        None => None,
    };
    // What the person of the session allowed is judged first: without a
    // page, a client they must allow is told so whomever the request or its
    // hint names and whatever level it requires, and learns nothing of who
    // signed in.
    let mut standing = None;
    if let Some(session) = &session {
        let prompted = trusted.proof.consent;
        let client = &trusted.client;
        standing =
            Some(judge_consent(work.as_mut(), client, prompted, session.person, &trusted).await?);
    }
    if trusted.proof.silent && matches!(standing, Some(ConsentStanding::Owed)) {
        return Err(tell_client(&trusted, &issuer, OAuthError::ConsentRequired));
    }
    let session = session.filter(|session| is_answered_by(&trusted, expected_person, session));
    if session.is_none() && trusted.proof.silent {
        return Err(tell_client(&trusted, &issuer, OAuthError::LoginRequired));
    }
    if let (Some(session), Some(standing)) = (session, standing) {
        // A session alone gives no code to a client the person must allow:
        // they answer on a page.
        let ConsentStanding::Given(allowed) = standing else {
            let waiting_in = Some(session.id);
            let (request, browser_secret) = leave_request_waiting(
                app,
                &mut work_slot,
                &parameters,
                trusted,
                expected_person,
                waiting_in,
            )
            .await?;
            return Ok(Authorization::ConsentRequired {
                request,
                browser_secret,
            });
        };
        let answered =
            answer_with_session(app, &mut work_slot, &trusted, &session, allowed.as_ref()).await?;
        return Ok(answered);
    }

    let (request, browser_secret) = leave_request_waiting(
        app,
        &mut work_slot,
        &parameters,
        trusted,
        expected_person,
        None,
    )
    .await?;
    Ok(Authorization::SignInRequired {
        request,
        browser_secret,
    })
}

/// A person signed in on the login page of a pending request.
pub struct SignedInForRequest {
    /// Where the browser goes next: back to the client, with what it asked.
    pub response: AuthorizationResponse,
    pub ticket: SessionTicket,
    /// What the browser keeps, to be counted apart at its next sign-in.
    pub device_mark: DeviceMark,
}

/// What a person typed on one form of the sign-in page.
pub enum SignInAnswer<'a> {
    Password {
        name: &'a str,
        password: Secret,
    },
    /// The code of their authenticator application, after their password.
    Code(&'a str),
    /// What their browser handed back from their security key, after their
    /// password.
    Key(&'a serde_json::Value),
}

/// What a person typed on the sign-in page, and where it comes from.
pub struct TypedSignIn<'a> {
    pub answer: SignInAnswer<'a>,
    /// The address of the browser, as a believed proxy said.
    pub caller: Option<IpAddr>,
    /// The marks of earlier sign-ins the browser brings, the latest first.
    pub known_browsers: &'a [DeviceMark],
}

// Written by hand: the mark of the browser is not printed.
impl fmt::Debug for SignedInForRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedInForRequest")
            .field("response", &self.response)
            .field("ticket", &self.ticket)
            .field("device_mark", &"..")
            .finish()
    }
}

/// A person signed in on the page of a pending request whose client they
/// must allow first: the request waits for their answer.
#[derive(Debug)]
pub struct SignedInForConsent {
    pub request: Uuid,
    /// The session the request now waits in. Only it can answer.
    pub ticket: SessionTicket,
    pub device_mark: DeviceMark,
}

/// A person who signed in for a request that named someone else: the
/// browser goes back to the client with no session, and the one opened for
/// the request is ended.
#[derive(Debug)]
pub struct SentBackWithoutSession {
    pub response: AuthorizationResponse,
    pub device_mark: DeviceMark,
}

/// Where an answer leaves a pending request.
#[derive(Debug)]
pub enum SignInStep {
    Finished(SignedInForRequest),
    /// The password was right and the person owes a second factor: the page
    /// asks for it, and the request waits.
    SecondFactorRequired(OwedSecondFactor),
    ConsentRequired(SignedInForConsent),
    SentBack(SentBackWithoutSession),
}

/// What the page of a pending request asks next. One of the two is enough.
#[derive(Clone, Debug, PartialEq)]
pub struct OwedSecondFactor {
    /// A code of the person's authenticator application.
    pub code: bool,
    /// What the page hands to the browser for a security key to answer.
    pub key: Option<serde_json::Value>,
}

impl SignInStep {
    /// The redirection and the ticket, when the request is finished.
    #[must_use]
    pub fn into_finished(self) -> Option<SignedInForRequest> {
        match self {
            Self::Finished(finished) => Some(finished),
            Self::SecondFactorRequired(_) | Self::ConsentRequired(_) | Self::SentBack(_) => None,
        }
    }
}

/// Proves one answer for a pending request. What the person owes, when they
/// proved their password and owe a second factor: the request then waits.
async fn prove_answer(
    app: &App,
    scope: RealmScope,
    pending: &PendingAuthorization,
    typed: TypedSignIn<'_>,
) -> Result<Result<SignedIn, OwedSecondFactor>, Failure> {
    let expired = || Failure::new(ErrorCode::AuthorizationRequestExpired);
    let (caller, marks) = (typed.caller, typed.known_browsers);
    match typed.answer {
        SignInAnswer::Password { name, password } => {
            match sign_in_with_password(app, scope, name, password, caller, marks).await? {
                FirstStep::SignedIn(signed_in) => Ok(Ok(signed_in)),
                FirstStep::SecondFactorRequired(owed) => {
                    // Written on the request, which only this browser can
                    // finish: what comes next is asked of this person and
                    // no other.
                    let key_proof = owed.key.map(|ceremony| PendingKeyProof {
                        state: ceremony.state,
                        options: ceremony.options,
                    });
                    let mut work = app.storage.begin(scope).await?;
                    let waiting = work
                        .mark_first_factor(
                            pending.id,
                            owed.person.id,
                            key_proof.as_ref(),
                            app.now(),
                        )
                        .await?;
                    work.commit().await?;
                    if !waiting {
                        return Err(expired());
                    }
                    Ok(Err(OwedSecondFactor {
                        code: owed.code,
                        key: key_proof.map(|proof| proof.options),
                    }))
                }
            }
        }
        SignInAnswer::Code(code) => {
            let person = pending.first_factor.ok_or_else(expired)?;
            finish_sign_in_with_code(app, scope, person, code, caller, marks)
                .await
                .map(Ok)
        }
        SignInAnswer::Key(answer) => {
            let person = pending.first_factor.ok_or_else(expired)?;
            let proof = pending.key_proof.as_ref().ok_or_else(expired)?;
            finish_sign_in_with_key(app, scope, person, &proof.state, answer, caller, marks)
                .await
                .map(Ok)
        }
    }
}

/// Takes one answer of a person on the page of a pending request, and
/// finishes the request when they owe nothing more.
///
/// # Errors
///
/// Returns [`ErrorCode::AuthorizationRequestExpired`] when the request is
/// unknown, expired, was started by another browser, or is given a code
/// before any password: all answer alike. Returns [`ErrorCode::SignInFailed`]
/// or [`ErrorCode::CodeRejected`] when the person is refused: the request
/// then still waits. Returns the storage failure otherwise.
pub async fn finish_sign_in(
    app: &App,
    realm: &str,
    request: Uuid,
    browser_secret: &Secret,
    typed: TypedSignIn<'_>,
) -> Result<SignInStep, Failure> {
    let (realm, scope) = resolve_realm(app, realm).await?;
    let expired = || Failure::new(ErrorCode::AuthorizationRequestExpired);

    let mut work = app.storage.begin(scope).await?;
    let pending = work.read_pending_authorization(request, app.now()).await?;
    drop(work);
    let presented = app.digester.sha256(browser_secret.expose());
    let expected = pending
        .as_ref()
        .map_or(&[0_u8; 32][..], |known| known.browser_digest.as_slice());
    let same_browser = app.digester.equal_in_constant_time(&presented, expected);
    let Some(pending) = pending.filter(|_| same_browser) else {
        return Err(expired());
    };
    let signed_in = match prove_answer(app, scope, &pending, typed).await? {
        Ok(signed_in) => signed_in,
        Err(owed) => return Ok(SignInStep::SecondFactorRequired(owed)),
    };
    let session = signed_in.session;
    match answer_signed_in(app, &realm, scope, &pending, signed_in).await {
        Ok(step) => Ok(step),
        // Whatever failed, its unit is gone with the call: the session opened
        // for nothing ends in a unit of its own, and the refusal is told.
        Err(refused) => {
            end_orphan_session(app, scope, session).await;
            Err(refused)
        }
    }
}

/// Why a person who just signed in for a request gets no answer for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignInRefusal {
    /// The request named another subject in its claims: no answer is ever
    /// given for anyone else (OpenID Connect Core 1.0, section 3.1.2.2).
    AnotherSubject,
    /// An identity token hint named another person: whoever signed in did so
    /// for themselves.
    AnotherPerson,
    /// The sign-in reached none of the levels the request required: the
    /// person stays signed in, and the client is told.
    LevelNotReached,
}

impl SignInRefusal {
    fn error(self) -> OAuthError {
        match self {
            Self::AnotherSubject | Self::AnotherPerson => OAuthError::LoginRequired,
            Self::LevelNotReached => OAuthError::UnmetAuthenticationRequirements,
        }
    }
}

/// Whether a request answers the person who just signed in for it: the
/// subject its claims name, the person its hint names, and the level it
/// requires, in that order.
fn judge_sign_in(pending: &PendingAuthorization, signed_in: &SignedIn) -> Option<SignInRefusal> {
    let person = signed_in.person.id;
    if pending
        .claims
        .as_ref()
        .is_some_and(|asked| !asked.admits_subject(&person.to_string()))
    {
        return Some(SignInRefusal::AnotherSubject);
    }
    if pending
        .expected_person
        .is_some_and(|expected| expected != person)
    {
        return Some(SignInRefusal::AnotherPerson);
    }
    let met = RequiredLevel::read(pending.claims.as_ref()).is_met_by(signed_in.reached);
    (!met).then_some(SignInRefusal::LevelNotReached)
}

/// Answers a pending request for the person who just signed in for it, in
/// one unit of work: the consent they owe first, or what the client asked.
async fn answer_signed_in(
    app: &App,
    realm: &RealmName,
    scope: RealmScope,
    pending: &PendingAuthorization,
    signed_in: SignedIn,
) -> Result<SignInStep, Failure> {
    let request = pending.id;
    let expired = || Failure::new(ErrorCode::AuthorizationRequestExpired);
    let mut work = app.storage.begin(scope).await?;
    // Whoever the request does not answer is sent back below, and is asked
    // nothing.
    let refusal = judge_sign_in(pending, &signed_in);
    if refusal.is_none()
        && is_consent_owed_after_sign_in(work.as_mut(), pending, signed_in.person.id).await?
    {
        // Marked once: of two submissions of one page, the other signed in
        // for nothing.
        if !work
            .mark_consent_owed(request, signed_in.session, app.now())
            .await?
        {
            return Err(expired());
        }
        work.commit().await?;
        return Ok(SignInStep::ConsentRequired(SignedInForConsent {
            request,
            ticket: signed_in.ticket,
            device_mark: signed_in.device_mark,
        }));
    }
    // Taken, not read: of two submissions of one page, one finishes the
    // request. The other signed in for nothing.
    let Some(pending) = work.take_pending_authorization(request, app.now()).await? else {
        return Err(expired());
    };
    if let Some(refusal) = refusal {
        work.commit().await?;
        let issuer = name_issuer(&app.settings, realm);
        let response = AuthorizationResponse::write(
            &pending.redirect_uri,
            pending.response_mode,
            &issuer,
            pending.state.as_deref(),
            vec![("error", refusal.error().name().to_owned())],
        );
        if refusal == SignInRefusal::AnotherSubject {
            end_orphan_session(app, scope, signed_in.session).await;
            return Ok(SignInStep::SentBack(SentBackWithoutSession {
                response,
                device_mark: signed_in.device_mark,
            }));
        }
        return Ok(SignInStep::Finished(SignedInForRequest {
            response,
            ticket: signed_in.ticket,
            device_mark: signed_in.device_mark,
        }));
    }
    let scopes = leave_out_offline_access(&pending.scopes);
    let issued = issue_answer(
        app,
        work.as_mut(),
        AnswerGrant {
            realm,
            subject: AnswerSubject::Named {
                client_id: &pending.client_id,
                session: signed_in.session,
                person: signed_in.person.id,
            },
            redirect_uri: &pending.redirect_uri,
            scopes: &scopes,
            state: pending.state.as_deref(),
            nonce: pending.nonce.as_deref(),
            response_type: pending.response_type,
            response_mode: pending.response_mode,
            code_challenge: pending.code_challenge.as_deref(),
            authenticated_at: app.now(),
            claims: pending.claims.as_ref(),
        },
    )
    .await?;
    record_signed_answer(app, work.as_mut(), issued.told).await?;
    work.commit().await?;
    Ok(SignInStep::Finished(SignedInForRequest {
        response: issued.response,
        ticket: signed_in.ticket,
        device_mark: signed_in.device_mark,
    }))
}

/// Whether the person who just signed in must allow the client of a request
/// before it gets a code. Asked again, they are, and nothing is read. The
/// flag of the client is read now, not when the request was made: a client
/// marked since asks. A client gone since is asked for, and its page says
/// it is gone.
async fn is_consent_owed_after_sign_in(
    work: &mut dyn UnitOfWork,
    pending: &PendingAuthorization,
    person: Uuid,
) -> Result<bool, Failure> {
    if pending.consent_prompted {
        return Ok(true);
    }
    let Some(terms) = work.read_consent_terms(person, &pending.client_id).await? else {
        return Ok(true);
    };
    let owing = if terms.requires_consent {
        let covering = list_covering_scopes(&pending.scopes, terms.allowed.as_ref());
        let claims = pending.claims.as_ref();
        let entitled = &terms.client_scopes;
        list_owing_claims(work, &pending.client_id, entitled, &covering, claims).await?
    } else {
        Vec::new()
    };
    Ok(is_consent_owed(&terms, false, &pending.scopes, &owing))
}

/// Ends the session of a submission that lost its request to another, or
/// whose request was answered nothing. A failure goes to the journal and no
/// further: the caller tells its own refusal, and the session ends when it
/// expires.
async fn end_orphan_session(app: &App, scope: RealmScope, session: Uuid) {
    let ended = async {
        let mut work = app.storage.begin(scope).await?;
        if let Some(orphan) = work.read_session(session).await? {
            // It answered nothing: no client it served is told.
            close_session(app, work.as_mut(), &orphan.session).await?;
            work.commit().await?;
        }
        Ok::<(), Failure>(())
    }
    .await;
    if let Err(failure) = ended {
        tracing::error!(
            code = failure.code.slug(),
            detail = failure.detail.as_deref(),
            %session,
            "a session opened for a request answered nothing stays open until it expires"
        );
    }
}

/// Tells what a pending request still asks of the browser that started it,
/// to show its page again after a refused answer. Nothing, when no password
/// was proven for it.
///
/// # Errors
///
/// Returns [`ErrorCode::AuthorizationRequestExpired`] as [`finish_sign_in`]
/// does, or the storage failure.
pub async fn describe_owed_second_factor(
    app: &App,
    realm: &str,
    request: Uuid,
    browser_secret: &Secret,
) -> Result<Option<OwedSecondFactor>, Failure> {
    let (_, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    let pending = work.read_pending_authorization(request, app.now()).await?;
    let presented = app.digester.sha256(browser_secret.expose());
    let expected = pending
        .as_ref()
        .map_or(&[0_u8; 32][..], |known| known.browser_digest.as_slice());
    let same_browser = app.digester.equal_in_constant_time(&presented, expected);
    let Some(pending) = pending.filter(|_| same_browser) else {
        return Err(Failure::new(ErrorCode::AuthorizationRequestExpired));
    };
    let Some(person) = pending.first_factor else {
        return Ok(None);
    };
    let code = work
        .read_totp(person)
        .await?
        .is_some_and(|authenticator| authenticator.confirmed_at.is_some());
    Ok(Some(OwedSecondFactor {
        code,
        key: pending.key_proof.map(|proof| proof.options),
    }))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value;
    use uuid::Uuid;

    use super::{
        Authorization, AuthorizationParameters, AuthorizationRefusal, SignInAnswer, TypedSignIn,
        begin_authorization, finish_sign_in,
    };
    use crate::app::App;
    use crate::error::ErrorCode;
    use crate::login::device::DeviceMark;
    use crate::login::session::SessionTicket;
    use crate::oidc::errors::OAuthError;
    use crate::oidc::token::{TokenRequest, TokenResponse, grant_token};
    use crate::ports::crypto::Digester;
    use crate::secret::Secret;
    use crate::testkit::digest::WeakDigester;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::{create_application, create_person, create_realm};
    use crate::testkit::memory::MemoryStorage;

    const CALLBACK: &str = "https://app.example.org/callback";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const PASSWORD: &str = "correct horse battery";
    const ISSUER: &str = "https://id.example.test/realms/acme";

    fn challenge() -> String {
        URL_SAFE_NO_PAD.encode(WeakDigester.sha256(VERIFIER.as_bytes()))
    }

    fn ask(challenge: &str) -> AuthorizationParameters<'_> {
        AuthorizationParameters {
            response_type: Some("code"),
            client_id: Some("webapp"),
            redirect_uri: Some(CALLBACK),
            scope: Some("openid profile email"),
            state: Some("st&te"),
            nonce: Some("n-0S6_WzA2Mj"),
            code_challenge: Some(challenge),
            code_challenge_method: Some("S256"),
            response_mode: None,
            prompt: None,
            max_age: None,
            id_token_hint: None,
            request: None,
            request_uri: None,
            claims: None,
            caller: None,
            known_browsers: &[],
        }
    }

    /// The realm `acme`, the person `ada`, and the application `webapp`.
    fn start(
        public: bool,
    ) -> (
        App,
        std::sync::Arc<MemoryStorage>,
        std::sync::Arc<crate::testkit::clock::FixedClock>,
        Option<Secret>,
    ) {
        let (app, storage, clock) = MemoryStorage::wire_with_clock();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        let secret = complete(create_application(&app, scope, "webapp", CALLBACK, public));
        (app, storage, clock, secret)
    }

    fn read_query(location: &str, name: &str) -> Option<String> {
        let query = location.split_once('?')?.1;
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| {
                value
                    .replace("%26", "&")
                    .replace("%3A", ":")
                    .replace("%2F", "/")
            })
        })
    }

    /// Goes through the endpoint, then the login page, and returns the redirection.
    fn sign_in_through_the_flow(app: &App) -> (String, SessionTicket) {
        sign_in_as(app, "ada")
    }

    fn sign_in_as(app: &App, name: &str) -> (String, SessionTicket) {
        let challenge = challenge();
        let begun = complete(begin_authorization(app, "acme", ask(&challenge), None))
            .expect("a pending request");
        let Authorization::SignInRequired {
            request,
            browser_secret,
        } = begun
        else {
            panic!("a person without a session must sign in: {begun:?}");
        };
        let signed_in = complete(finish_sign_in(
            app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name,
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person")
        .into_finished()
        .expect("a person who owes no code");
        (
            signed_in.response.write_location().expect("an address"),
            signed_in.ticket,
        )
    }

    fn exchange(
        app: &App,
        code: &str,
        secret: Option<&Secret>,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenResponse, OAuthError> {
        let request = TokenRequest {
            grant_type: Some("authorization_code"),
            client_id: Some("webapp"),
            client_secret: secret.map(|secret| {
                crate::clients::authenticate::PresentedSecret::Basic(Secret::new(
                    secret.expose().to_vec(),
                ))
            }),
            code: Some(code),
            redirect_uri: Some(redirect_uri),
            code_verifier: Some(verifier),
            ..TokenRequest::default()
        };
        complete(grant_token(app, "acme", request)).map_err(|failure| failure.error)
    }

    fn read_claims(token: &str) -> Value {
        let payload = token.split('.').nth(1).expect("a compact token");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
            .expect("claims")
    }

    #[test]
    fn a_person_signs_in_and_the_client_gets_tokens_that_say_who_signed_in() {
        let (app, _storage, _clock, secret) = start(false);

        let (location, _ticket) = sign_in_through_the_flow(&app);

        assert!(
            location.starts_with(&format!("{CALLBACK}?code=")),
            "{location}"
        );
        assert_eq!(
            read_query(&location, "state").as_deref(),
            Some("st&te"),
            "the state comes back as it was sent"
        );
        assert_eq!(
            read_query(&location, "iss").as_deref(),
            Some("https://id.example.test/realms/acme")
        );
        let code = read_query(&location, "code").expect("a code");
        let tokens = exchange(&app, &code, secret.as_ref(), VERIFIER, CALLBACK).expect("tokens");

        assert_eq!(tokens.scope, "openid profile email");
        let access = read_claims(&tokens.access_token);
        let identity = read_claims(tokens.id_token.as_deref().expect("an identity token"));
        assert_eq!(identity["aud"], "webapp");
        assert_eq!(identity["nonce"], "n-0S6_WzA2Mj");
        assert_eq!(identity["preferred_username"], "ada");
        assert_eq!(identity["email"], "ada@example.org");
        assert_eq!(
            identity["sub"], access["sub"],
            "both tokens name the same person"
        );
        assert_eq!(identity["sid"], access["sid"]);
        assert!(Uuid::parse_str(identity["sub"].as_str().expect("a subject")).is_ok());
        assert!(identity["auth_time"].is_i64());
        assert_eq!(
            identity["amr"],
            serde_json::json!(["pwd"]),
            "the password alone proved the person"
        );
        assert_eq!(identity["acr"], "1", "a password alone is one factor");
        assert_eq!(access["acr"], "1");
        assert_eq!(
            access["auth_time"], identity["auth_time"],
            "what a resource server weighs is in the access token too"
        );
    }

    fn refresh(app: &App, secret: Option<&Secret>, refresh_token: &str) -> Result<(), OAuthError> {
        let request = TokenRequest {
            grant_type: Some("refresh_token"),
            client_id: Some("webapp"),
            client_secret: secret.map(|secret| {
                crate::clients::authenticate::PresentedSecret::Basic(Secret::new(
                    secret.expose().to_vec(),
                ))
            }),
            refresh_token: Some(refresh_token),
            ..TokenRequest::default()
        };
        complete(grant_token(app, "acme", request))
            .map(|_| ())
            .map_err(|failure| failure.error)
    }

    fn read_revocations(app: &App, storage: &MemoryStorage) -> Vec<Value> {
        let (_, scope) =
            complete(crate::tenancy::resolve::resolve_realm(app, "acme")).expect("the realm");
        storage
            .read_audit_envelopes(scope.realm())
            .into_iter()
            .filter(|event| event["kind"] == "token.revoked")
            .collect()
    }

    #[test]
    fn a_code_presented_again_is_refused_and_takes_back_the_refresh_token_it_obtained() {
        let (app, storage, _clock, secret) = start(false);
        let (location, ticket) = sign_in_through_the_flow(&app);
        let code = read_query(&location, "code").expect("a code");
        let first = exchange(&app, &code, secret.as_ref(), VERIFIER, CALLBACK).expect("tokens");
        let refresh_token = first.refresh_token.expect("a refresh token");

        assert_eq!(
            exchange(&app, &code, secret.as_ref(), VERIFIER, CALLBACK).map(|_| ()),
            Err(OAuthError::InvalidGrant)
        );
        assert_eq!(
            refresh(&app, secret.as_ref(), &refresh_token),
            Err(OAuthError::InvalidGrant),
            "what the first exchange obtained is taken back"
        );
        assert_eq!(
            exchange(&app, &code, secret.as_ref(), VERIFIER, CALLBACK).map(|_| ()),
            Err(OAuthError::InvalidGrant)
        );
        let revocations = read_revocations(&app, &storage);
        assert_eq!(revocations.len(), 1, "taken back once: {revocations:?}");
        let told = &revocations[0]["payload"];
        assert_eq!(told["reason"], "code_replayed");
        assert_eq!(told["client_id"], "webapp");
        assert_eq!(told["session_id"], ticket.session.to_string(), "{told}");
        assert_eq!(told["tokens"], 1, "{told}");
        assert_eq!(told["last_used_at"], Value::Null, "never spent: {told}");
        // The exchange named the family it started, and in which session: a
        // stolen token is traced from one event to the other.
        let (_, scope) =
            complete(crate::tenancy::resolve::resolve_realm(&app, "acme")).expect("the realm");
        let issued = storage
            .read_audit_envelopes(scope.realm())
            .into_iter()
            .find(|event| event["kind"] == "token.issued")
            .expect("the exchange");
        assert_eq!(issued["payload"]["family"], told["family"], "{issued}");
        assert_eq!(
            issued["payload"]["session_id"], told["session_id"],
            "{issued}"
        );
    }

    #[test]
    fn a_spent_code_presented_by_another_client_takes_nothing_back() {
        let (app, storage, _clock, _secret) = start(true);
        let (_, scope) =
            complete(crate::tenancy::resolve::resolve_realm(&app, "acme")).expect("the realm");
        complete(create_application(
            &app,
            scope,
            "other",
            "https://other.example.org/callback",
            true,
        ));
        let (location, _ticket) = sign_in_through_the_flow(&app);
        let code = read_query(&location, "code").expect("a code");
        let first = exchange(&app, &code, None, VERIFIER, CALLBACK).expect("tokens");

        let from_other = TokenRequest {
            grant_type: Some("authorization_code"),
            client_id: Some("other"),
            code: Some(&code),
            redirect_uri: Some(CALLBACK),
            code_verifier: Some(VERIFIER),
            ..TokenRequest::default()
        };
        let refused = complete(grant_token(&app, "acme", from_other)).map(|_| ());
        assert_eq!(
            refused.map_err(|failure| failure.error),
            Err(OAuthError::InvalidGrant)
        );
        let refresh_token = first.refresh_token.expect("a refresh token");
        assert_eq!(refresh(&app, None, &refresh_token), Ok(()));
        assert!(read_revocations(&app, &storage).is_empty());
    }

    #[test]
    fn a_wrong_verifier_or_another_redirect_uri_is_refused_and_burns_the_code() {
        for (verifier, redirect_uri) in [
            ("another-verifier-of-the-right-length-0123456789", CALLBACK),
            (VERIFIER, "https://app.example.org/other"),
        ] {
            let (app, _storage, _clock, secret) = start(false);
            let (location, _ticket) = sign_in_through_the_flow(&app);
            let code = read_query(&location, "code").expect("a code");

            assert_eq!(
                exchange(&app, &code, secret.as_ref(), verifier, redirect_uri).map(|_| ()),
                Err(OAuthError::InvalidGrant)
            );
            assert_eq!(
                exchange(&app, &code, secret.as_ref(), VERIFIER, CALLBACK).map(|_| ()),
                Err(OAuthError::InvalidGrant),
                "a code presented once is gone, even to whoever holds the right verifier"
            );
        }
    }

    #[test]
    fn a_code_expires_after_a_minute_and_dies_with_the_session_that_made_it() {
        let (app, _storage, clock, secret) = start(false);
        let (location, _ticket) = sign_in_through_the_flow(&app);
        let code = read_query(&location, "code").expect("a code");
        clock.advance(Duration::from_mins(1));
        assert_eq!(
            exchange(&app, &code, secret.as_ref(), VERIFIER, CALLBACK).map(|_| ()),
            Err(OAuthError::InvalidGrant)
        );

        let (app, storage, _clock, secret) = start(false);
        let (location, _ticket) = sign_in_through_the_flow(&app);
        let code = read_query(&location, "code").expect("a code");
        storage.end_every_session();
        assert_eq!(
            exchange(&app, &code, secret.as_ref(), VERIFIER, CALLBACK).map(|_| ()),
            Err(OAuthError::InvalidGrant)
        );
    }

    #[test]
    fn a_confidential_client_must_prove_itself_and_a_public_client_has_only_the_verifier() {
        let (app, _storage, _clock, secret) = start(false);
        let (location, _ticket) = sign_in_through_the_flow(&app);
        let code = read_query(&location, "code").expect("a code");
        assert_eq!(
            exchange(&app, &code, None, VERIFIER, CALLBACK).map(|_| ()),
            Err(OAuthError::InvalidClient),
            "a confidential client without its secret"
        );
        assert!(
            exchange(&app, &code, secret.as_ref(), VERIFIER, CALLBACK).is_ok(),
            "the refusal came before the code was spent"
        );

        let (app, _storage, _clock, secret) = start(true);
        assert!(secret.is_none(), "a public client is given no secret");
        let (location, _ticket) = sign_in_through_the_flow(&app);
        let code = read_query(&location, "code").expect("a code");
        assert!(exchange(&app, &code, None, VERIFIER, CALLBACK).is_ok());
    }

    #[test]
    fn nothing_is_sent_to_a_client_or_a_redirect_uri_that_is_not_trusted() {
        let (app, _storage, _clock, _secret) = start(false);
        let challenge = challenge();
        let shown = |parameters: AuthorizationParameters<'_>| match complete(begin_authorization(
            &app, "acme", parameters, None,
        )) {
            Err(AuthorizationRefusal::Shown(failure)) => failure.code,
            other => panic!("the refusal must be shown to the person: {other:?}"),
        };

        assert_eq!(
            shown(AuthorizationParameters {
                client_id: Some("nobody"),
                ..ask(&challenge)
            }),
            ErrorCode::ClientNotFound
        );
        assert_eq!(
            shown(AuthorizationParameters {
                client_id: None,
                ..ask(&challenge)
            }),
            ErrorCode::ClientNotFound
        );
        for redirect_uri in [
            None,
            Some("https://evil.example.org/callback"),
            Some("https://app.example.org/callback/"),
            Some("https://app.example.org/callback?x=1"),
        ] {
            assert_eq!(
                shown(AuthorizationParameters {
                    redirect_uri,
                    ..ask(&challenge)
                }),
                ErrorCode::RedirectUriMismatch,
                "{redirect_uri:?}"
            );
        }
    }

    #[test]
    fn a_request_the_client_got_wrong_is_returned_to_its_registered_uri_with_its_state() {
        let (app, _storage, _clock, _secret) = start(false);
        let challenge = challenge();
        let returned = |parameters: AuthorizationParameters<'_>| match complete(
            begin_authorization(&app, "acme", parameters, None),
        ) {
            Err(AuthorizationRefusal::Returned { response }) => {
                let location = response.write_location().expect("an address");
                assert!(
                    location.starts_with(&format!("{CALLBACK}?error=")),
                    "{location}"
                );
                assert_eq!(read_query(&location, "state").as_deref(), Some("st&te"));
                read_query(&location, "error").expect("an error")
            }
            other => panic!("the refusal must go back to the client: {other:?}"),
        };

        assert_eq!(
            returned(AuthorizationParameters {
                response_type: Some("token"),
                ..ask(&challenge)
            }),
            OAuthError::UnsupportedResponseType.name()
        );
        assert_eq!(
            returned(AuthorizationParameters {
                code_challenge: None,
                ..ask(&challenge)
            }),
            OAuthError::InvalidRequest.name(),
            "no code without a challenge"
        );
        assert_eq!(
            returned(AuthorizationParameters {
                code_challenge_method: Some("plain"),
                ..ask(&challenge)
            }),
            OAuthError::InvalidRequest.name(),
            "S256 or nothing"
        );
        assert_eq!(
            returned(AuthorizationParameters {
                code_challenge_method: None,
                ..ask(&challenge)
            }),
            OAuthError::InvalidRequest.name()
        );
        assert_eq!(
            returned(AuthorizationParameters {
                scope: Some("openid admin"),
                ..ask(&challenge)
            }),
            OAuthError::InvalidScope.name()
        );
    }

    #[test]
    fn a_person_already_signed_in_is_not_asked_again_and_half_a_ticket_proves_nothing() {
        let (app, _storage, _clock, _secret) = start(false);
        let (_location, ticket) = sign_in_through_the_flow(&app);
        let challenge = challenge();

        let again = complete(begin_authorization(
            &app,
            "acme",
            ask(&challenge),
            Some(&ticket),
        ))
        .expect("an answer");
        assert!(matches!(again, Authorization::Granted { .. }), "{again:?}");

        let forged = SessionTicket {
            session: ticket.session,
            secret: Secret::new(vec![0; 32]),
        };
        let asked = complete(begin_authorization(
            &app,
            "acme",
            ask(&challenge),
            Some(&forged),
        ))
        .expect("an answer");
        assert!(
            matches!(asked, Authorization::SignInRequired { .. }),
            "the identifier of a session, which every token carries, opens nothing alone"
        );
    }

    #[test]
    fn a_pending_request_is_finished_only_by_the_browser_that_started_it_and_waits_through_a_wrong_password()
     {
        let (app, _storage, clock, _secret) = start(false);
        let challenge = challenge();
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = complete(begin_authorization(&app, "acme", ask(&challenge), None))
        else {
            panic!("a pending request");
        };
        let finish = |browser: &Secret, password: &str| {
            complete(finish_sign_in(
                &app,
                "acme",
                request,
                browser,
                TypedSignIn {
                    answer: SignInAnswer::Password {
                        name: "ada",
                        password: Secret::new(password.as_bytes().to_vec()),
                    },
                    caller: None,
                    known_browsers: &[],
                },
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        };

        assert_eq!(
            finish(&Secret::new(vec![1; 32]), PASSWORD),
            Err(ErrorCode::AuthorizationRequestExpired),
            "another browser, even with the right password"
        );
        assert_eq!(
            finish(&browser_secret, "a guess"),
            Err(ErrorCode::SignInFailed)
        );
        assert_eq!(
            finish(&browser_secret, PASSWORD),
            Ok(()),
            "the request waited"
        );
        assert_eq!(
            finish(&browser_secret, PASSWORD),
            Err(ErrorCode::AuthorizationRequestExpired),
            "a request is finished once"
        );

        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = complete(begin_authorization(&app, "acme", ask(&challenge), None))
        else {
            panic!("a pending request");
        };
        clock.advance(Duration::from_mins(10));
        let late = complete(finish_sign_in(
            &app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name: "ada",
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ));
        assert_eq!(
            late.map(|_| ()).map_err(|failure| failure.code),
            Err(ErrorCode::AuthorizationRequestExpired)
        );
    }

    #[test]
    fn a_byte_no_client_writes_names_no_client_and_is_never_echoed_back() {
        let (app, _storage, _clock, _secret) = start(true);
        let challenge = challenge();

        let named_with_a_null = AuthorizationParameters {
            client_id: Some("webapp\0"),
            ..ask(&challenge)
        };
        let shown = complete(begin_authorization(&app, "acme", named_with_a_null, None));
        assert!(
            matches!(&shown, Err(AuthorizationRefusal::Shown(failure)) if failure.code == ErrorCode::ClientNotFound),
            "{shown:?}"
        );

        for (state, nonce) in [(Some("st\0te"), None), (Some("fine"), Some("no\nce"))] {
            let parameters = AuthorizationParameters {
                state,
                nonce,
                ..ask(&challenge)
            };
            let returned = complete(begin_authorization(&app, "acme", parameters, None));
            let Err(AuthorizationRefusal::Returned { response }) = returned else {
                panic!("a trusted client gets its error back: {returned:?}");
            };
            let location = response.write_location().expect("an address");
            assert_eq!(
                read_query(&location, "error").as_deref(),
                Some("invalid_request")
            );
            assert_eq!(
                read_query(&location, "state").as_deref(),
                state.filter(|state| !state.contains('\0')),
                "{location}"
            );
        }
    }

    #[test]
    fn an_address_leaves_no_more_sign_ins_waiting_than_it_may_in_a_window() {
        use crate::login::throttle::MAX_PENDING_SIGN_INS_PER_ADDRESS;

        let (app, _storage, clock, _secret) = start(true);
        let challenge = challenge();
        let ask_from = |address: &str| {
            let parameters = AuthorizationParameters {
                caller: Some(address.parse().expect("an address")),
                ..ask(&challenge)
            };
            match complete(begin_authorization(&app, "acme", parameters, None)) {
                Ok(Authorization::SignInRequired { .. }) => Ok(()),
                Err(AuthorizationRefusal::Shown(failure)) => Err(failure.code),
                _ => panic!("neither a sign-in nor a refusal shown"),
            }
        };
        for _ in 0..MAX_PENDING_SIGN_INS_PER_ADDRESS {
            assert_eq!(ask_from("2001:db8:1:2::9"), Ok(()));
        }
        assert_eq!(
            ask_from("2001:db8:1:2::7"),
            Err(ErrorCode::SignInRequestsTooFrequent),
            "an address of the same network"
        );
        assert_eq!(ask_from("203.0.113.7"), Ok(()), "another address");
        clock.advance(Duration::from_mins(11));
        assert_eq!(ask_from("2001:db8:1:2::9"), Ok(()), "a window later");
    }

    #[test]
    fn a_known_browser_leaves_its_sign_ins_waiting_under_its_device_not_its_address() {
        use crate::login::throttle::MAX_PENDING_SIGN_INS_PER_ADDRESS;

        let (app, _storage, _clock, _secret) = start(true);
        let challenge = challenge();
        let begun = complete(begin_authorization(&app, "acme", ask(&challenge), None))
            .expect("a pending request");
        let Authorization::SignInRequired {
            request,
            browser_secret,
        } = begun
        else {
            panic!("a person without a session must sign in");
        };
        let known = complete(finish_sign_in(
            &app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name: "ada",
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person")
        .into_finished()
        .expect("a person who owes no code")
        .device_mark;
        let written = known.write();
        let device = written.split('.').nth(1).expect("a device");
        let unknown = DeviceMark::parse(&written.replace(device, &Uuid::nil().to_string()))
            .expect("a mark of no kept browser");
        let ask_with = |marks: &[DeviceMark]| {
            let parameters = AuthorizationParameters {
                caller: Some("198.51.100.7".parse().expect("an address")),
                known_browsers: marks,
                ..ask(&challenge)
            };
            match complete(begin_authorization(&app, "acme", parameters, None)) {
                Ok(Authorization::SignInRequired { .. }) => Ok(()),
                Err(AuthorizationRefusal::Shown(failure)) => Err(failure.code),
                _ => panic!("neither a sign-in nor a refusal shown"),
            }
        };
        for _ in 0..MAX_PENDING_SIGN_INS_PER_ADDRESS {
            assert_eq!(ask_with(&[]), Ok(()));
        }
        assert_eq!(ask_with(&[]), Err(ErrorCode::SignInRequestsTooFrequent));
        assert_eq!(
            ask_with(std::slice::from_ref(&unknown)),
            Err(ErrorCode::SignInRequestsTooFrequent),
            "a device the realm does not keep counts for nothing"
        );
        assert_eq!(
            ask_with(&[unknown, known.clone()]),
            Ok(()),
            "the browser the realm keeps is held by the address no longer"
        );
        for _ in 1..MAX_PENDING_SIGN_INS_PER_ADDRESS {
            assert_eq!(ask_with(std::slice::from_ref(&known)), Ok(()));
        }
        assert_eq!(
            ask_with(std::slice::from_ref(&known)),
            Err(ErrorCode::SignInRequestsTooFrequent),
            "and it is bounded as an address is"
        );
    }

    #[test]
    fn a_browser_kept_past_its_expiry_leaves_its_sign_ins_waiting_under_its_address() {
        use crate::login::device::DEVICE_MARK_LIFETIME;
        use crate::login::throttle::MAX_PENDING_SIGN_INS_PER_ADDRESS;

        let (app, _storage, clock, _secret) = start(true);
        let challenge = challenge();
        let begun = complete(begin_authorization(&app, "acme", ask(&challenge), None))
            .expect("a pending request");
        let Authorization::SignInRequired {
            request,
            browser_secret,
        } = begun
        else {
            panic!("a person without a session must sign in");
        };
        let expired = complete(finish_sign_in(
            &app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name: "ada",
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person")
        .into_finished()
        .expect("a person who owes no code")
        .device_mark;
        // The realm still holds the row: nothing purged it yet.
        clock.advance(Duration::from_secs(
            DEVICE_MARK_LIFETIME.whole_seconds().unsigned_abs() + 60,
        ));
        let ask_with = |marks: &[DeviceMark]| {
            let parameters = AuthorizationParameters {
                caller: Some("198.51.100.7".parse().expect("an address")),
                known_browsers: marks,
                ..ask(&challenge)
            };
            match complete(begin_authorization(&app, "acme", parameters, None)) {
                Ok(Authorization::SignInRequired { .. }) => Ok(()),
                Err(AuthorizationRefusal::Shown(failure)) => Err(failure.code),
                _ => panic!("neither a sign-in nor a refusal shown"),
            }
        };
        for _ in 0..MAX_PENDING_SIGN_INS_PER_ADDRESS {
            assert_eq!(ask_with(&[]), Ok(()));
        }

        assert_eq!(
            ask_with(std::slice::from_ref(&expired)),
            Err(ErrorCode::SignInRequestsTooFrequent),
            "a browser past its expiry is held by its address"
        );
    }

    #[test]
    fn a_session_answers_without_a_page_only_as_prompt_and_max_age_allow() {
        let (app, _storage, clock, _secret) = start(false);
        let (_location, ticket) = sign_in_through_the_flow(&app);
        let challenge = challenge();
        let ask_with = |prompt: Option<&'static str>, max_age: Option<&'static str>, ticket| {
            let parameters = AuthorizationParameters {
                prompt,
                max_age,
                ..ask(&challenge)
            };
            match complete(begin_authorization(&app, "acme", parameters, ticket)) {
                Ok(Authorization::Granted { .. }) => "granted".to_owned(),
                Ok(Authorization::SignInRequired { .. }) => "sign in".to_owned(),
                Ok(Authorization::ConsentRequired { .. }) => "consent".to_owned(),
                Err(AuthorizationRefusal::Returned { response }) => {
                    let location = response.write_location().expect("an address");
                    read_query(&location, "error").expect("an error")
                }
                Err(AuthorizationRefusal::Shown(failure)) => panic!("shown: {failure:?}"),
            }
        };

        assert_eq!(ask_with(None, None, Some(&ticket)), "granted");
        assert_eq!(ask_with(Some("login"), None, Some(&ticket)), "sign in");
        assert_eq!(
            ask_with(None, Some("0"), Some(&ticket)),
            "sign in",
            "max_age=0 asks a sign-in now, as prompt=login does"
        );
        assert_eq!(ask_with(None, Some("3600"), Some(&ticket)), "granted");
        assert_eq!(ask_with(Some("none"), None, Some(&ticket)), "granted");
        assert_eq!(ask_with(Some("none"), None, None), "login_required");
        assert_eq!(
            ask_with(None, Some(""), Some(&ticket)),
            "granted",
            "a parameter without a value was not sent"
        );
        assert_eq!(
            ask_with(Some("consent"), None, Some(&ticket)),
            "consent",
            "the person is asked on a page, even by a client that requires no consent"
        );
        assert_eq!(ask_with(Some("consent"), None, None), "sign in");
        clock.advance(Duration::from_secs(3_601));
        assert_eq!(ask_with(None, Some("3600"), Some(&ticket)), "sign in");
        assert_eq!(
            ask_with(Some("none"), Some("3600"), Some(&ticket)),
            "login_required"
        );
    }

    #[test]
    fn a_session_answers_a_hint_only_for_the_person_it_names() {
        let (app, _storage, clock, secret) = start(false);
        let (_, scope) =
            complete(crate::tenancy::resolve::resolve_realm(&app, "acme")).expect("the realm");
        complete(create_person(&app, scope, "bob", PASSWORD));
        let (location, ada) = sign_in_as(&app, "ada");
        let code = read_query(&location, "code").expect("a code");
        let tokens = exchange(&app, &code, secret.as_ref(), VERIFIER, CALLBACK).expect("tokens");
        let of_ada = tokens.id_token.expect("an identity token");
        let (_, bob) = sign_in_as(&app, "bob");
        let challenge = challenge();
        let ask_with = |hint: &str, prompt: Option<&'static str>, ticket| {
            let parameters = AuthorizationParameters {
                prompt,
                id_token_hint: Some(hint),
                ..ask(&challenge)
            };
            match complete(begin_authorization(&app, "acme", parameters, ticket)) {
                Ok(Authorization::Granted { .. }) => "granted".to_owned(),
                Ok(Authorization::SignInRequired { .. }) => "sign in".to_owned(),
                Ok(Authorization::ConsentRequired { .. }) => "consent".to_owned(),
                Err(AuthorizationRefusal::Returned { response }) => {
                    let location = response.write_location().expect("an address");
                    read_query(&location, "error").expect("an error")
                }
                Err(AuthorizationRefusal::Shown(failure)) => panic!("shown: {failure:?}"),
            }
        };

        assert_eq!(ask_with(&of_ada, Some("none"), Some(&ada)), "granted");
        assert_eq!(
            ask_with(&of_ada, Some("none"), Some(&bob)),
            "login_required",
            "the session of bob does not answer for ada"
        );
        assert_eq!(ask_with(&of_ada, None, Some(&bob)), "sign in");
        assert_eq!(ask_with(&of_ada, Some("none"), None), "login_required");
        for unreadable in ["not.a.token", tokens.access_token.as_str()] {
            assert_eq!(
                ask_with(unreadable, Some("none"), Some(&ada)),
                "invalid_request",
                "an access token is no hint"
            );
        }
        clock.advance(Duration::from_mins(10));
        assert_eq!(
            ask_with(&of_ada, Some("none"), Some(&ada)),
            "granted",
            "a hint is read long after its token expired: the realm signed it"
        );
    }

    #[test]
    fn a_hint_holds_the_person_who_signs_in_to_the_one_it_names() {
        let (app, _storage, _clock, secret) = start(false);
        let (_, scope) =
            complete(crate::tenancy::resolve::resolve_realm(&app, "acme")).expect("the realm");
        complete(create_person(&app, scope, "bob", PASSWORD));
        let (location, _) = sign_in_as(&app, "ada");
        let code = read_query(&location, "code").expect("a code");
        let of_ada = exchange(&app, &code, secret.as_ref(), VERIFIER, CALLBACK)
            .expect("tokens")
            .id_token
            .expect("an identity token");
        let challenge = challenge();
        // A fresh proof is asked, so no session answers: whoever is at the
        // browser signs in.
        let sign_in_with_hint = |name: &str| {
            let parameters = AuthorizationParameters {
                prompt: Some("login"),
                id_token_hint: Some(&of_ada),
                ..ask(&challenge)
            };
            let begun = complete(begin_authorization(&app, "acme", parameters, None))
                .expect("a pending request");
            let Authorization::SignInRequired {
                request,
                browser_secret,
            } = begun
            else {
                panic!("a fresh proof is asked of whoever is there");
            };
            complete(finish_sign_in(
                &app,
                "acme",
                request,
                &browser_secret,
                TypedSignIn {
                    answer: SignInAnswer::Password {
                        name,
                        password: Secret::new(PASSWORD.as_bytes().to_vec()),
                    },
                    caller: None,
                    known_browsers: &[],
                },
            ))
            .expect("a signed-in person")
            .into_finished()
            .expect("a person who owes no code")
            .response
            .write_location()
            .expect("an address")
        };

        let of_bob = sign_in_with_hint("bob");
        assert_eq!(
            read_query(&of_bob, "error").as_deref(),
            Some("login_required"),
            "bob signed in, and the client waits for ada: {of_bob}"
        );
        assert_eq!(read_query(&of_bob, "code"), None);
        assert_eq!(read_query(&of_bob, "state").as_deref(), Some("st&te"));
        let again = sign_in_with_hint("ada");
        assert!(read_query(&again, "code").is_some(), "{again}");
    }

    #[test]
    fn a_hint_given_to_another_client_is_refused() {
        let (app, _storage, _clock, secret) = start(false);
        let (_, scope) =
            complete(crate::tenancy::resolve::resolve_realm(&app, "acme")).expect("the realm");
        let other_callback = "https://other.example.org/callback";
        complete(create_application(
            &app,
            scope,
            "other",
            other_callback,
            true,
        ));
        let (location, ticket) = sign_in_through_the_flow(&app);
        let code = read_query(&location, "code").expect("a code");
        let of_webapp = exchange(&app, &code, secret.as_ref(), VERIFIER, CALLBACK)
            .expect("tokens")
            .id_token
            .expect("an identity token");
        let challenge = challenge();
        let parameters = AuthorizationParameters {
            client_id: Some("other"),
            redirect_uri: Some(other_callback),
            scope: Some("openid"),
            prompt: Some("none"),
            id_token_hint: Some(&of_webapp),
            ..ask(&challenge)
        };

        let refused = complete(begin_authorization(&app, "acme", parameters, Some(&ticket)));

        let Err(AuthorizationRefusal::Returned { response }) = refused else {
            panic!("returned to the client: {refused:?}");
        };
        let location = response.write_location().expect("an address");
        assert!(location.starts_with(other_callback), "{location}");
        assert_eq!(
            read_query(&location, "error").as_deref(),
            Some("invalid_request")
        );
    }

    #[test]
    fn a_client_owed_a_consent_is_told_so_without_a_page_whoever_its_hint_names() {
        use crate::clients::register::NewClient;
        use crate::consent::manage::withdraw_my_consent;
        use crate::oidc::scenario::Scenario;
        use crate::testkit::fixtures::{CodeFlow, check_and_register_client, run_code_flow};

        const LOOPBACK: &str = "http://127.0.0.1:8400/callback";
        let scenario = Scenario::start();
        let app = &scenario.app;
        complete(create_person(app, scenario.scope, "bob", PASSWORD));
        scenario.register_partner();
        let scopes = ["openid".to_owned()];
        let callbacks = [LOOPBACK.to_owned(), CALLBACK.to_owned()];
        let native = NewClient {
            client_id: "native",
            name: "An application of this machine",
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &callbacks,
            post_logout_redirect_uris: &[],
            frontchannel_logout_uri: None,
            response_types: &[],
            public: true,
            requires_consent: false,
            id_token_signed_response_alg: None,
            auth_method: None,
            jwks: None,
            jwks_uri: None,
            auth_signing_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: false,
            created_by: Some("operator"),
        };
        let mut work = complete(app.storage.begin(scenario.scope)).expect("a unit");
        complete(check_and_register_client(app, work.as_mut(), native))
            .expect("a client of this machine");
        complete(work.commit()).expect("a commit");
        let flow = |client_id, username| CodeFlow {
            realm: "acme",
            client_id,
            client_secret: None,
            redirect_uri: CALLBACK,
            scope: "openid",
            username,
            password: PASSWORD,
        };
        let to_native = complete(run_code_flow(app, flow("native", "ada"))).tokens;
        let bob = complete(run_code_flow(app, flow("webapp", "bob"))).ticket;
        let to_partner = scenario.sign_in_and_consent("partner", "openid");
        let ada = to_partner.ticket;
        complete(withdraw_my_consent(app, "acme", Some(&ada), "partner")).expect("a withdrawal");
        let challenge = challenge();
        let ask_as = |client_id, redirect_uri, hint: &TokenResponse, ticket| {
            let parameters = AuthorizationParameters {
                client_id: Some(client_id),
                redirect_uri: Some(redirect_uri),
                scope: Some("openid"),
                prompt: Some("none"),
                id_token_hint: hint.id_token.as_deref(),
                ..ask(&challenge)
            };
            read_outcome(complete(begin_authorization(
                app,
                "acme",
                parameters,
                Some(ticket),
            )))
        };

        let owed = [
            ("partner", CALLBACK, &to_partner.tokens),
            ("native", LOOPBACK, &to_native),
        ];
        for (client_id, redirect_uri, of_ada) in owed {
            for (person, ticket) in [("ada", &ada), ("bob", &bob)] {
                assert_eq!(
                    ask_as(client_id, redirect_uri, of_ada, ticket),
                    "consent_required",
                    "{client_id}, in the session of {person}"
                );
            }
        }
        assert_eq!(
            ask_as("native", CALLBACK, &to_native, &bob),
            "login_required",
            "owed nothing, a client is told the session does not answer for ada"
        );
    }

    #[test]
    fn a_prompt_or_an_age_the_realm_cannot_read_is_returned_as_invalid_request() {
        let (app, _storage, _clock, _secret) = start(false);
        let challenge = challenge();

        for (prompt, max_age) in [
            (Some("none login"), None),
            (Some("bogus"), None),
            (None, Some("-1")),
            (None, Some("+5")),
            (None, Some("1e3")),
        ] {
            let parameters = AuthorizationParameters {
                prompt,
                max_age,
                ..ask(&challenge)
            };
            let returned = complete(begin_authorization(&app, "acme", parameters, None));
            let Err(AuthorizationRefusal::Returned { response }) = returned else {
                panic!("returned to the client: {returned:?}");
            };
            let location = response.write_location().expect("an address");
            assert_eq!(
                read_query(&location, "error").as_deref(),
                Some("invalid_request"),
                "{prompt:?} {max_age:?}"
            );
        }
    }

    #[test]
    fn a_person_with_an_authenticator_finishes_the_request_with_a_code_and_the_token_says_so() {
        use crate::oidc::scenario::Scenario;

        let scenario = Scenario::start();
        let first = scenario.sign_in("openid");
        let secret = scenario.enroll_authenticator(&first.ticket);
        let begun = complete(begin_authorization(
            &scenario.app,
            "acme",
            ask(&challenge()),
            None,
        ))
        .expect("a pending request");
        let Authorization::SignInRequired {
            request,
            browser_secret,
        } = begun
        else {
            panic!("a person without a session must sign in: {begun:?}");
        };
        let answer = |answer: SignInAnswer<'_>| {
            complete(finish_sign_in(
                &scenario.app,
                "acme",
                request,
                &browser_secret,
                TypedSignIn {
                    answer,
                    caller: None,
                    known_browsers: &[],
                },
            ))
        };

        let too_early = answer(SignInAnswer::Code("000000"));
        assert_eq!(
            too_early.map(|_| ()).map_err(|failure| failure.code),
            Err(ErrorCode::AuthorizationRequestExpired),
            "a code before any password is the answer to nothing"
        );
        let opened_before = scenario
            .read_event_kinds()
            .iter()
            .filter(|kind| *kind == "session.opened")
            .count();
        let after_the_password = answer(SignInAnswer::Password {
            name: "ada",
            password: Secret::new(PASSWORD.as_bytes().to_vec()),
        })
        .expect("a right password");
        assert!(
            after_the_password.into_finished().is_none(),
            "the request waits for the code"
        );
        let refused = answer(SignInAnswer::Code("000000"));
        assert_eq!(
            refused.map(|_| ()).map_err(|failure| failure.code),
            Err(ErrorCode::CodeRejected)
        );
        let opened = |scenario: &Scenario| {
            scenario
                .read_event_kinds()
                .iter()
                .filter(|kind| *kind == "session.opened")
                .count()
        };
        assert_eq!(
            opened(&scenario),
            opened_before,
            "the password alone opened no session"
        );
        let code = scenario.read_code_now(&secret);
        let finished = answer(SignInAnswer::Code(&code))
            .expect("a right code")
            .into_finished()
            .expect("a finished request");
        assert_eq!(opened(&scenario), opened_before + 1);

        let code = read_query(
            &finished.response.write_location().expect("an address"),
            "code",
        )
        .expect("a code");
        let request = TokenRequest {
            grant_type: Some("authorization_code"),
            client_id: Some("webapp"),
            code: Some(&code),
            redirect_uri: Some(CALLBACK),
            code_verifier: Some(VERIFIER),
            ..TokenRequest::default()
        };
        let tokens = complete(grant_token(&scenario.app, "acme", request)).expect("tokens");
        let identity = read_claims(&tokens.id_token.expect("an identity token"));
        assert_eq!(identity["amr"], serde_json::json!(["pwd", "otp", "mfa"]));
        assert_eq!(
            identity["acr"], "2",
            "a code after the password is two factors"
        );
        assert_eq!(read_claims(&tokens.access_token)["acr"], "2");
    }

    #[test]
    fn a_person_with_a_key_finishes_the_request_with_its_answer_and_the_token_says_so() {
        use crate::oidc::scenario::Scenario;
        use crate::testkit::crypto::TrustingKeys;

        let scenario = Scenario::start();
        let first = scenario.sign_in("openid");
        scenario.enroll_security_key(&first.ticket, "k1");
        let begun = complete(begin_authorization(
            &scenario.app,
            "acme",
            ask(&challenge()),
            None,
        ))
        .expect("a pending request");
        let Authorization::SignInRequired {
            request,
            browser_secret,
        } = begun
        else {
            panic!("a person without a session must sign in: {begun:?}");
        };
        let answer = |answer: SignInAnswer<'_>| {
            complete(finish_sign_in(
                &scenario.app,
                "acme",
                request,
                &browser_secret,
                TypedSignIn {
                    answer,
                    caller: None,
                    known_browsers: &[],
                },
            ))
        };

        let early = TrustingKeys::answer_proof(&serde_json::json!({}), "k1", 1);
        assert_eq!(
            answer(SignInAnswer::Key(&early))
                .map(|_| ())
                .map_err(|failure| failure.code),
            Err(ErrorCode::AuthorizationRequestExpired),
            "the answer of a key before any password is the answer to nothing"
        );
        let step = answer(SignInAnswer::Password {
            name: "ada",
            password: Secret::new(PASSWORD.as_bytes().to_vec()),
        })
        .expect("a right password");
        let super::SignInStep::SecondFactorRequired(owed) = step else {
            panic!("the request waits for the key");
        };
        assert!(!owed.code);
        let options = owed.key.expect("what the page hands to the browser");
        assert_eq!(
            complete(super::describe_owed_second_factor(
                &scenario.app,
                "acme",
                request,
                &browser_secret
            ))
            .expect("what is owed"),
            Some(super::OwedSecondFactor {
                code: false,
                key: Some(options.clone())
            }),
            "the page can be shown again"
        );
        let finished = answer(SignInAnswer::Key(&TrustingKeys::answer_proof(
            &options, "k1", 1,
        )))
        .expect("a right answer")
        .into_finished()
        .expect("a finished request");

        let code = read_query(
            &finished.response.write_location().expect("an address"),
            "code",
        )
        .expect("a code");
        let request = TokenRequest {
            grant_type: Some("authorization_code"),
            client_id: Some("webapp"),
            code: Some(&code),
            redirect_uri: Some(CALLBACK),
            code_verifier: Some(VERIFIER),
            ..TokenRequest::default()
        };
        let tokens = complete(grant_token(&scenario.app, "acme", request)).expect("tokens");
        let identity = read_claims(&tokens.id_token.expect("an identity token"));
        assert_eq!(identity["amr"], serde_json::json!(["pwd", "pop", "mfa"]));
        assert_eq!(
            identity["acr"], "2",
            "a key after the password is two factors"
        );
    }

    /// Names where an answer leaves the browser.
    fn read_outcome(answer: Result<Authorization, AuthorizationRefusal>) -> String {
        match answer {
            Ok(Authorization::Granted { .. }) => "granted".to_owned(),
            Ok(Authorization::SignInRequired { .. }) => "sign in".to_owned(),
            Ok(Authorization::ConsentRequired { .. }) => "consent".to_owned(),
            Err(AuthorizationRefusal::Returned { response }) => {
                let location = response.write_location().expect("an address");
                read_query(&location, "error").expect("an error")
            }
            Err(AuthorizationRefusal::Shown(failure)) => panic!("shown: {failure:?}"),
        }
    }

    #[test]
    fn a_session_exactly_as_old_as_max_age_is_asked_again_and_a_longer_age_is_capped() {
        let (app, _storage, clock, _secret) = start(false);
        let (_location, ticket) = sign_in_through_the_flow(&app);
        let challenge = challenge();
        let ask_with = |max_age: &str| {
            let parameters = AuthorizationParameters {
                max_age: Some(max_age),
                ..ask(&challenge)
            };
            read_outcome(complete(begin_authorization(
                &app,
                "acme",
                parameters,
                Some(&ticket),
            )))
        };

        for too_long_to_hold in ["99999999999", "99999999999999999999999999999999"] {
            assert_eq!(
                ask_with(too_long_to_hold),
                "granted",
                "{too_long_to_hold} is read as the longest age, not refused"
            );
        }
        clock.advance(Duration::from_secs(59));
        assert_eq!(ask_with("60"), "granted");
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            ask_with("60"),
            "sign in",
            "proven sixty seconds ago is not younger than sixty seconds"
        );
        assert_eq!(ask_with("61"), "granted");
    }

    /// The realm of `start(false)` with `bob`, and `signer`, which proves
    /// itself and signs its requests with its secret.
    struct SigningRealm {
        app: App,
        secret: Secret,
        /// An identity token of `ada` that `signer` was given.
        of_ada: String,
        ada: SessionTicket,
        bob: SessionTicket,
    }

    impl SigningRealm {
        fn prepare() -> Self {
            use crate::clients::assertion::ASSERTION_TYPE;
            use crate::clients::register::NewClient;
            use crate::clients::{AssertionAlgorithm, ClientAuthMethod};
            use crate::testkit::fixtures::{check_and_register_client, sign_client_assertion};

            let (app, _storage, _clock, _secret) = start(false);
            let (_, scope) =
                complete(crate::tenancy::resolve::resolve_realm(&app, "acme")).expect("the realm");
            complete(create_person(&app, scope, "bob", PASSWORD));
            let (scopes, callbacks) = (["openid".to_owned()], [CALLBACK.to_owned()]);
            let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
            let wanted = NewClient {
                client_id: "signer",
                name: "signer",
                scopes: &scopes,
                capabilities: &[],
                redirect_uris: &callbacks,
                post_logout_redirect_uris: &[],
                frontchannel_logout_uri: None,
                response_types: &[],
                public: false,
                requires_consent: false,
                id_token_signed_response_alg: None,
                auth_method: Some(ClientAuthMethod::ClientSecretJwt),
                jwks: None,
                jwks_uri: None,
                auth_signing_alg: None,
                request_object_signing_alg: Some(AssertionAlgorithm::Hs256),
                require_signed_request_object: false,
                created_by: None,
            };
            let (_, secret) = complete(check_and_register_client(&app, work.as_mut(), wanted))
                .expect("a client that signs its requests");
            complete(work.commit()).expect("a commit");
            let secret = secret.expect("a secret, shown once");

            let signed = sign_request(&app, &secret, &serde_json::json!({}));
            let parameters = AuthorizationParameters {
                client_id: Some("signer"),
                request: Some(&signed),
                ..AuthorizationParameters::default()
            };
            let Ok(Authorization::SignInRequired {
                request,
                browser_secret,
            }) = complete(begin_authorization(&app, "acme", parameters, None))
            else {
                panic!("a person without a session signs in first");
            };
            let typed = TypedSignIn {
                answer: SignInAnswer::Password {
                    name: "ada",
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            };
            let signed_in = complete(finish_sign_in(
                &app,
                "acme",
                request,
                &browser_secret,
                typed,
            ))
            .expect("a signed-in person")
            .into_finished()
            .expect("a person who owes no code");
            let assertion = sign_client_assertion(&app, "signer", &secret, ISSUER, "x-1");
            let exchange = TokenRequest {
                grant_type: Some("authorization_code"),
                code: signed_in.response.read_parameter("code"),
                redirect_uri: Some(CALLBACK),
                code_verifier: Some(VERIFIER),
                client_assertion_type: Some(ASSERTION_TYPE),
                client_assertion: Some(&assertion),
                ..TokenRequest::default()
            };
            let of_ada = complete(grant_token(&app, "acme", exchange))
                .expect("tokens")
                .id_token
                .expect("an identity token");
            let (_, bob) = sign_in_as(&app, "bob");
            Self {
                app,
                secret,
                of_ada,
                ada: signed_in.ticket,
                bob,
            }
        }

        /// Sends a request of `signer` with each of `changes` signed in it,
        /// beside `query`, for the browser of `ticket`.
        fn send(
            &self,
            changes: &Value,
            query: &AuthorizationParameters<'_>,
            ticket: &SessionTicket,
        ) -> String {
            let signed = sign_request(&self.app, &self.secret, changes);
            let parameters = AuthorizationParameters {
                client_id: Some("signer"),
                request: Some(&signed),
                ..*query
            };
            read_outcome(complete(begin_authorization(
                &self.app,
                "acme",
                parameters,
                Some(ticket),
            )))
        }
    }

    /// A request of `signer` for a code, signed with its secret, with each
    /// of `changes` written in it.
    fn sign_request(app: &App, secret: &Secret, changes: &Value) -> String {
        let mut claims = serde_json::json!({
            "iss": "signer",
            "aud": ISSUER,
            "exp": app.now().unix_timestamp() + 60,
            "response_type": "code",
            "redirect_uri": CALLBACK,
            "scope": "openid",
            "nonce": "n-1",
            "code_challenge": challenge(),
            "code_challenge_method": "S256",
        });
        for (name, value) in changes.as_object().expect("changes") {
            claims[name] = value.clone();
        }
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let tag = app
            .digester
            .hmac_sha256(secret, input.as_bytes())
            .expect("a tag");
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(tag))
    }

    #[test]
    fn a_hint_a_signed_request_carries_holds_the_session_to_its_person_as_in_a_query() {
        let realm = SigningRealm::prepare();
        let silent_for_ada = serde_json::json!({ "prompt": "none", "id_token_hint": realm.of_ada });
        let alone = AuthorizationParameters::default();

        assert_eq!(realm.send(&silent_for_ada, &alone, &realm.ada), "granted");
        assert_eq!(
            realm.send(&silent_for_ada, &alone, &realm.bob),
            "login_required",
            "the session of bob does not answer for ada"
        );
        let challenge = challenge();
        let in_the_query = AuthorizationParameters {
            client_id: Some("signer"),
            scope: Some("openid"),
            prompt: Some("none"),
            id_token_hint: Some(&realm.of_ada),
            ..ask(&challenge)
        };
        assert_eq!(
            read_outcome(complete(begin_authorization(
                &realm.app,
                "acme",
                in_the_query,
                Some(&realm.bob),
            ))),
            "login_required",
            "the same refusal, asked in the query"
        );
    }

    #[test]
    fn a_hint_in_the_query_beside_a_signed_request_is_not_read() {
        let realm = SigningRealm::prepare();
        let beside = AuthorizationParameters {
            id_token_hint: Some(&realm.of_ada),
            ..AuthorizationParameters::default()
        };

        assert_eq!(
            realm.send(
                &serde_json::json!({ "prompt": "none" }),
                &beside,
                &realm.bob
            ),
            "granted",
            "the session of bob answers: the object names nobody"
        );
    }

    #[test]
    fn an_age_a_signed_request_carries_asks_an_older_session_to_sign_in_again() {
        let realm = SigningRealm::prepare();
        let alone = AuthorizationParameters::default();

        assert_eq!(
            realm.send(&serde_json::json!({}), &alone, &realm.ada),
            "granted"
        );
        assert_eq!(
            realm.send(&serde_json::json!({ "max_age": 0 }), &alone, &realm.ada),
            "sign in",
            "proven longer ago than the object allows"
        );
    }

    #[test]
    fn the_parameters_of_a_request_print_no_identity_token_hint() {
        let parameters = AuthorizationParameters {
            client_id: Some("webapp"),
            id_token_hint: Some("eyJhbGciOiJFUzI1NiJ9.e30.c2ln"),
            claims: Some(r#"{"id_token":{"sub":{"value":"someone"}}}"#),
            ..AuthorizationParameters::default()
        };

        let printed = format!("{parameters:?}");

        assert!(!printed.contains("eyJ"), "{printed}");
        assert!(printed.contains("id_token_hint: Some"), "{printed}");
        assert!(
            !printed.contains("someone"),
            "the claims may name a person: {printed}"
        );
        assert!(printed.contains("webapp"), "{printed}");
    }

    /// The identifier of the person `name` of `acme`.
    fn find_person(app: &App, name: &str) -> Uuid {
        let (_, scope) =
            complete(crate::tenancy::resolve::resolve_realm(app, "acme")).expect("the realm");
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
        complete(work.read_person_by_username(name))
            .expect("a read")
            .expect("the person")
            .id
    }

    /// The outcome of the usual request naming `claims`, for the browser of
    /// `ticket` when there is one.
    fn ask_naming(
        app: &App,
        claims: &str,
        prompt: Option<&str>,
        ticket: Option<&SessionTicket>,
    ) -> String {
        let challenge = challenge();
        let parameters = AuthorizationParameters {
            claims: Some(claims),
            prompt,
            ..ask(&challenge)
        };
        read_outcome(complete(begin_authorization(
            app, "acme", parameters, ticket,
        )))
    }

    /// A request that names the subject `subject` for the identity token.
    fn name_subject(subject: &str) -> String {
        serde_json::json!({ "id_token": { "sub": { "value": subject } } }).to_string()
    }

    /// A request that requires one of `levels` as essential.
    fn require_levels(levels: &[&str]) -> String {
        serde_json::json!({ "id_token": { "acr": { "essential": true, "values": levels } } })
            .to_string()
    }

    /// Signs `name` in for a request of `webapp` naming `claims`, and says
    /// where it leaves the browser.
    fn sign_in_naming(app: &App, claims: &str, name: &str) -> super::SignInStep {
        let challenge = challenge();
        let parameters = AuthorizationParameters {
            claims: Some(claims),
            ..ask(&challenge)
        };
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = complete(begin_authorization(app, "acme", parameters, None))
        else {
            panic!("a person without a session signs in first");
        };
        complete(finish_sign_in(
            app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name,
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person")
    }

    #[test]
    fn claims_the_realm_cannot_read_are_returned_as_invalid_request_and_unknown_members_ignored() {
        use crate::claims::request::MAX_CLAIMS_PARAMETER_BYTES;

        let (app, _storage, _clock, _secret) = start(false);
        let past_the_bound = format!(
            r#"{{"userinfo": {{"{}": null}}}}"#,
            "n".repeat(MAX_CLAIMS_PARAMETER_BYTES)
        );

        for unreadable in [
            "not json",
            "[]",
            r#"{"userinfo": ["name"]}"#,
            r#"{"id_token": {"name": "yes"}}"#,
            r#"{"id_token": {"acr": {"essential": "true"}}}"#,
            r#"{"userinfo": {"name": {"values": "Ada"}}}"#,
            r#"{"id_token": {"sub": {"values": ["a", "b"]}}}"#,
            r#"{"userinfo": {"na\u0000me": null}}"#,
            past_the_bound.as_str(),
        ] {
            assert_eq!(
                ask_naming(&app, unreadable, None, None),
                "invalid_request",
                "{unreadable:.60}"
            );
        }
        for read in [
            r#"{"access_token": {"x": 1}, "userinfo": {"name": {"purpose": "y"}}}"#,
            r#"{"userinfo": null}"#,
            "",
        ] {
            assert_eq!(ask_naming(&app, read, None, None), "sign in", "{read}");
        }
    }

    #[test]
    fn claims_named_for_userinfo_ask_for_an_answer_that_carries_an_access_token() {
        use crate::oidc::response::ResponseType;
        use crate::testkit::fixtures::{Application, register_answered_application};

        let (app, _storage, _clock, _secret) = start(false);
        let (_, scope) =
            complete(crate::tenancy::resolve::resolve_realm(&app, "acme")).expect("the realm");
        let spa = Application {
            client_id: "spa",
            redirect_uri: CALLBACK,
            post_logout_redirect_uri: None,
            public: true,
            requires_consent: false,
        };
        complete(register_answered_application(
            &app,
            scope,
            spa,
            &[ResponseType::IdToken, ResponseType::IdTokenToken],
        ));
        let ask_spa = |response_type, claims| {
            let parameters = AuthorizationParameters {
                client_id: Some("spa"),
                response_type: Some(response_type),
                code_challenge: None,
                code_challenge_method: None,
                claims: Some(claims),
                ..ask("")
            };
            // Told in the fragment, where the answer would have gone.
            match complete(begin_authorization(&app, "acme", parameters, None)) {
                Err(AuthorizationRefusal::Returned { response }) => response
                    .read_parameter("error")
                    .expect("an error")
                    .to_owned(),
                outcome => read_outcome(outcome),
            }
        };
        let of_userinfo = r#"{"userinfo": {"email": null}}"#;

        assert_eq!(ask_spa("id_token", of_userinfo), "invalid_request");
        assert_eq!(
            ask_spa("id_token", r#"{"id_token": {"email": null}}"#),
            "sign in"
        );
        assert_eq!(ask_spa("id_token token", of_userinfo), "sign in");
        assert_eq!(
            ask_naming(&app, of_userinfo, None, None),
            "sign in",
            "a code is spent for an access token"
        );
    }

    #[test]
    fn a_session_answers_a_subject_the_claims_name_only_for_that_person() {
        let (app, _storage, _clock, _secret) = start(false);
        let (_, scope) =
            complete(crate::tenancy::resolve::resolve_realm(&app, "acme")).expect("the realm");
        complete(create_person(&app, scope, "bob", PASSWORD));
        let (_, ada) = sign_in_as(&app, "ada");
        let (_, bob) = sign_in_as(&app, "bob");
        let of_ada = name_subject(&find_person(&app, "ada").to_string());

        assert_eq!(
            ask_naming(&app, &of_ada, Some("none"), Some(&ada)),
            "granted"
        );
        assert_eq!(
            ask_naming(&app, &of_ada, Some("none"), Some(&bob)),
            "login_required",
            "the session of bob does not answer for ada"
        );
        assert_eq!(ask_naming(&app, &of_ada, None, Some(&bob)), "sign in");
        for nobody in [
            name_subject("someone-else"),
            r#"{"id_token": {"sub": {"value": 7}}}"#.to_owned(),
        ] {
            assert_eq!(
                ask_naming(&app, &nobody, Some("none"), Some(&ada)),
                "login_required",
                "{nobody}"
            );
        }
        assert_eq!(
            ask_naming(
                &app,
                r#"{"id_token": {"sub": null}}"#,
                Some("none"),
                Some(&bob)
            ),
            "granted",
            "a subject asked for without a value names nobody"
        );
    }

    #[test]
    fn someone_else_who_signs_in_for_a_named_subject_is_sent_back_without_a_session() {
        let (app, storage, _clock, _secret) = start(false);
        let (_, scope) =
            complete(crate::tenancy::resolve::resolve_realm(&app, "acme")).expect("the realm");
        complete(create_person(&app, scope, "bob", PASSWORD));
        let ada = find_person(&app, "ada");
        let bob = find_person(&app, "bob");
        let of_ada = name_subject(&ada.to_string());

        let step = sign_in_naming(&app, &of_ada, "bob");

        let super::SignInStep::SentBack(sent_back) = step else {
            panic!("bob is sent back to the client: {step:?}");
        };
        let location = sent_back.response.write_location().expect("an address");
        assert!(location.starts_with(CALLBACK), "{location}");
        assert_eq!(
            read_query(&location, "error").as_deref(),
            Some("login_required")
        );
        assert_eq!(read_query(&location, "state").as_deref(), Some("st&te"));
        assert_eq!(read_query(&location, "code"), None);
        assert_eq!(
            storage.count_active_sessions(bob),
            0,
            "the session opened for the request is ended"
        );

        let step = sign_in_naming(&app, &of_ada, "ada");
        let finished = step.into_finished().expect("ada is answered");
        let location = finished.response.write_location().expect("an address");
        assert!(read_query(&location, "code").is_some(), "{location}");
        assert_eq!(storage.count_active_sessions(ada), 1);
    }

    #[test]
    fn an_essential_level_the_realm_has_no_name_for_is_refused_before_anyone_signs_in() {
        let (app, _storage, _clock, _secret) = start(false);
        let (_, ada) = sign_in_as(&app, "ada");

        for prompt in [None, Some("none"), Some("login")] {
            assert_eq!(
                ask_naming(&app, &require_levels(&["gold"]), prompt, None),
                "unmet_authentication_requirements",
                "{prompt:?}"
            );
        }
        assert_eq!(
            ask_naming(&app, &require_levels(&["gold"]), None, Some(&ada)),
            "unmet_authentication_requirements"
        );
        assert_eq!(
            ask_naming(&app, &require_levels(&["gold", "1"]), None, Some(&ada)),
            "granted",
            "one level it knows is enough"
        );
        assert_eq!(
            ask_naming(
                &app,
                r#"{"id_token": {"acr": {"values": ["gold"]}}}"#,
                None,
                Some(&ada)
            ),
            "granted",
            "asked for voluntarily, a level is a hint"
        );
    }

    #[test]
    fn a_session_short_of_an_essential_level_does_not_answer_and_without_a_page_is_told_so() {
        let (app, _storage, _clock, _secret) = start(false);
        let (_, ada) = sign_in_as(&app, "ada");

        assert_eq!(
            ask_naming(&app, &require_levels(&["2"]), None, Some(&ada)),
            "sign in",
            "a password alone is short of a second factor"
        );
        assert_eq!(
            ask_naming(&app, &require_levels(&["2"]), Some("none"), Some(&ada)),
            "login_required"
        );
        for met in [&["1"][..], &["2", "1"]] {
            assert_eq!(
                ask_naming(&app, &require_levels(met), Some("none"), Some(&ada)),
                "granted",
                "{met:?}"
            );
        }
    }

    #[test]
    fn a_sign_in_short_of_an_essential_level_is_told_unmet_and_the_person_stays_signed_in() {
        let (app, storage, _clock, _secret) = start(false);
        let ada = find_person(&app, "ada");

        let step = sign_in_naming(&app, &require_levels(&["2"]), "ada");

        let finished = step.into_finished().expect("sent back with the session");
        let location = finished.response.write_location().expect("an address");
        assert_eq!(
            read_query(&location, "error").as_deref(),
            Some("unmet_authentication_requirements"),
            "{location}"
        );
        assert_eq!(read_query(&location, "state").as_deref(), Some("st&te"));
        assert_eq!(read_query(&location, "iss").as_deref(), Some(ISSUER));
        assert_eq!(read_query(&location, "code"), None);
        assert_eq!(
            storage.count_active_sessions(ada),
            1,
            "the session the browser is given stands"
        );
    }

    #[test]
    fn a_sign_in_that_reaches_an_essential_level_is_said_in_a_level_the_client_named() {
        use crate::oidc::scenario::Scenario;

        let scenario = Scenario::start();
        let first = scenario.sign_in("openid");
        let secret = scenario.enroll_authenticator(&first.ticket);
        let sign_in_requiring = |levels: &[&str]| {
            let challenge = challenge();
            let claims = require_levels(levels);
            let parameters = AuthorizationParameters {
                claims: Some(&claims),
                ..ask(&challenge)
            };
            let Ok(Authorization::SignInRequired {
                request,
                browser_secret,
            }) = complete(begin_authorization(&scenario.app, "acme", parameters, None))
            else {
                panic!("a person without a session signs in first");
            };
            let answer = |answer: SignInAnswer<'_>| {
                complete(finish_sign_in(
                    &scenario.app,
                    "acme",
                    request,
                    &browser_secret,
                    TypedSignIn {
                        answer,
                        caller: None,
                        known_browsers: &[],
                    },
                ))
                .expect("an answer")
            };
            answer(SignInAnswer::Password {
                name: "ada",
                password: Secret::new(PASSWORD.as_bytes().to_vec()),
            });
            let code = scenario.read_code_now(&secret);
            let finished = answer(SignInAnswer::Code(&code))
                .into_finished()
                .expect("a finished request");
            scenario.clock.advance(Duration::from_secs(30));
            let code = finished
                .response
                .read_parameter("code")
                .expect("a code")
                .to_owned();
            scenario.exchange_as("webapp", &code)
        };

        let required = sign_in_requiring(&["2"]);
        let identity = read_claims(required.id_token.as_deref().expect("an identity token"));
        assert_eq!(identity["acr"], "2");
        assert_eq!(identity["amr"], serde_json::json!(["pwd", "otp", "mfa"]));

        let named_lower = sign_in_requiring(&["1"]);
        let identity = read_claims(named_lower.id_token.as_deref().expect("an identity token"));
        assert_eq!(
            identity["acr"], "1",
            "the client named one factor, which two include"
        );
        assert_eq!(
            read_claims(&named_lower.access_token)["acr"],
            "2",
            "the access token says what was reached"
        );
        let renewed = scenario
            .refresh(
                named_lower
                    .refresh_token
                    .as_deref()
                    .expect("a refresh token"),
            )
            .expect("tokens");
        let again = read_claims(renewed.id_token.as_deref().expect("an identity token"));
        assert_eq!(
            again["acr"], "1",
            "the request is read again at each renewal"
        );
        assert_eq!(again["auth_time"], identity["auth_time"]);
    }

    #[test]
    fn the_claims_a_signed_request_carries_are_read_and_those_of_the_query_beside_it_are_not() {
        let realm = SigningRealm::prepare();
        let of_ada = read_claims(&realm.of_ada)["sub"]
            .as_str()
            .expect("a subject")
            .to_owned();
        let naming_ada = serde_json::json!({ "id_token": { "sub": { "value": of_ada } } });
        let alone = AuthorizationParameters::default();

        assert_eq!(
            realm.send(
                &serde_json::json!({ "prompt": "none", "claims": naming_ada }),
                &alone,
                &realm.bob
            ),
            "login_required",
            "carried as an object"
        );
        assert_eq!(
            realm.send(
                &serde_json::json!({ "prompt": "none", "claims": naming_ada.to_string() }),
                &alone,
                &realm.bob
            ),
            "login_required",
            "carried as a text"
        );
        let text = naming_ada.to_string();
        let beside = AuthorizationParameters {
            claims: Some(&text),
            ..AuthorizationParameters::default()
        };
        assert_eq!(
            realm.send(
                &serde_json::json!({ "prompt": "none" }),
                &beside,
                &realm.bob
            ),
            "granted",
            "the object names nobody"
        );
        assert_eq!(
            realm.send(
                &serde_json::json!({ "prompt": "none", "acr_values": 7 }),
                &alone,
                &realm.ada
            ),
            "granted",
            "acr_values is read by nobody, and refuses nothing"
        );
    }

    #[test]
    fn a_ticket_of_an_offline_session_proves_nothing_whatever_its_secret() {
        use crate::login::session::{Session, SessionKind, SessionState};
        use crate::oidc::scenario::Scenario;

        let scenario = Scenario::start();
        scenario.register_partner();
        let offline = scenario.sign_in_and_consent("partner", "openid offline_access");
        let sid = read_claims(offline.tokens.id_token.as_deref().expect("an identity"))["sid"]
            .as_str()
            .and_then(|sid| Uuid::parse_str(sid).ok())
            .expect("the offline session");
        // One with a secret the browser would hold, written as no flow does.
        let secret = vec![4_u8; 32];
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
        let read = complete(work.read_session(sid))
            .expect("a read")
            .expect("the offline session");
        let kept = Session {
            id: Uuid::from_u128(77),
            secret_digest: scenario.app.digester.sha256(&secret).to_vec(),
            state: SessionState::Active,
            kind: SessionKind::Offline,
            ..read.session
        };
        complete(work.insert_session(&kept)).expect("a session");
        complete(work.commit()).expect("a commit");
        let challenge = challenge();

        for ticket in [
            SessionTicket {
                session: sid,
                secret: Secret::new(vec![0; 32]),
            },
            SessionTicket {
                session: kept.id,
                secret: Secret::new(secret.clone()),
            },
        ] {
            let answer = complete(begin_authorization(
                &scenario.app,
                "acme",
                ask(&challenge),
                Some(&ticket),
            ));
            assert_eq!(read_outcome(answer), "sign in", "{}", ticket.session);
        }
    }

    #[test]
    fn offline_access_is_granted_only_by_a_consent_given_on_the_page_of_the_request() {
        use crate::oidc::scenario::Scenario;

        let scenario = Scenario::start();
        let granted_scope = |location: &str| {
            let code = read_query(location, "code").expect("a code");
            exchange(&scenario.app, &code, None, VERIFIER, CALLBACK)
                .expect("tokens")
                .scope
        };

        let signed_in = scenario.sign_in("openid offline_access");
        assert_eq!(
            signed_in.tokens.scope, "openid",
            "asked with no page to answer on, it is left out in silence"
        );
        assert_eq!(
            read_claims(&signed_in.tokens.access_token)["sid"],
            signed_in.ticket.session.to_string(),
            "the grant lives in the browser session"
        );
        let challenge = challenge();
        let silent = AuthorizationParameters {
            scope: Some("openid offline_access"),
            prompt: Some("none"),
            ..ask(&challenge)
        };
        let answered = complete(begin_authorization(
            &scenario.app,
            "acme",
            silent,
            Some(&signed_in.ticket),
        ));
        let Ok(Authorization::Granted { response }) = answered else {
            panic!("a session answers at once: {answered:?}");
        };
        let location = response.write_location().expect("an address");
        assert_eq!(granted_scope(&location), "openid");

        scenario.register_partner();
        let allowed = scenario.sign_in_and_consent("partner", "openid offline_access");
        assert_eq!(allowed.tokens.scope, "openid offline_access");
    }

    #[test]
    fn a_public_client_sent_back_to_this_machine_asks_the_person_at_each_request() {
        use crate::clients::register::NewClient;
        use crate::oidc::scenario::Scenario;
        use crate::testkit::fixtures::check_and_register_client;

        const LOOPBACK: &str = "http://127.0.0.1:8400/callback";
        const WRITTEN_OTHERWISE: [&str; 4] = [
            "https://127.0.0.2:8443/cb",
            "https://[0:0:0:0:0:0:0:1]/cb",
            "https://localhost./cb",
            "https://app.localhost/cb",
        ];
        let scenario = Scenario::start();
        let mut callbacks = vec![LOOPBACK.to_owned(), CALLBACK.to_owned()];
        callbacks.extend(WRITTEN_OTHERWISE.map(str::to_owned));
        let scopes = ["openid".to_owned()];
        let native = |client_id, public| NewClient {
            client_id,
            name: "An application of this machine",
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &callbacks,
            post_logout_redirect_uris: &[],
            frontchannel_logout_uri: None,
            response_types: &[],
            public,
            requires_consent: true,
            id_token_signed_response_alg: None,
            auth_method: None,
            jwks: None,
            jwks_uri: None,
            auth_signing_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: false,
            created_by: Some("operator"),
        };
        let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
        for (client_id, public) in [("native", true), ("native-secret", false)] {
            complete(check_and_register_client(
                &scenario.app,
                work.as_mut(),
                native(client_id, public),
            ))
            .expect("a client of this machine the realm made");
        }
        complete(work.commit()).expect("a commit");
        let signed_in = scenario.sign_in_and_consent("native", "openid");
        scenario.allow_on_the_page("native-secret", "openid");
        let challenge = challenge();
        let ask_as = |client_id, redirect_uri, prompt| {
            let parameters = AuthorizationParameters {
                redirect_uri: Some(redirect_uri),
                client_id: Some(client_id),
                scope: Some("openid"),
                prompt,
                ..ask(&challenge)
            };
            read_outcome(complete(begin_authorization(
                &scenario.app,
                "acme",
                parameters,
                Some(&signed_in.ticket),
            )))
        };

        assert_eq!(
            ask_as("native", CALLBACK, Some("none")),
            "granted",
            "allowed once, it is sent back to its host without a page"
        );
        assert_eq!(
            ask_as("native", LOOPBACK, Some("none")),
            "consent_required",
            "whatever listens on this machine is not known by its address"
        );
        for redirect_uri in WRITTEN_OTHERWISE {
            assert_eq!(
                ask_as("native", redirect_uri, Some("none")),
                "consent_required",
                "this machine, however it is written: {redirect_uri}"
            );
        }
        assert_eq!(ask_as("native", LOOPBACK, None), "consent");
        assert_eq!(
            ask_as("native-secret", LOOPBACK, Some("none")),
            "granted",
            "a client that proves itself is known by its secret"
        );
    }

    #[test]
    fn a_public_client_sent_back_to_a_host_it_kept_before_its_check_asks_the_person_at_each_request()
     {
        use crate::clients::{Client, ClientAuthMethod, KeptProof};
        use crate::oidc::scenario::Scenario;

        // Kept before the grammar of today, which reads no host in it.
        const KEPT_BEFORE: &str = "http://localhost:8080/cb?a=|b";
        const NAMED_IN_CAPITALS: &str = "https://LocalHost/cb";
        let scenario = Scenario::start();
        let legacy = Client {
            id: Uuid::from_u128(7),
            client_id: "legacy".to_owned(),
            name: "An application kept before".to_owned(),
            auth_method: ClientAuthMethod::None,
            auth_signing_alg: None,
            allows_client_credentials: false,
            allows_authorization_code: true,
            redirect_uris: vec![
                CALLBACK.to_owned(),
                KEPT_BEFORE.to_owned(),
                NAMED_IN_CAPITALS.to_owned(),
            ],
            response_types: vec![crate::oidc::response::ResponseType::Code],
            post_logout_redirect_uris: Vec::new(),
            frontchannel_logout_uri: None,
            requires_consent: true,
            scopes: vec!["openid".to_owned()],
            capabilities: Vec::new(),
            id_token_signed_response_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: false,
            enabled: true,
            self_registered: false,
            created_at: scenario.app.now(),
        };
        let nothing = KeptProof {
            secret_digest: None,
            sealed_secret: None,
            jwks: None,
        };
        let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
        complete(work.insert_client(&legacy, &nothing)).expect("a client the store keeps");
        complete(work.commit()).expect("a commit");
        let signed_in = scenario.sign_in_and_consent("legacy", "openid");
        let challenge = challenge();
        let ask_silently = |redirect_uri| {
            let parameters = AuthorizationParameters {
                redirect_uri: Some(redirect_uri),
                client_id: Some("legacy"),
                scope: Some("openid"),
                prompt: Some("none"),
                ..ask(&challenge)
            };
            read_outcome(complete(begin_authorization(
                &scenario.app,
                "acme",
                parameters,
                Some(&signed_in.ticket),
            )))
        };

        assert_eq!(
            ask_silently(CALLBACK),
            "granted",
            "allowed, in a live session"
        );
        assert_eq!(
            ask_silently(KEPT_BEFORE),
            "consent_required",
            "a host this version cannot read may be this machine"
        );
        assert_eq!(
            ask_silently(NAMED_IN_CAPITALS),
            "consent_required",
            "this machine, however its name is written"
        );
    }

    #[test]
    fn an_answer_to_an_address_of_this_deployment_travels_in_the_address_and_is_never_posted() {
        const PORTAL: &str = "https://id.example.test/portal/callback";
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_application(&app, scope, "webapp", PORTAL, false));
        let challenge = challenge();
        let ask_in = |response_mode| {
            let parameters = AuthorizationParameters {
                redirect_uri: Some(PORTAL),
                response_mode,
                ..ask(&challenge)
            };
            complete(begin_authorization(&app, "acme", parameters, None))
        };

        for response_mode in [None, Some("query")] {
            let begun = ask_in(response_mode);
            assert!(
                matches!(begun, Ok(Authorization::SignInRequired { .. })),
                "{response_mode:?}: {begun:?}"
            );
        }
        let posted = ask_in(Some("form_post"));
        assert!(
            matches!(
                &posted,
                Err(AuthorizationRefusal::Shown(failure))
                    if failure.code == ErrorCode::AnswerPostedToDeployment
            ),
            "shown, with a code of its own: {posted:?}"
        );
    }

    #[test]
    fn without_a_page_a_client_the_person_never_allowed_learns_nothing_of_who_signed_in() {
        use crate::oidc::scenario::Scenario;

        let scenario = Scenario::start();
        scenario.register_partner();
        let ada = scenario.sign_in("openid").ticket;
        let of_ada = name_subject(&scenario.find_ada().to_string());
        let ask_partner = |claims: &str, ticket| {
            let challenge = challenge();
            let parameters = AuthorizationParameters {
                client_id: Some("partner"),
                scope: Some("openid"),
                prompt: Some("none"),
                claims: Some(claims),
                ..ask(&challenge)
            };
            read_outcome(complete(begin_authorization(
                &scenario.app,
                "acme",
                parameters,
                Some(ticket),
            )))
        };

        for claims in [
            of_ada.clone(),
            name_subject("someone-else"),
            require_levels(&["2"]),
        ] {
            assert_eq!(
                ask_partner(&claims, &ada),
                "consent_required",
                "the same answer, whoever is named: {claims}"
            );
        }

        let (_, allowed) = scenario.allow_on_the_page("partner", "openid");
        assert_eq!(ask_partner(&of_ada, &allowed), "granted");
        assert_eq!(
            ask_partner(&name_subject("someone-else"), &allowed),
            "login_required",
            "allowed, the client is told when someone else is named"
        );
        assert_eq!(
            ask_partner(&require_levels(&["2"]), &allowed),
            "login_required"
        );
    }

    #[test]
    fn without_a_page_a_client_of_this_machine_learns_nothing_of_who_signed_in() {
        use crate::clients::register::NewClient;
        use crate::oidc::scenario::Scenario;
        use crate::testkit::fixtures::check_and_register_client;

        const LOOPBACK: &str = "http://127.0.0.1:8400/callback";
        let scenario = Scenario::start();
        let (scopes, callbacks) = (["openid".to_owned()], [LOOPBACK.to_owned()]);
        let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
        let native = NewClient {
            client_id: "native",
            name: "An application of this machine",
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &callbacks,
            post_logout_redirect_uris: &[],
            frontchannel_logout_uri: None,
            response_types: &[],
            public: true,
            requires_consent: false,
            id_token_signed_response_alg: None,
            auth_method: None,
            jwks: None,
            jwks_uri: None,
            auth_signing_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: false,
            created_by: Some("operator"),
        };
        complete(check_and_register_client(
            &scenario.app,
            work.as_mut(),
            native,
        ))
        .expect("a client of this machine");
        complete(work.commit()).expect("a commit");
        let ada = scenario.sign_in("openid").ticket;
        let challenge = challenge();

        for claims in [
            name_subject(&scenario.find_ada().to_string()),
            name_subject("someone-else"),
        ] {
            let parameters = AuthorizationParameters {
                client_id: Some("native"),
                redirect_uri: Some(LOOPBACK),
                scope: Some("openid"),
                prompt: Some("none"),
                claims: Some(&claims),
                ..ask(&challenge)
            };
            assert_eq!(
                read_outcome(complete(begin_authorization(
                    &scenario.app,
                    "acme",
                    parameters,
                    Some(&ada),
                ))),
                "consent_required",
                "{claims}"
            );
        }
    }

    #[test]
    fn a_hint_and_a_subject_that_name_two_people_send_a_third_back_without_a_session() {
        let (app, storage, _clock, secret) = start(false);
        let (_, scope) =
            complete(crate::tenancy::resolve::resolve_realm(&app, "acme")).expect("the realm");
        for name in ["bob", "carol"] {
            complete(create_person(&app, scope, name, PASSWORD));
        }
        let (location, _) = sign_in_as(&app, "ada");
        let code = read_query(&location, "code").expect("a code");
        let of_ada = exchange(&app, &code, secret.as_ref(), VERIFIER, CALLBACK)
            .expect("tokens")
            .id_token
            .expect("an identity token");
        let of_bob = name_subject(&find_person(&app, "bob").to_string());
        let challenge = challenge();
        let parameters = AuthorizationParameters {
            prompt: Some("login"),
            id_token_hint: Some(&of_ada),
            claims: Some(&of_bob),
            ..ask(&challenge)
        };
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = complete(begin_authorization(&app, "acme", parameters, None))
        else {
            panic!("a fresh proof is asked");
        };

        let step = complete(finish_sign_in(
            &app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name: "carol",
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person");

        assert!(
            matches!(step, super::SignInStep::SentBack(_)),
            "the subject named is judged first: {step:?}"
        );
        assert_eq!(storage.count_active_sessions(find_person(&app, "carol")), 0);
    }

    #[test]
    fn a_claims_parameter_that_names_nothing_keeps_nothing_with_the_request() {
        let (app, _storage, _clock, _secret) = start(false);
        let (_, scope) =
            complete(crate::tenancy::resolve::resolve_realm(&app, "acme")).expect("the realm");
        let kept = |claims: &str| {
            let challenge = challenge();
            let parameters = AuthorizationParameters {
                claims: Some(claims),
                ..ask(&challenge)
            };
            let Ok(Authorization::SignInRequired { request, .. }) =
                complete(begin_authorization(&app, "acme", parameters, None))
            else {
                panic!("a person without a session signs in first");
            };
            let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
            complete(work.read_pending_authorization(request, app.now()))
                .expect("a read")
                .expect("the request")
                .claims
        };

        for nothing in ["{}", r#"{"userinfo": null, "id_token": {}}"#] {
            assert_eq!(kept(nothing), None, "{nothing}");
        }
        assert!(kept(r#"{"userinfo": {"name": null}}"#).is_some());
    }
}
