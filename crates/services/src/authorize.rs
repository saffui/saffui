//! Where a login starts, and what may be sent onward from it.
//!
//! The split that matters here is not success against failure but showable
//! against sendable. RFC 6749 §4.1.2.1: a request whose client or redirect
//! cannot be trusted is shown to the user and never redirected, because
//! redirecting it is the open redirector.

use chrono::{DateTime, Duration, Utc};
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use models::entities::acr::{self, AchievedAuth, AcrRequirement, AuthContextRequest, AuthDecision};
use models::entities::attributes::AttributeValue;
use models::entities::client::ClientModel;
use models::sessions::records::{UserSessionModel, UserSessionState};
use serde_json::{Value, json};
use store::providers::login::{self, AuthSession};
use store::providers::{auth_flows, client_scopes, clients, realms, sessions};
use store::tenancy::TenantContext;

use crate::claims_request::ClaimsRequest;
use crate::landing::{Landing, ResponseMode};
use crate::login::browser;
use crate::pushed;
use crate::request_object;

/// How long a login may sit half finished.
const LOGIN_LIFESPAN: i64 = 900;

/// The flow a browser login runs when the client names none.
const BROWSER_FLOW: &str = "browser";

/// What the query asked for.
#[derive(Debug, Default)]
pub struct Requested<'a> {
    pub response_type: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub redirect_uri: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub state: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    /// A signed request object, or where to fetch one. Neither is read here,
    /// and both have to be refused rather than ignored.
    pub request: Option<&'a str>,
    pub request_uri: Option<&'a str>,
    /// How the client asked to be answered.
    pub response_mode: Option<&'a str>,
    /// `none`, `login`, `consent`, `select_account`, space separated.
    pub prompt: Option<&'a str>,
    /// How old the authentication may be. Zero is meaningful and means always
    /// re-authenticate, which is why it is not a flag.
    pub max_age: Option<i64>,
    pub acr_values: Option<&'a str>,
    /// The `claims` parameter, OIDC Core §5.5, as the client sent it.
    pub claims: Option<&'a str>,
}

/// Where the browser goes next.
#[derive(Debug)]
pub enum Begun {
    /// Nobody is signed in here yet, so a login is opened and answered.
    Authenticate { auth_session_id: String },
    /// Somebody is, and the client gets its code without the user seeing a
    /// screen. This is what single sign-on is.
    Admitted { landing: Landing },
}

/// Why the login did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// Shown to the user, carrying the code that names why. Nothing here may be
    /// sent to a redirect, because what failed is the reason to believe there is
    /// one worth sending to.
    #[error("{0}")]
    Unshowable(&'static str),
    /// Sent to the registered redirect, as §4.1.2.1 requires, with the state
    /// the client asked to have echoed.
    #[error("{0}")]
    Redirect(&'static str),
}

/// Start a login, or say how the refusal travels.
pub async fn begin(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &TenantContext,
    issuer: &str,
    asked: &Requested<'_>,
    signed_in: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Begun, Refusal> {
    // A reference this server issued stands for the whole request, so it is
    // taken first and the browser's own query is not read at all.
    let taken;
    let asked = match asked.request_uri {
        None => asked,
        Some(handle) => {
            taken = pushed::spend_reference(transaction, provider, handle)
                .await
                .ok_or(Refusal::Unshowable("invalid_request_uri"))?;
            if asked
                .client_id
                .is_some_and(|named| named != taken.client_id)
            {
                return Err(Refusal::Unshowable("invalid_request_uri"));
            }
            &taken.as_request()
        }
    };
    let client = named_client(transaction, asked.client_id).await?;

    // What the client signed governs the request, so it is read before the
    // redirect is looked up: the object is where a client states one.
    let carried;
    let merged;
    let requested = match asked.request {
        None => asked,
        Some(raw) => {
            carried = request_object::read(&client, raw, issuer, now)
                .map_err(|why| Refusal::Redirect(why.told()))?;
            merged = carried
                .over(asked)
                .map_err(|why| Refusal::Redirect(why.told()))?;
            &merged
        }
    };
    let redirect_uri = registered_redirect(&client, requested.redirect_uri)?;

    // From here the client and the redirect are established, so a refusal can
    // travel to the client rather than stopping at the user.
    //
    // Absent means disabled. A flag nobody set is not permission, and reading it
    // as one opens every client that was registered before the flag existed.
    if client.standard_flow_enabled != Some(true) {
        return Err(Refusal::Redirect("unauthorized_client"));
    }
    if requested.response_type != Some("code") {
        return Err(Refusal::Redirect("unsupported_response_type"));
    }
    // Read before anything is answered, since the refusal itself travels the
    // way the request asked. A mode this build does not know is refused rather
    // than answered as `query`: a response put where the client is not reading
    // is one it never sees, and for anything but a code it is one that lands
    // somewhere it should not.
    let Some(mode) = ResponseMode::read(requested.response_mode) else {
        return Err(Refusal::Redirect("unsupported_response_mode"));
    };
    // This is an OpenID Provider, and `openid` is what says a request is one.
    // The cost is stated rather than hidden: a plain OAuth client that never
    // asks for it is refused here.
    if !requested
        .scope
        .unwrap_or_default()
        .split_whitespace()
        .any(|asked| asked == OPENID)
    {
        return Err(Refusal::Redirect("invalid_scope"));
    }
    proof_is_registered(&client, requested)?;

    // Read in full before anything is decided on it. A request for claims that
    // cannot be read is a request whose wishes are unknown, and answering it
    // with a guess is answering a different request.
    let asked_claims = match requested.claims {
        None => ClaimsRequest::default(),
        Some(raw) => ClaimsRequest::parse(raw).map_err(|_| Refusal::Redirect("invalid_request"))?,
    };

    // A login the browser already holds, if it holds one. Everything the code
    // needs is on that row, so nothing is asked of the user a second time.
    let granted = granted_scope(
        transaction,
        &client.client_id,
        requested.scope.unwrap_or_default(),
    )
    .await?;

    // What the request asks of the authentication itself, against what the
    // browser already holds.
    let prompt = Prompt::read(requested.prompt)?;
    // OIDC Core §11: without `prompt=consent` the request for offline access is
    // ignored rather than refused, and the rest of it is served.
    let granted = if prompt.consent {
        granted
    } else {
        drop_scope(&granted, OFFLINE_ACCESS)
    };
    // `acr_values` is voluntary by definition. An `acr` named in `claims` is
    // as hard as the client said: essential must be met or the login fails,
    // §5.5.1.1; voluntary is the same hint `acr_values` is. Both given at once
    // is unspecified, and the one that can fail a login is the one honoured.
    let (acr_values, requirement) = match asked_claims.contexts_asked() {
        Some((named, true)) => (named, AcrRequirement::Essential),
        Some((named, false)) => (
            requested
                .acr_values
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_owned)
                .chain(named)
                .collect(),
            AcrRequirement::Voluntary,
        ),
        None => (
            requested
                .acr_values
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            AcrRequirement::Voluntary,
        ),
    };
    let asked = AuthContextRequest {
        acr_values,
        requirement,
        max_age: requested.max_age,
        prompt_login: prompt.login,
    };
    let map = realms::load(transaction, &tenant.realm_id)
        .await
        .map_err(|_| Refusal::Redirect("server_error"))?
        .and_then(|realm| realm.acr_loa_map)
        .unwrap_or_default();

    // A session somebody else holds does not answer a request for this
    // subject, §3.1.2.2. It is not reused; whoever the client named has to
    // log in, and the flow's end is where a different outcome is refused.
    let held = live_login(transaction, signed_in, now)
        .await?
        .filter(|login| {
            asked_claims
                .subject_asked()
                .is_none_or(|wanted| wanted == login.user_id)
        });
    let achieved = held.as_ref().map(|login| AchievedAuth {
        loa: login.loa.unwrap_or(0),
        auth_time: login.auth_time.unwrap_or(login.started_at),
    });

    let stored_claims = (!asked_claims.is_empty()).then(|| asked_claims.to_value());

    match acr::decide(&asked, &map, achieved, now.timestamp()) {
        AuthDecision::Satisfied => {}
        // RFC 9470. Nothing this realm offers can meet it, so failing now beats
        // authenticating the user and failing afterwards.
        AuthDecision::Unsatisfiable { .. } => {
            return Err(Refusal::Redirect("unmet_authentication_requirements"));
        }
        // "Never interact" and "authenticate again" are contradictory by
        // construction, and the contradiction is the client's to resolve.
        AuthDecision::Reauthenticate { .. } if prompt.none => {
            return Err(Refusal::Redirect("login_required"));
        }
        AuthDecision::Reauthenticate { .. } => {
            return start_login(
                transaction,
                provider,
                &client,
                redirect_uri,
                mode,
                &granted,
                requested,
                stored_claims.as_ref(),
                now,
            )
            .await;
        }
    }

    if let Some(login) = held {
        let landing = browser::mint_code(
            transaction,
            provider,
            tenant,
            &browser::Authorized {
                client_id: &client.client_id,
                user_id: &login.user_id,
                session_id: &login.session_id,
                redirect_uri,
                scope: &granted,
                state: requested.state,
                mode,
                nonce: requested.nonce,
                code_challenge: requested.code_challenge,
                code_challenge_method: requested.code_challenge_method,
                // The login's instant, not this one. A client asking how
                // recently the user authenticated is asking about the login.
                auth_time: login.auth_time.unwrap_or(login.started_at),
                // What was reached, never what was asked for. A server that
                // echoes the request turns the claim into decoration, and a
                // relying party reads it to decide whether to release money.
                acr: acr::acr_claim(
                    &map,
                    AchievedAuth {
                        loa: login.loa.unwrap_or(0),
                        auth_time: login.auth_time.unwrap_or(login.started_at),
                    },
                ),
                claims: stored_claims.as_ref(),
            },
            now,
        )
        .await
        .map_err(|_| Refusal::Redirect("server_error"))?;
        return Ok(Begun::Admitted { landing });
    }

    start_login(
        transaction,
        provider,
        &client,
        redirect_uri,
        mode,
        &granted,
        requested,
        stored_claims.as_ref(),
        now,
    )
    .await
}

/// What `prompt` asked for.
///
/// `none` and `login` together contradict each other, and OIDC Core §3.1.2.1
/// makes that an error rather than a precedence question.
struct Prompt {
    none: bool,
    login: bool,
    consent: bool,
}

impl Prompt {
    fn read(raw: Option<&str>) -> Result<Self, Refusal> {
        let asked: Vec<&str> = raw.unwrap_or_default().split_whitespace().collect();
        let prompt = Prompt {
            none: asked.contains(&"none"),
            login: asked.contains(&"login"),
            consent: asked.contains(&"consent"),
        };
        if prompt.none && asked.len() > 1 {
            return Err(Refusal::Redirect("invalid_request"));
        }
        Ok(prompt)
    }
}

/// Open a login and say where it is answered.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
async fn start_login(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    client: &ClientModel,
    redirect_uri: &str,
    mode: ResponseMode,
    granted: &str,
    requested: &Requested<'_>,
    claims: Option<&Value>,
    now: DateTime<Utc>,
) -> Result<Begun, Refusal> {
    let flow = browser_flow(transaction, client).await?;
    let auth_session_id = draw_id(provider)?;

    login::start(
        transaction,
        &AuthSession {
            session_id: auth_session_id.clone(),
            client_id: client.client_id.clone(),
            flow_id: flow,
            execution_id: None,
            user_id: None,
            redirect_uri: redirect_uri.to_owned(),
            expires_at: now + Duration::seconds(LOGIN_LIFESPAN),
            // Everything the redemption re-checks and the id token echoes. It
            // is written once, here, because by the time the flow finishes the
            // request that carried it is gone.
            notes: json!({
                // What the client may have, not what it asked for. The code
                // carries this into the token, and whatever releases claims by
                // scope reads it there.
                "scope": granted,
                "state": requested.state,
                "nonce": requested.nonce,
                "code_challenge": requested.code_challenge,
                "code_challenge_method": requested.code_challenge_method,
                // What the client named, already read and kept in the shape
                // the store reads back, so the door is the only place it is
                // parsed.
                "claims": claims,
                // How the answer travels. Kept because by the time the flow
                // finishes, the request that named it is gone.
                "response_mode": mode.as_str(),
            }),
        },
    )
    .await
    .map_err(|_| Refusal::Redirect("server_error"))?;

    Ok(Begun::Authenticate { auth_session_id })
}

/// The login a browser named, when it is one this realm still stands behind.
///
/// A cookie is a claim and not a fact. The row says whether the login is still
/// open and whether it has run out, and both are checked here rather than being
/// left to whatever reads the token minted from it.
async fn live_login(
    transaction: &Transaction<'_>,
    signed_in: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Option<UserSessionModel>, Refusal> {
    let Some(session_id) = signed_in.filter(|named| !named.is_empty()) else {
        return Ok(None);
    };
    Ok(sessions::load(transaction, session_id)
        .await
        .map_err(|_| Refusal::Redirect("server_error"))?
        .filter(|login| login.state == UserSessionState::LoggedIn)
        .filter(|login| login.expiration.is_none_or(|ends| ends > now.timestamp())))
}

/// The `openid` marker, which is a request marker rather than a scope a client
/// is attached to.
const OPENID: &str = "openid";

/// A grant that outlives the login it came from, OIDC Core §11.
pub const OFFLINE_ACCESS: &str = "offline_access";

fn drop_scope(granted: &str, dropped: &str) -> String {
    granted
        .split_whitespace()
        .filter(|held| *held != dropped)
        .collect::<Vec<_>>()
        .join(" ")
}

/// What the client may actually have of what it asked for.
///
/// Requested and granted are not the same list, and treating them as one is a
/// leak with a long reach: the scope rides the code into the token, and whatever
/// releases claims by scope then releases what the client was never attached to.
/// Unentitled scopes are dropped rather than refused, which is what RFC 6749 §3.3
/// permits and what clients expect.
///
/// How a client holds a scope decides the rest, and that is a property of the
/// attachment rather than of the scope. A scope attached outright is granted
/// whether or not it was asked for; an optional one only when the request names
/// it. The other flag, `default_scope`, answers a different question: which
/// scopes a client is offered when it is registered. Reading that one here made
/// a realm-wide offer into a per-client grant, and left the plane no way to say
/// "this client always carries this" for one client alone.
///
/// Which is what the admin plane needs. Its scope is attached to the console and
/// to nothing else, so the console carries it without asking and the plane can
/// require it by default, rather than every admin UI having to remember to ask.
pub async fn granted_scope(
    transaction: &Transaction<'_>,
    client_id: &str,
    requested: &str,
) -> Result<String, Refusal> {
    let attached = client_scopes::scopes_of_client(transaction, client_id)
        .await
        .map_err(|_| Refusal::Redirect("server_error"))?;

    let mut granted: Vec<String> = Vec::new();
    for asked in requested.split_whitespace() {
        let entitled = asked == OPENID || attached.iter().any(|(scope, _)| scope.name == asked);
        if entitled && !granted.iter().any(|held| held == asked) {
            granted.push(asked.to_owned());
        }
    }
    for (scope, optional) in &attached {
        if !optional && !granted.iter().any(|held| held == &scope.name) {
            granted.push(scope.name.clone());
        }
    }
    Ok(granted.join(" "))
}

/// The client, or nothing that may be redirected to.
async fn named_client(
    transaction: &Transaction<'_>,
    client_id: Option<&str>,
) -> Result<ClientModel, Refusal> {
    let client_id = client_id
        .filter(|named| !named.is_empty())
        .ok_or(Refusal::Unshowable("invalid_request"))?;
    clients::load(transaction, client_id)
        .await
        .map_err(|_| Refusal::Unshowable("server_error"))?
        .filter(|client| client.enabled != Some(false))
        // One code for absent, unknown and switched off. Three would let a
        // caller read off which clients this realm holds.
        .ok_or(Refusal::Unshowable("unauthorized_client"))
}

/// The redirect, matched whole against what the client registered.
///
/// Exact, not a prefix and not a pattern. Every open redirector in this protocol
/// is a server that matched loosely, and the code grant compares against this
/// same value later, so a match that is looser here is a match the redemption
/// cannot tighten.
///
/// A client with no registered redirect has none, which refuses everything. The
/// other reading, that an empty registration permits anything, is the open
/// redirector written as a default.
fn registered_redirect<'a>(
    client: &ClientModel,
    asked: Option<&'a str>,
) -> Result<&'a str, Refusal> {
    let asked = asked
        .filter(|uri| !uri.is_empty())
        .ok_or(Refusal::Unshowable("invalid_request"))?;
    client
        .redirect_uris
        .as_ref()
        .is_some_and(|registered| registered.iter().any(|uri| uri == asked))
        .then_some(asked)
        .ok_or(Refusal::Unshowable("invalid_request"))
}

/// A public client authenticates with nothing, so the challenge is the whole of
/// its proof. Required here rather than only at redemption: a code minted
/// without one is one anybody who intercepts the redirect can spend, and by
/// redemption it is too late to have asked.
fn proof_is_registered(client: &ClientModel, requested: &Requested<'_>) -> Result<(), Refusal> {
    // S256 named, or nothing. RFC 7636 §4.3 reads an absent method as `plain`,
    // so accepting the omission is accepting `plain` under another spelling, and
    // refusing the word while accepting the silence refuses nothing.
    if requested.code_challenge.is_some() && requested.code_challenge_method != Some("S256") {
        return Err(Refusal::Redirect("invalid_request"));
    }
    if client.public_client == Some(true) && requested.code_challenge.is_none() {
        return Err(Refusal::Redirect("invalid_request"));
    }
    Ok(())
}

/// The flow this client's browser login runs.
async fn browser_flow(
    transaction: &Transaction<'_>,
    client: &ClientModel,
) -> Result<String, Refusal> {
    let named = client
        .auth_flow_binding_overrides
        .as_ref()
        .and_then(|bound| bound.get(BROWSER_FLOW))
        .and_then(AttributeValue::as_str)
        .unwrap_or(BROWSER_FLOW);

    auth_flows::flow_by_alias(transaction, named)
        .await
        .map_err(|_| Refusal::Redirect("server_error"))?
        .map(|flow| flow.flow_id)
        .ok_or(Refusal::Redirect("server_error"))
}

fn draw_id(provider: &dyn CryptoProvider) -> Result<String, Refusal> {
    let mut drawn = [0_u8; 16];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Refusal::Redirect("server_error"))?;
    Ok(data_encoding::HEXLOWER.encode(&drawn))
}
