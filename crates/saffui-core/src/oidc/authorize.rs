//! The authorization endpoint: the code flow, with PKCE.
//!
//! The order of the checks is the security of this file. Until the client
//! and its redirect URI are trusted, a refusal is shown to the person and
//! nothing is sent anywhere. Only after that may a refusal travel to the
//! client, on the redirect URI it registered.

use std::fmt::{self, Write as _};
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use time::Duration;
use uuid::Uuid;

use super::code::{AuthorizationCode, PendingAuthorization};
use super::discovery::name_issuer;
use super::errors::OAuthError;
use super::pkce::is_well_formed_challenge;
use crate::app::App;
use crate::clients::{Client, check_scope_token, read_named_client};
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::login::device::DeviceMark;
use crate::login::session::{Session, SessionTicket, close_session, find_live_session};
use crate::login::steps::password::sign_in;
use crate::login::throttle::admit_pending_sign_in;
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;
use crate::tenancy::RealmName;
use crate::tenancy::resolve::resolve_realm;
use crate::tokens::verify::read_identity_hint;

/// How long a code lives: the time of one redirect and one request.
const CODE_LIFETIME: Duration = Duration::seconds(60);
/// How long a request waits for its person to sign in.
const PENDING_LIFETIME: Duration = Duration::minutes(10);
/// The longest `state` or `nonce` a client may send.
const OPAQUE_VALUE_MAX_BYTES: usize = 512;

/// What a client sent to the authorization endpoint, as read from the query.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthorizationParameters<'a> {
    pub response_type: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub redirect_uri: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub state: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    /// `none`, `login`, `consent`, `select_account`, separated by spaces.
    pub prompt: Option<&'a str>,
    /// The longest time, in seconds, since the person last proved who they are.
    pub max_age: Option<&'a str>,
    /// An identity token the client was given earlier: the person it expects.
    pub id_token_hint: Option<&'a str>,
    /// The address of the browser, as a believed proxy said: the sign-ins
    /// it leaves waiting are counted under it.
    pub caller: Option<IpAddr>,
    /// The marks the browser keeps: a browser the realm knows leaves its
    /// sign-ins waiting under its device, not under the address.
    pub known_browsers: &'a [DeviceMark],
}

pub enum Authorization {
    /// The person is signed in: the browser goes back to the client with a code.
    Granted { location: String },
    /// The person must sign in. The request waits under this identifier, and
    /// only the browser that holds this secret can finish it.
    SignInRequired {
        request: Uuid,
        browser_secret: Secret,
    },
}

#[derive(Debug)]
pub enum AuthorizationRefusal {
    /// Told to the person: the client or its redirect URI is not trusted.
    Shown(Failure),
    /// Sent to the client, on the redirect URI it registered.
    Returned { location: String },
}

// Written by hand: the location of a granted request carries the code.
impl fmt::Debug for Authorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted { .. } => formatter
                .debug_struct("Granted")
                .field("location", &"..")
                .finish(),
            Self::SignInRequired { request, .. } => formatter
                .debug_struct("SignInRequired")
                .field("request", request)
                .finish_non_exhaustive(),
        }
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
    code_challenge: String,
    /// How the person must have proved who they are for a session to serve.
    proof: ProofAsked,
}

/// What `prompt` and `max_age` ask of the session that would answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProofAsked {
    /// A sign-in now, whatever session there is.
    fresh: bool,
    /// No page: a session answers, or the client is told one is needed.
    silent: bool,
    /// A consent this realm has no page to ask for: refused, never assumed.
    consent: bool,
    /// A session older than this many seconds does not answer.
    max_age: Option<i64>,
}

/// Reads `prompt` and `max_age`. A value this realm does not know, `none`
/// beside another, or an age that is not a number of seconds is refused.
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
        if written.len() > 10 || !written.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        asked.max_age = Some(written.parse().ok()?);
    }
    Some(asked)
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

/// Builds the redirection back to the client. The issuer travels with every
/// answer, so that a client talking to several providers knows who answered.
fn write_return_location(
    redirect_uri: &str,
    issuer: &str,
    state: Option<&str>,
    answer: &[(&str, &str)],
) -> String {
    let mut location = redirect_uri.to_owned();
    location.push(if redirect_uri.contains('?') { '&' } else { '?' });
    for (name, value) in answer {
        location.push_str(name);
        location.push('=');
        write_query_value(&mut location, value);
        location.push('&');
    }
    if let Some(state) = state {
        location.push_str("state=");
        write_query_value(&mut location, state);
        location.push('&');
    }
    location.push_str("iss=");
    write_query_value(&mut location, issuer);
    location
}

async fn trust_request(
    app: &App,
    realm: &str,
    parameters: AuthorizationParameters<'_>,
    work_slot: &mut Option<Box<dyn UnitOfWork>>,
) -> Result<TrustedRequest, AuthorizationRefusal> {
    let (realm, scope) = resolve_realm(app, realm).await?;
    let work = work_slot.insert(app.storage.begin(scope).await.map_err(Failure::from)?);

    // Shown, never returned: there is nowhere trusted to return to yet.
    let client_id = parameters
        .client_id
        .ok_or(Failure::new(ErrorCode::ClientNotFound))?;
    let client = read_named_client(work.as_mut(), client_id)
        .await
        .map_err(Failure::from)?
        .filter(|client| client.enabled && client.allows_authorization_code)
        .ok_or(Failure::new(ErrorCode::ClientNotFound))?;
    let redirect_uri = parameters
        .redirect_uri
        .filter(|asked| {
            client
                .redirect_uris
                .iter()
                .any(|registered| registered == asked)
        })
        .ok_or(Failure::new(ErrorCode::RedirectUriMismatch))?
        .to_owned();

    let issuer = name_issuer(&app.settings, &realm);
    // Too long, or with a character no client writes on purpose: such a value
    // is neither kept nor echoed back.
    let unacceptable =
        |value: &str| value.len() > OPAQUE_VALUE_MAX_BYTES || value.chars().any(char::is_control);
    let state = parameters.state.filter(|state| !unacceptable(state));
    let returned = |error: OAuthError| AuthorizationRefusal::Returned {
        location: write_return_location(&redirect_uri, &issuer, state, &[("error", error.name())]),
    };

    if parameters.state.is_some_and(unacceptable) || parameters.nonce.is_some_and(unacceptable) {
        return Err(returned(OAuthError::InvalidRequest));
    }
    if parameters.response_type != Some("code") {
        return Err(returned(OAuthError::UnsupportedResponseType));
    }
    let challenge = parameters
        .code_challenge
        .filter(|challenge| is_well_formed_challenge(challenge));
    let (Some(code_challenge), Some("S256")) = (challenge, parameters.code_challenge_method) else {
        return Err(returned(OAuthError::InvalidRequest));
    };
    let proof = read_proof_asked(parameters.prompt, parameters.max_age)
        .ok_or_else(|| returned(OAuthError::InvalidRequest))?;
    // Consent cannot be asked yet: refused, as OIDC Core asks, never taken as given.
    if proof.consent {
        return Err(returned(OAuthError::ConsentRequired));
    }
    let mut scopes = Vec::new();
    for token in parameters
        .scope
        .unwrap_or_default()
        .split(' ')
        .filter(|token| !token.is_empty())
    {
        if check_scope_token(token).is_err()
            || !client.scopes.iter().any(|allowed| allowed == token)
        {
            return Err(returned(OAuthError::InvalidScope));
        }
        if !scopes.iter().any(|known| known == token) {
            scopes.push(token.to_owned());
        }
    }
    Ok(TrustedRequest {
        realm,
        client,
        redirect_uri,
        scopes,
        state: state.map(str::to_owned),
        nonce: parameters.nonce.map(str::to_owned),
        code_challenge: code_challenge.to_owned(),
        proof,
    })
}

struct CodeGrant<'a> {
    realm: &'a RealmName,
    client_id: &'a str,
    redirect_uri: &'a str,
    scopes: &'a [String],
    state: Option<&'a str>,
    nonce: Option<&'a str>,
    code_challenge: &'a str,
    person: Uuid,
    session: Uuid,
    authenticated_at: time::OffsetDateTime,
}

/// Mints a code, keeps its digest, and returns where to send the browser.
async fn issue_code(
    app: &App,
    work: &mut dyn UnitOfWork,
    grant: CodeGrant<'_>,
) -> Result<String, Failure> {
    let mut random = [0_u8; 32];
    app.random
        .fill(&mut random)
        .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
    let code = URL_SAFE_NO_PAD.encode(random);
    work.insert_authorization_code(&AuthorizationCode {
        code_digest: app.digester.sha256(code.as_bytes()).to_vec(),
        client_id: grant.client_id.to_owned(),
        person: grant.person,
        session: grant.session,
        redirect_uri: grant.redirect_uri.to_owned(),
        scopes: grant.scopes.to_vec(),
        nonce: grant.nonce.map(str::to_owned),
        code_challenge: grant.code_challenge.to_owned(),
        authenticated_at: grant.authenticated_at,
        expires_at: app.now() + CODE_LIFETIME,
    })
    .await?;
    let issuer = name_issuer(&app.settings, grant.realm);
    Ok(write_return_location(
        grant.redirect_uri,
        &issuer,
        grant.state,
        &[("code", &code)],
    ))
}

/// A hint names the person the client expects. The session of someone else
/// does not answer for them: the person is asked, or, without a page, the
/// client is told a sign-in is needed. A hint that is not an identity token
/// this realm gave this very client is refused. Returns the session that
/// answers, and the person the hint names.
async fn hold_session_to_hint(
    app: &App,
    work: &mut dyn UnitOfWork,
    trusted: &TrustedRequest,
    issuer: &str,
    hint: &str,
    session: Option<Session>,
) -> Result<(Option<Session>, Uuid), AuthorizationRefusal> {
    let expected = read_identity_hint(app, work, issuer, hint)
        .await?
        .filter(|named| named.client_id == trusted.client.client_id)
        .and_then(|named| Uuid::parse_str(&named.subject).ok());
    let Some(expected) = expected else {
        return Err(AuthorizationRefusal::Returned {
            location: write_return_location(
                &trusted.redirect_uri,
                issuer,
                trusted.state.as_deref(),
                &[("error", OAuthError::InvalidRequest.name())],
            ),
        });
    };
    Ok((
        session.filter(|session| session.person == expected),
        expected,
    ))
}

/// Keeps a request no session answered until a person signs in for it, and
/// gives back its id and the secret only the browser that asked holds.
async fn keep_pending_authorization(
    app: &App,
    work: &mut dyn UnitOfWork,
    trusted: TrustedRequest,
    expected_person: Option<Uuid>,
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
        code_challenge: trusted.code_challenge,
        expires_at: app.now() + PENDING_LIFETIME,
        expected_person,
    };
    work.insert_pending_authorization(&pending)
        .await
        .map_err(Failure::from)?;
    Ok((pending.id, browser_secret))
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
    let trusted = trust_request(app, realm, parameters, &mut work_slot).await?;
    let work = work_slot
        .as_mut()
        .ok_or(Failure::new(ErrorCode::Internal))?;

    let session = match ticket {
        Some(ticket) if !trusted.proof.fresh => {
            find_live_session(app, work.as_mut(), ticket).await?
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
    let (session, expected_person) = match parameters.id_token_hint.filter(|hint| !hint.is_empty())
    {
        Some(hint) => {
            let (session, expected) =
                hold_session_to_hint(app, work.as_mut(), &trusted, &issuer, hint, session).await?;
            (session, Some(expected))
        }
        None => (session, None),
    };
    if session.is_none() && trusted.proof.silent {
        return Err(AuthorizationRefusal::Returned {
            location: write_return_location(
                &trusted.redirect_uri,
                &issuer,
                trusted.state.as_deref(),
                &[("error", OAuthError::LoginRequired.name())],
            ),
        });
    }
    if let Some(session) = session {
        let location = issue_code(
            app,
            work.as_mut(),
            CodeGrant {
                realm: &trusted.realm,
                client_id: &trusted.client.client_id,
                redirect_uri: &trusted.redirect_uri,
                scopes: &trusted.scopes,
                state: trusted.state.as_deref(),
                nonce: trusted.nonce.as_deref(),
                code_challenge: &trusted.code_challenge,
                person: session.person,
                session: session.id,
                authenticated_at: session.authenticated_at,
            },
        )
        .await?;
        work_slot
            .take()
            .ok_or(Failure::new(ErrorCode::Internal))?
            .commit()
            .await
            .map_err(Failure::from)?;
        return Ok(Authorization::Granted { location });
    }

    admit_pending_sign_in(
        app,
        work.as_mut(),
        parameters.caller,
        parameters.known_browsers,
    )
    .await?;
    let (request, browser_secret) =
        keep_pending_authorization(app, work.as_mut(), trusted, expected_person).await?;
    work_slot
        .take()
        .ok_or(Failure::new(ErrorCode::Internal))?
        .commit()
        .await
        .map_err(Failure::from)?;
    Ok(Authorization::SignInRequired {
        request,
        browser_secret: Secret::new(browser_secret),
    })
}

/// A person signed in on the login page of a pending request.
pub struct SignedInForRequest {
    /// Where the browser goes next: back to the client, with a code.
    pub location: String,
    pub ticket: SessionTicket,
    /// What the browser keeps, to be counted apart at its next sign-in.
    pub device_mark: DeviceMark,
}

/// What a person typed on the sign-in page, and where it comes from.
pub struct TypedSignIn<'a> {
    pub name: &'a str,
    pub password: Secret,
    /// The address of the browser, as a believed proxy said.
    pub caller: Option<IpAddr>,
    /// The marks of earlier sign-ins the browser brings, the latest first.
    pub known_browsers: &'a [DeviceMark],
}

// Written by hand: the location carries the code.
impl fmt::Debug for SignedInForRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedInForRequest")
            .field("location", &"..")
            .field("ticket", &self.ticket)
            .field("device_mark", &"..")
            .finish()
    }
}

/// Finishes a pending request with the name and the password a person typed.
///
/// # Errors
///
/// Returns [`ErrorCode::AuthorizationRequestExpired`] when the request is
/// unknown, expired, or was started by another browser: the three answer
/// alike. Returns [`ErrorCode::SignInFailed`] when the person is refused:
/// the request then still waits. Returns the storage failure otherwise.
pub async fn finish_sign_in(
    app: &App,
    realm: &str,
    request: Uuid,
    browser_secret: &Secret,
    typed: TypedSignIn<'_>,
) -> Result<SignedInForRequest, Failure> {
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
    if pending.is_none() || !same_browser {
        return Err(expired());
    }

    let signed_in = sign_in(
        app,
        scope,
        typed.name,
        typed.password,
        typed.caller,
        typed.known_browsers,
    )
    .await?;

    let mut work = app.storage.begin(scope).await?;
    // Taken, not read: of two submissions of one page, one finishes the
    // request. The other signed in for nothing, and its session ends here.
    let Some(pending) = work.take_pending_authorization(request, app.now()).await? else {
        if let Some(orphan) = work.read_session(signed_in.session).await? {
            close_session(app, work.as_mut(), &orphan).await?;
            work.commit().await?;
        }
        return Err(expired());
    };
    // The person a hint named is the one the client waits for: anyone else
    // signed in for themselves, and the client is told a sign-in is needed.
    if pending
        .expected_person
        .is_some_and(|expected| expected != signed_in.person.id)
    {
        work.commit().await?;
        let issuer = name_issuer(&app.settings, &realm);
        return Ok(SignedInForRequest {
            location: write_return_location(
                &pending.redirect_uri,
                &issuer,
                pending.state.as_deref(),
                &[("error", OAuthError::LoginRequired.name())],
            ),
            ticket: signed_in.ticket,
            device_mark: signed_in.device_mark,
        });
    }
    let location = issue_code(
        app,
        work.as_mut(),
        CodeGrant {
            realm: &realm,
            client_id: &pending.client_id,
            redirect_uri: &pending.redirect_uri,
            scopes: &pending.scopes,
            state: pending.state.as_deref(),
            nonce: pending.nonce.as_deref(),
            code_challenge: &pending.code_challenge,
            person: signed_in.person.id,
            session: signed_in.session,
            authenticated_at: app.now(),
        },
    )
    .await?;
    work.commit().await?;
    Ok(SignedInForRequest {
        location,
        ticket: signed_in.ticket,
        device_mark: signed_in.device_mark,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value;
    use uuid::Uuid;

    use super::{
        Authorization, AuthorizationParameters, AuthorizationRefusal, TypedSignIn,
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
            prompt: None,
            max_age: None,
            id_token_hint: None,
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
                name,
                password: Secret::new(PASSWORD.as_bytes().to_vec()),
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person");
        (signed_in.location, signed_in.ticket)
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
            client_secret: secret.map(|secret| Secret::new(secret.expose().to_vec())),
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
    }

    fn refresh(app: &App, secret: Option<&Secret>, refresh_token: &str) -> Result<(), OAuthError> {
        let request = TokenRequest {
            grant_type: Some("refresh_token"),
            client_id: Some("webapp"),
            client_secret: secret.map(|secret| Secret::new(secret.expose().to_vec())),
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
        let (location, _ticket) = sign_in_through_the_flow(&app);
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
        assert_eq!(revocations[0]["payload"]["reason"], "code_replayed");
        assert_eq!(revocations[0]["payload"]["client_id"], "webapp");
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
            Err(AuthorizationRefusal::Returned { location }) => {
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
                    name: "ada",
                    password: Secret::new(password.as_bytes().to_vec()),
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
                name: "ada",
                password: Secret::new(PASSWORD.as_bytes().to_vec()),
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
            let Err(AuthorizationRefusal::Returned { location }) = returned else {
                panic!("a trusted client gets its error back: {returned:?}");
            };
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
                name: "ada",
                password: Secret::new(PASSWORD.as_bytes().to_vec()),
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person")
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
                name: "ada",
                password: Secret::new(PASSWORD.as_bytes().to_vec()),
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person")
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
                Err(AuthorizationRefusal::Returned { location }) => {
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
            "consent_required",
            "there is no page to ask it on: it is refused, not assumed"
        );
        clock.advance(Duration::from_secs(3_601));
        assert_eq!(ask_with(None, Some("3600"), Some(&ticket)), "sign in");
        assert_eq!(
            ask_with(Some("none"), Some("3600"), Some(&ticket)),
            "login_required"
        );
    }

    #[test]
    fn a_session_answers_a_hint_only_for_the_person_it_names() {
        let (app, _storage, _clock, secret) = start(false);
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
                Err(AuthorizationRefusal::Returned { location }) => {
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
                    name,
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                    caller: None,
                    known_browsers: &[],
                },
            ))
            .expect("a signed-in person")
            .location
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

        let Err(AuthorizationRefusal::Returned { location }) = refused else {
            panic!("returned to the client: {refused:?}");
        };
        assert!(location.starts_with(other_callback), "{location}");
        assert_eq!(
            read_query(&location, "error").as_deref(),
            Some("invalid_request")
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
            let Err(AuthorizationRefusal::Returned { location }) = returned else {
                panic!("returned to the client: {returned:?}");
            };
            assert_eq!(
                read_query(&location, "error").as_deref(),
                Some("invalid_request"),
                "{prompt:?} {max_age:?}"
            );
        }
    }
}
