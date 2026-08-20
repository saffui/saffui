//! Answering one step of a login a browser started.
//!
//! The flow runner decides; this is what surrounds it. Which login is being
//! answered, who the answer says the subject is, and, once the flow admits,
//! the SSO session and the code the client comes back to spend.

use chrono::{DateTime, Duration, Utc};
use crypto::provider::CryptoProvider;
use data_encoding::HEXLOWER;
use deadpool_postgres::Transaction;
use models::entities::acr::{self, AchievedAuth};
use models::entities::oidc::AuthorizationCode;
use models::sessions::records::{UserSessionModel, UserSessionState};
use serde_json::{Value, json};
use store::providers::login::AuthSession;
use store::providers::{login, oidc, realms, sessions, users};
use store::tenancy::TenantContext;

use crate::login::authenticator::Answer;
use crate::login::{Progress, run_flow};

/// How long a code may sit before it is spent.
///
/// One minute, which is OIDC Core §3.1.3.3's guidance. It travels through a
/// browser redirect and is spent immediately after, so anything longer is a
/// window nobody uses and an attacker might.
const CODE_LIFESPAN: i64 = 60;

/// How long the login it opens lasts.
const SSO_LIFESPAN: i64 = 36_000;

/// The context value a password step reaches. The realm decides what level that
/// is worth; this only says which name to look up.
const PASSWORD_CONTEXT: &str = "password";

/// Where a login stands after one answer.
#[derive(Debug)]
pub enum Step {
    /// A step is waiting. The caller answers again, naming the same login.
    Challenge { execution_id: String },
    /// Admitted. The browser goes here, and the client spends what it carries.
    /// The session is named so the transport can bind the browser to it.
    Admitted {
        redirect_to: String,
        session_id: String,
    },
    /// Refused, and no further answer changes that.
    Refused,
}

/// Why the step could not be run.
///
/// Separate from a refusal: a login nobody can find has not decided that this
/// caller may not in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unanswerable {
    #[error("no login is in progress under that name")]
    NoSuchLogin,
    #[error("the flow could not be run")]
    Unrunnable,
    #[error("the store could not be read")]
    Unreadable,
}

/// Run one step of the login named by `auth_session_id`.
pub async fn answer_step(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &TenantContext,
    auth_session_id: &str,
    username: Option<&str>,
    answer: Option<&Answer>,
    now: DateTime<Utc>,
) -> Result<Step, Unanswerable> {
    let login = login::resume(transaction, auth_session_id)
        .await
        .map_err(|_| Unanswerable::Unreadable)?
        .ok_or(Unanswerable::NoSuchLogin)?;

    let realm = realms::load(transaction, &tenant.realm_id)
        .await
        .map_err(|_| Unanswerable::Unreadable)?
        .ok_or(Unanswerable::Unreadable)?;

    // Resolved here rather than inside the flow: an authenticator says whether
    // an answer is right, not who is answering. A name nobody holds is passed
    // through as absent, and the flow spends the same time on it.
    let subject = named_subject(transaction, &login, username).await?;

    let progress = run_flow(
        transaction,
        provider,
        &realm,
        &login.flow_id,
        subject.as_ref(),
        answer,
        now,
    )
    .await
    .map_err(|_| Unanswerable::Unrunnable)?;

    match progress {
        Progress::Waiting { execution_id } => {
            // Written before the answer is asked for, so a login resumed on
            // another connection knows which step it is on.
            login::record_step(
                transaction,
                auth_session_id,
                subject.as_ref().map(|user| user.user_id.as_str()),
                Some(&execution_id),
                &json!({}),
            )
            .await
            .map_err(|_| Unanswerable::Unreadable)?;
            Ok(Step::Challenge { execution_id })
        }
        Progress::Refused => Ok(Step::Refused),
        Progress::Admitted => {
            let subject = subject.ok_or(Unanswerable::Unrunnable)?;
            let reached = realm
                .acr_loa_map
                .as_ref()
                .and_then(|map| map.loa_of(PASSWORD_CONTEXT));
            admit(
                transaction,
                provider,
                tenant,
                &login,
                &subject.user_id,
                &subject.user_name,
                reached,
                realm.acr_loa_map.as_ref(),
                now,
            )
            .await
            .map(|redirect_to| Step::Admitted {
                redirect_to,
                session_id: login.session_id.clone(),
            })
        }
    }
}

/// What a code is minted against, gathered so two callers state the same facts.
pub struct Authorized<'a> {
    pub client_id: &'a str,
    pub user_id: &'a str,
    pub session_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub state: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    /// When the user authenticated, not when this code was minted. `max_age`
    /// asks about the first, and a session begun at nine and re-authenticated
    /// at noon is three hours old with an authentication minutes old.
    pub auth_time: i64,
    /// The level the login actually reached. Frozen here because by redemption
    /// the session may have stepped up in another tab, and a value resolved
    /// then would attest to a strength this code was never issued under.
    pub acr: Option<&'a str>,
}

/// Mint a code and say where the browser goes with it.
///
/// Shared, because `/authorize` mints one when it finds a live login and this
/// module mints one when a flow just finished. Two mintings would be two places
/// for a field to be forgotten.
pub async fn mint_code(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &TenantContext,
    authorized: &Authorized<'_>,
    now: DateTime<Utc>,
) -> Result<String, Unanswerable> {
    let raw = draw(provider)?;
    oidc::mint_code(
        transaction,
        &AuthorizationCode {
            code_hash: digest(provider, raw.as_bytes())?,
            tenant: tenant.tenant.clone(),
            realm_id: tenant.realm_id.clone(),
            client_id: authorized.client_id.to_owned(),
            user_id: authorized.user_id.to_owned(),
            session_id: authorized.session_id.to_owned(),
            redirect_uri: authorized.redirect_uri.to_owned(),
            scope: authorized.scope.to_owned(),
            nonce: authorized.nonce.map(str::to_owned),
            code_challenge: authorized.code_challenge.map(str::to_owned),
            code_challenge_method: authorized.code_challenge_method.map(str::to_owned),
            auth_time: authorized.auth_time,
            acr: authorized.acr.map(str::to_owned),
            org_id: None,
            org_name: None,
        },
        now + Duration::seconds(CODE_LIFESPAN),
    )
    .await
    .map_err(|_| Unanswerable::Unreadable)?;

    Ok(landing(authorized.redirect_uri, &raw, authorized.state))
}

/// Open the login, mint the code, and say where the browser goes.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one login"
)]
async fn admit(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &TenantContext,
    login: &AuthSession,
    user_id: &str,
    user_name: &str,
    reached: Option<i32>,
    realm_map: Option<&models::entities::acr::AcrLoaMap>,
    now: DateTime<Utc>,
) -> Result<String, Unanswerable> {
    // The transient identifier becomes the durable one. The code names it as
    // `sid`, and one identifier means a login and the session it opened cannot
    // drift apart.
    sessions::open(
        transaction,
        &UserSessionModel {
            tenant: tenant.tenant.clone(),
            session_id: login.session_id.clone(),
            realm_id: tenant.realm_id.clone(),
            user_id: user_id.to_owned(),
            login_username: user_name.to_owned(),
            broker_session_id: None,
            broker_user_id: None,
            auth_method: Some("browser".to_owned()),
            ip_address: None,
            started_at: now.timestamp(),
            auth_time: Some(now.timestamp()),
            // What the flow reached, under this realm's map. Only a password
            // step exists, so that is what is looked up; a realm mapping nothing
            // records nothing rather than a level it never defined.
            loa: reached,
            expiration: Some((now + Duration::seconds(SSO_LIFESPAN)).timestamp()),
            state: UserSessionState::LoggedIn,
            remember_me: Some(false),
            last_session_refresh: None,
            is_offline: Some(false),
            notes: None,
        },
    )
    .await
    .map_err(|_| Unanswerable::Unreadable)?;

    let notes = &login.notes;
    let landing = mint_code(
        transaction,
        provider,
        tenant,
        &Authorized {
            client_id: &login.client_id,
            user_id,
            session_id: &login.session_id,
            redirect_uri: &login.redirect_uri,
            scope: noted(notes, "scope").unwrap_or_default(),
            state: noted(notes, "state"),
            nonce: noted(notes, "nonce"),
            code_challenge: noted(notes, "code_challenge"),
            code_challenge_method: noted(notes, "code_challenge_method"),
            auth_time: now.timestamp(),
            // Frozen here. By redemption the session may have stepped up in
            // another tab, and a value resolved then would attest to a strength
            // this code was never issued under.
            acr: reached.and_then(|loa| {
                realm_map.and_then(|map| {
                    acr::acr_claim(
                        map,
                        AchievedAuth {
                            loa,
                            auth_time: now.timestamp(),
                        },
                    )
                })
            }),
        },
        now,
    )
    .await?;

    // The login in progress is over. Leaving it would let the same answer mint
    // a second code for one authorization.
    login::finish(transaction, &login.session_id)
        .await
        .map_err(|_| Unanswerable::Unreadable)?;

    Ok(landing)
}

/// Where the browser goes, carrying what the client will spend.
fn landing(redirect_uri: &str, code: &str, state: Option<&str>) -> String {
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut landing = format!("{redirect_uri}{separator}code={}", escaped(code));
    if let Some(state) = state {
        landing.push_str(&format!("&state={}", escaped(state)));
    }
    landing
}

/// Percent encoding for a query value, RFC 3986 §2.3's unreserved set kept and
/// everything else escaped.
fn escaped(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

fn noted<'a>(notes: &'a Value, named: &str) -> Option<&'a str> {
    notes.get(named).and_then(Value::as_str)
}

/// Who the login is for: the one it already resolved, or the one this answer
/// names.
async fn named_subject(
    transaction: &Transaction<'_>,
    login: &AuthSession,
    username: Option<&str>,
) -> Result<Option<models::entities::user::UserModel>, Unanswerable> {
    if let Some(user_id) = login.user_id.as_deref() {
        return users::load(transaction, user_id)
            .await
            .map_err(|_| Unanswerable::Unreadable);
    }
    match username.filter(|named| !named.is_empty()) {
        None => Ok(None),
        Some(named) => users::load_by_name(transaction, named)
            .await
            .map_err(|_| Unanswerable::Unreadable),
    }
}

fn draw(provider: &dyn CryptoProvider) -> Result<String, Unanswerable> {
    let mut drawn = [0_u8; 32];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unanswerable::Unreadable)?;
    Ok(HEXLOWER.encode(&drawn))
}

/// The digest the row is keyed by. The raw code goes to the browser and is
/// never stored, so a leaked table yields nothing spendable.
fn digest(provider: &dyn CryptoProvider, raw: &[u8]) -> Result<String, Unanswerable> {
    let hashed = provider
        .digest()
        .hash(crypto::provider::HashAlg::Sha256, raw)
        .map_err(|_| Unanswerable::Unreadable)?;
    Ok(HEXLOWER.encode(&hashed))
}
