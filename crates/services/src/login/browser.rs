//! Answering one step of a login a browser started.
//!
//! The flow runner decides; this is what surrounds it. Which login is being
//! answered, who the answer says the subject is, and, once the flow admits,
//! the SSO session and the code the client comes back to spend.

use chrono::{DateTime, Duration, Utc};
use config::serving::PublicOrigin;
use crypto::provider::CryptoProvider;
use data_encoding::HEXLOWER;
use deadpool_postgres::Transaction;
use models::entities::acr::{self, AchievedAuth};
use models::entities::oidc::AuthorizationCode;
use models::sessions::records::{UserSessionModel, UserSessionState};
use serde_json::Value;
use store::providers::login::AuthSession;
use store::providers::{login, oidc, realms, sessions, users};
use store::tenancy::TenantContext;

use crate::claims_request::ClaimsRequest;
use crate::landing::{Landing, ResponseMode};
use crate::login::authenticator::Answer;
use crate::login::enrolment::{self, Enrolment};
use crate::login::{Progress, run_flow};
use crate::response_type::ResponseType;

/// How long a code may sit before it is spent.
///
/// One minute, which is OIDC Core §3.1.3.3's guidance. It travels through a
/// browser redirect and is spent immediately after, so anything longer is a
/// window nobody uses and an attacker might.
const CODE_LIFESPAN: i64 = 60;

/// How long the login it opens lasts.
const SSO_LIFESPAN: i64 = 36_000;

/// What it takes to open a realm's sealed values.
#[derive(Clone, Copy)]
pub struct Sealing<'a> {
    pub ring: &'a store::keyring::RealmKeyring,
    pub envelope: &'a crypto::envelope::Envelope,
}

/// Where a login stands after one answer.
#[derive(Debug)]
pub enum Step {
    /// A step is waiting. The caller answers again, naming the same login, and
    /// is shown what the step issued when it issued anything.
    Challenge {
        execution_id: String,
        asks: Option<Value>,
        /// A message this round produced, to be sent once the caller has
        /// committed. Never sent inside the transaction that made it.
        ///
        /// Boxed: it carries a realm's whole mail settings, and every other
        /// variant would otherwise be as large as the one that has them.
        sending: Option<Box<crate::messaging::Outgoing>>,
    },
    /// Admitted. The browser goes here, and the client spends what it carries.
    /// The session is named so the transport can bind the browser to it.
    Admitted {
        landing: Landing,
        session_id: String,
    },
    /// Refused, and no further answer changes that.
    Refused,
    /// Authenticated, and still not what the client asked for: it named a
    /// subject and somebody else logged in. The client hears, at its redirect,
    /// and no session opens, since §3.1.2.2 forbids answering for another user.
    SentBack { landing: Landing },
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
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one step"
)]
pub async fn answer_step(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &TenantContext,
    origin: &PublicOrigin,
    auth_session_id: &str,
    username: Option<&str>,
    answers: &[Answer],
    // What finishes an enrolment, when the realm required one. Not an
    // [`Answer`]: it proves nothing about who is answering.
    enrolling: enrolment::Answers<'_>,
    seen: &crate::provenance::Provenance,
    // Whether anything carries a message out of this deployment.
    sends: bool,
    // What it takes to open this realm's sealed values. Absent where a caller
    // has no step that needs one, which is every flow but a mailed one.
    sealing: Option<Sealing<'_>>,
    // What it takes to sign, when the request wants something minted here.
    signing: Option<&crate::grant::Signing<'_>>,
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

    // Read before the flow rather than inside a step: a step that reached for
    // the realm's keyring would be one every other step pays for.
    let mail = match sealing {
        None => None,
        Some(sealing) => store::providers::mail::load(transaction, sealing.ring, sealing.envelope)
            .await
            .map_err(|_| Unanswerable::Unreadable)?,
    };

    let (progress, sending) = run_flow(
        transaction,
        provider,
        &realm,
        origin,
        &login.flow_id,
        subject.as_ref(),
        answers,
        // What the previous round of this same login remembered. A challenge is
        // verified against what was handed out, never against what came back.
        &login.notes,
        Some(crate::login::authenticator::Posting {
            auth_session_id,
            realm_name: &realm.name,
            mail: mail.as_ref(),
            can_send: sends,
            now,
        }),
    )
    .await
    .map_err(|_| Unanswerable::Unrunnable)?;

    match progress {
        Progress::Waiting {
            execution_id,
            asks,
            remember,
        } => {
            // Written before the answer is asked for, so a login resumed on
            // another connection knows which step it is on.
            // What the step issued goes down with where the flow stands. The
            // notes merge rather than replace, so a second step's state does not
            // drop the first's.
            login::record_step(
                transaction,
                auth_session_id,
                subject.as_ref().map(|user| user.user_id.as_str()),
                Some(&execution_id),
                &Value::Object(remember),
            )
            .await
            .map_err(|_| Unanswerable::Unreadable)?;
            Ok(Step::Challenge {
                execution_id,
                asks,
                sending,
            })
        }
        Progress::Refused => Ok(Step::Refused),
        Progress::Admitted { by } => {
            let subject = subject.ok_or(Unanswerable::Unrunnable)?;
            // Admitted is not yet in: what the realm required of this user
            // runs now, under an identity the flow has finished proving, and
            // the login completes only once nothing more is required.
            match enrolment::required(
                transaction,
                provider,
                tenant,
                &realm,
                origin,
                &subject,
                enrolling,
                &login.notes,
            )
            .await
            {
                Enrolment::Settled => {}
                Enrolment::Refused => return Ok(Step::Refused),
                Enrolment::Asked { named, challenge } => {
                    let mut remember = serde_json::Map::new();
                    remember.insert(named.to_owned(), challenge.remembered);
                    login::record_step(
                        transaction,
                        auth_session_id,
                        Some(&subject.user_id),
                        // The ceremony is not an execution row, and the
                        // column holds a foreign key to those.
                        None,
                        &Value::Object(remember),
                    )
                    .await
                    .map_err(|_| Unanswerable::Unreadable)?;
                    return Ok(Step::Challenge {
                        sending: None,
                        execution_id: named.to_owned(),
                        asks: Some(challenge.shown),
                    });
                }
            }
            // A request for one subject is answered for that subject or not at
            // all. The login is over either way; what differs is who hears.
            let asked = login
                .notes
                .get("claims")
                .map(ClaimsRequest::from_value)
                .unwrap_or_default();
            if asked
                .subject_asked()
                .is_some_and(|wanted| wanted != subject.user_id)
            {
                login::finish(transaction, &login.session_id)
                    .await
                    .map_err(|_| Unanswerable::Unreadable)?;
                return Ok(Step::SentBack {
                    landing: sent_back(
                        &login.redirect_uri,
                        "login_required",
                        noted(&login.notes, "state"),
                        answering(&login.notes),
                    ),
                });
            }
            // The highest of what actually ran. A flow that reached a second
            // factor is stronger than the password that opened it, and reading
            // only the first would report a level the login exceeded.
            let reached = realm
                .acr_loa_map
                .as_ref()
                .and_then(|map| by.iter().filter_map(|ran| map.loa_of(ran.context())).max());
            admit(
                transaction,
                provider,
                tenant,
                &login,
                &subject.user_id,
                &subject.user_name,
                reached,
                &realm,
                origin.issuer(&tenant.realm_id),
                signing,
                seen,
                now,
            )
            .await
            .map(|landing| Step::Admitted {
                landing,
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
    /// How the answer travels, as the request that opened this named it.
    pub mode: ResponseMode,
    /// What comes back.
    pub asked_for: ResponseType,
    /// Both needed only when something is minted here.
    pub signing: Option<&'a crate::grant::Signing<'a>>,
    pub realm: Option<&'a models::entities::realm::RealmModel>,
    pub issuer: &'a str,
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
    /// The `claims` the request named, as the store keeps them.
    pub claims: Option<&'a Value>,
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
) -> Result<Landing, Unanswerable> {
    // An implicit request gets nothing to redeem, and a code minted anyway is
    // a spendable credential nobody comes back for.
    let raw = authorized
        .asked_for
        .code
        .then(|| draw(provider))
        .transpose()?;
    if let Some(raw) = &raw {
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
                claims: authorized.claims.cloned(),
            },
            now + Duration::seconds(CODE_LIFESPAN),
        )
        .await
        .map_err(|_| Unanswerable::Unreadable)?;
    }

    let mut answer = Landing::new(authorized.redirect_uri, authorized.mode);
    if let Some(raw) = &raw {
        answer = answer.carrying("code", raw.as_str());
    }
    // After the code: the identity token carries its hash.
    if authorized.asked_for.mints_here() {
        let (Some(signing), Some(realm)) = (authorized.signing, authorized.realm) else {
            return Err(Unanswerable::Unrunnable);
        };
        let handed = crate::implicit::issue(
            transaction,
            signing,
            tenant,
            authorized.asked_for,
            &crate::implicit::Established {
                client: &client_of(transaction, authorized.client_id).await?,
                realm,
                issuer: authorized.issuer,
                user_id: authorized.user_id,
                session_id: authorized.session_id,
                scope: authorized.scope,
                nonce: authorized.nonce,
                auth_time: authorized.auth_time,
                acr: authorized.acr,
                code: raw.as_deref(),
                claims: authorized.claims,
            },
            now,
        )
        .await
        .map_err(|_| Unanswerable::Unrunnable)?;
        for (named, value) in handed {
            answer = answer.carrying(named, value);
        }
    }
    Ok(answer.carrying_any("state", authorized.state))
}

/// The client this is being minted for.
async fn client_of(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> Result<models::entities::client::ClientModel, Unanswerable> {
    store::providers::clients::load(transaction, client_id)
        .await
        .map_err(|_| Unanswerable::Unreadable)?
        .ok_or(Unanswerable::Unrunnable)
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
    realm: &models::entities::realm::RealmModel,
    issuer: String,
    signing: Option<&crate::grant::Signing<'_>>,
    seen: &crate::provenance::Provenance,
    now: DateTime<Utc>,
) -> Result<Landing, Unanswerable> {
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
            ip_address: seen.address.clone(),
            user_agent: seen.agent.clone(),
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
            mode: answering(notes),
            asked_for: coming_back(notes),
            signing,
            realm: Some(realm),
            issuer: &issuer,
            nonce: noted(notes, "nonce"),
            code_challenge: noted(notes, "code_challenge"),
            code_challenge_method: noted(notes, "code_challenge_method"),
            claims: notes.get("claims").filter(|asked| asked.is_object()),
            auth_time: now.timestamp(),
            // Frozen here. By redemption the session may have stepped up in
            // another tab, and a value resolved then would attest to a strength
            // this code was never issued under.
            acr: reached.and_then(|loa| {
                realm.acr_loa_map.as_ref().and_then(|map| {
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

/// What this login hands back. A login opened before this build knew about
/// anything else carries none.
fn coming_back(notes: &Value) -> ResponseType {
    noted(notes, "response_type")
        .and_then(ResponseType::read)
        .unwrap_or(ResponseType {
            code: true,
            id_token: false,
            token: false,
        })
}

/// How this login's answer travels. A login opened before this build knew
/// about modes carries none, and the one a code gets is the answer.
fn answering(notes: &Value) -> ResponseMode {
    ResponseMode::read(noted(notes, "response_mode")).unwrap_or_default()
}

/// What the client is told no with, RFC 6749 §4.1.2.1: the error at the
/// redirect, with the state the client asked to have echoed.
fn sent_back(redirect_uri: &str, error: &str, state: Option<&str>, mode: ResponseMode) -> Landing {
    Landing::new(redirect_uri, mode)
        .carrying("error", error)
        .carrying_any("state", state)
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
