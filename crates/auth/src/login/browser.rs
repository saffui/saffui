use chrono::{DateTime, Duration, Utc};
use config::serving::PublicOrigin;
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use models::sessions::records::{UserSessionModel, UserSessionState};
use serde_json::Value;
use store::providers::login::AuthSession;
use store::providers::{login, realms, sessions, users};
use store::tenancy::TenantContext;

use crate::login::authenticator::Answer;
use crate::login::enrolment::{self, Enrolment};
use crate::login::{Progress, run_flow};
use models::claims_request::ClaimsRequest;

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
    /// The flow wants something more from the person.
    Challenge {
        execution_id: String,
        asks: Option<serde_json::Value>,
        sending: Option<Box<crate::messaging::Outgoing>>,
    },
    /// The client asks for what the person has not agreed to.
    Consent {
        client_id: String,
        client_name: String,
        scopes: Vec<String>,
    },
    /// The person is established, and the login is over. What is done with that
    /// belongs to whatever asked for the login: a redirect URI and a response
    /// mode are the protocol's, and holding them here would mean rewriting this
    /// crate for the next protocol.
    Admitted(Box<Admission>),
    /// The login ended without establishing anybody, and the client is owed an
    /// answer. Named rather than rendered, for the same reason.
    SentBack {
        error: &'static str,
        /// The login as it stood, for the same reason an admission carries
        /// one: the row is gone, and where the client hears this is written
        /// in its notes.
        login: Box<AuthSession>,
    },
    /// The credentials were wrong.
    Refused,
    /// Too many wrong ones, until this instant.
    LockedOut { until: i64 },
}

/// What a finished login established, for the protocol to act on.
#[derive(Debug, Clone)]
pub struct Admission {
    /// The login as it stood, handed back because the row is now gone and what
    /// the request asked for is written in its notes.
    pub login: AuthSession,
    pub session_id: String,
    pub user_id: String,
    /// What a relying party's iframe compares this login against, §4.2.
    pub browser_state: Option<String>,
    /// The level the flow reached, under this realm's map.
    pub reached: Option<i32>,
    /// When the person authenticated, which is not when a token is minted.
    pub auth_time: i64,
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
    signing: Option<&store::keyring::Signing<'_>>,
    // What the person answered to the consent screen, when they answered.
    consented: Option<bool>,
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
        seen.address.as_deref(),
        now,
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
        Progress::LockedOut { until } => Ok(Step::LockedOut { until }),
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
                Some(crate::login::authenticator::Posting {
                    auth_session_id,
                    realm_name: &realm.name,
                    mail: mail.as_ref(),
                    can_send: sends,
                    now,
                }),
            )
            .await
            {
                Enrolment::Settled => {}
                Enrolment::Refused => return Ok(Step::Refused),
                Enrolment::Asked {
                    named,
                    challenge,
                    sending,
                } => {
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
                        sending,
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
                    error: "login_required",
                    login: Box::new(login.clone()),
                });
            }
            // Asked after the person is established and before anything is
            // minted: a screen shown earlier asks somebody who has not proved
            // who they are, and one shown later asks about something already
            // given away.
            let asking_again = noted(&login.notes, "prompt")
                .is_some_and(|named| named.split_whitespace().any(|held| held == "consent"));
            let client = client_of(transaction, &login.client_id).await?;
            let scope = noted(&login.notes, "scope").unwrap_or_default().to_owned();
            if crate::consent::must_ask(
                transaction,
                &client,
                &subject.user_id,
                &scope,
                asking_again,
            )
            .await
            .map_err(|_| Unanswerable::Unreadable)?
            {
                match consented {
                    // Not answered yet: show what is being asked for.
                    None => {
                        return Ok(Step::Consent {
                            client_id: client.client_id.clone(),
                            client_name: client.name.clone(),
                            scopes: scope.split_whitespace().map(str::to_owned).collect(),
                        });
                    }
                    Some(true) => {
                        crate::consent::keep(
                            transaction,
                            &subject.user_id,
                            &client.client_id,
                            &scope,
                            now,
                        )
                        .await
                        .map_err(|_| Unanswerable::Unreadable)?;
                    }
                    // §3.1.2.6: the person is who they say they are and said
                    // no to this client. That is the client's answer, not a
                    // refused login.
                    Some(false) => {
                        login::finish(transaction, &login.session_id)
                            .await
                            .map_err(|_| Unanswerable::Unreadable)?;
                        return Ok(Step::SentBack {
                            error: "access_denied",
                            login: Box::new(login.clone()),
                        });
                    }
                }
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
            .map(|admitted| Step::Admitted(Box::new(admitted)))
        }
    }
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
    _realm: &models::entities::realm::RealmModel,
    _issuer: String,
    _signing: Option<&store::keyring::Signing<'_>>,
    seen: &crate::provenance::Provenance,
    now: DateTime<Utc>,
) -> Result<Admission, Unanswerable> {
    // The transient identifier becomes the durable one. The code names it as
    // `sid`, and one identifier means a login and the session it opened cannot
    // drift apart.
    let browser_state = crate::session_state::draw_browser_state(provider);
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
            // §4.2: what a relying party's iframe compares this login against.
            browser_state: browser_state.clone(),
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

    // The login in progress is over, here and not in the caller. Leaving it
    // would let the same answer mint a second code for one authorization, and
    // a guarantee split across two crates is one somebody forgets to hold.
    login::finish(transaction, &login.session_id)
        .await
        .map_err(|_| Unanswerable::Unreadable)?;

    Ok(Admission {
        // Handed back rather than left behind: the row is gone, and what the
        // request asked for is written in its notes.
        login: login.clone(),
        session_id: login.session_id.clone(),
        user_id: user_id.to_owned(),
        browser_state,
        reached,
        auth_time: now.timestamp(),
    })
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
