//! Setting up a second factor: a person enrolls their authenticator
//! application, and an administrator can take it away.

use std::net::IpAddr;

use serde_json::json;
use time::Duration;
use uuid::Uuid;

use super::device::DeviceMark;
use super::session::{
    AuthenticationMethod, Session, SessionTicket, proves_second_factor, read_proven_session,
};
use super::steps::password::verify_password;
use super::steps::totp::{accept_code, read_secret_place};
use super::store::{SecurityKey, TotpAuthenticator, TotpUse};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::admin::AdminCaller;
use crate::directory::Person;
use crate::error::{ErrorCode, Failure};
use crate::oidc::discovery::name_issuer;
use crate::ports::crypto::{KeyRefusal, TotpEnrollmentText};
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;
use crate::tenancy::resolve::resolve_realm;
use crate::tenancy::{RealmName, RealmScope};

/// Where a person stands with their authenticator application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentState {
    NotEnrolled,
    /// A secret was shown and no code confirmed it yet.
    Pending,
    Enrolled,
}

struct SignedInPerson {
    realm: RealmName,
    scope: RealmScope,
    work: Box<dyn UnitOfWork>,
    session: Session,
    person_holds_factor: bool,
    person: Person,
}

/// Finds who a ticket proves, in a unit of work that stays open. Setting
/// up a second factor is for a person who is signed in, and for nobody else.
async fn require_signed_in_person(
    app: &App,
    realm: &str,
    ticket: Option<&SessionTicket>,
) -> Result<SignedInPerson, Failure> {
    let required = || Failure::new(ErrorCode::SessionRequired);
    let (realm, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    let ticket = ticket.ok_or_else(required)?;
    let read = read_proven_session(app, work.as_mut(), ticket)
        .await?
        .ok_or_else(required)?;
    let person = work
        .read_person(read.session.person)
        .await?
        .filter(|person| person.enabled)
        .ok_or_else(required)?;
    Ok(SignedInPerson {
        realm,
        scope,
        work,
        session: read.session,
        person_holds_factor: read.person_holds_factor,
        person,
    })
}

/// Tells where the signed-in person stands.
///
/// # Errors
///
/// Returns [`ErrorCode::SessionRequired`] without a live session, or the
/// storage failure.
pub async fn describe_enrollment(
    app: &App,
    realm: &str,
    ticket: Option<&SessionTicket>,
) -> Result<EnrollmentState, Failure> {
    let mut found = require_signed_in_person(app, realm, ticket).await?;
    Ok(match found.work.read_totp(found.person.id).await? {
        None => EnrollmentState::NotEnrolled,
        Some(known) if known.confirmed_at.is_none() => EnrollmentState::Pending,
        Some(_) => EnrollmentState::Enrolled,
    })
}

/// Makes a secret for the signed-in person and returns what their
/// application enrolls it from. The secret is shown this once. It serves
/// for nothing until a code confirms it.
///
/// # Errors
///
/// Returns [`ErrorCode::SessionRequired`] without a live session,
/// [`ErrorCode::AuthenticatorAlreadyEnrolled`] when a confirmed
/// authenticator exists, or the storage failure.
pub async fn begin_totp_enrollment(
    app: &App,
    realm: &str,
    ticket: Option<&SessionTicket>,
) -> Result<TotpEnrollmentText, Failure> {
    let unavailable = |detail: &str| Failure::with_detail(ErrorCode::CryptoUnavailable, detail);
    let mut found = require_signed_in_person(app, realm, ticket).await?;
    refuse_unproven_session(&found.session, found.person_holds_factor)?;
    let secret = app
        .one_time_codes
        .make_totp_secret()
        .map_err(|_| unavailable("a one-time secret cannot be made"))?;
    let (data_key, place) = read_secret_place(found.work.as_mut(), found.person.id).await?;
    let sealed_secret = app
        .sealer
        .seal(&data_key, &place, &secret)
        .map_err(|_| unavailable("a one-time secret cannot be sealed"))?;
    let pending = TotpAuthenticator {
        person: found.person.id,
        sealed_secret,
        confirmed_at: None,
        last_step: None,
        created_at: app.now(),
    };
    if !found.work.write_pending_totp(&pending).await? {
        return Err(Failure::new(ErrorCode::AuthenticatorAlreadyEnrolled));
    }
    found.work.commit().await?;
    let issuer = name_issuer(&app.settings, &found.realm);
    app.one_time_codes
        .write_totp_enrollment(&issuer, &found.person.username, &secret)
        .map_err(|_| unavailable("a one-time secret cannot be written"))
}

/// Confirms the authenticator of the signed-in person. They prove again who
/// they are, with their password, and that their application holds the
/// secret, with one of its codes: a session someone else got hold of sets
/// up nothing. A browser the realm keeps for the person is counted apart,
/// as at sign-in: guesses on the name from elsewhere do not keep them from
/// setting up a factor. The application starts with no code counted
/// against the person: it is not born suspended.
///
/// # Errors
///
/// Returns [`ErrorCode::SessionRequired`] without a live session,
/// [`ErrorCode::SignInFailed`] for a wrong password, [`ErrorCode::CodeRejected`]
/// for a wrong code or when no secret waits for one,
/// [`ErrorCode::AuthenticatorAlreadyEnrolled`] when it is confirmed already,
/// or the storage failure.
pub async fn confirm_totp_enrollment(
    app: &App,
    realm: &str,
    ticket: Option<&SessionTicket>,
    password: Secret,
    code: &str,
    caller: Option<IpAddr>,
    known_browsers: &[DeviceMark],
) -> Result<(), Failure> {
    let found = require_signed_in_person(app, realm, ticket).await?;
    let (scope, session, person) = (found.scope, found.session, found.person);
    // No transaction is held while the password is hashed.
    drop(found.work);
    let proven = verify_password(
        app,
        scope,
        &person.username,
        password,
        caller,
        known_browsers,
    )
    .await?;
    if proven.person.id != person.id {
        return Err(Failure::new(ErrorCode::SignInFailed));
    }

    let mut work = app.storage.begin(scope).await?;
    let pending = work
        .read_totp(person.id)
        .await?
        .ok_or(Failure::new(ErrorCode::CodeRejected))?;
    if pending.confirmed_at.is_some() {
        return Err(Failure::new(ErrorCode::AuthenticatorAlreadyEnrolled));
    }
    require_factor_proof(work.as_mut(), person.id, &session).await?;
    let confirmation = TotpUse::Confirmation;
    if !accept_code(
        app,
        work.as_mut(),
        person.id,
        &pending.sealed_secret,
        code,
        confirmation,
    )
    .await?
    {
        return Err(Failure::new(ErrorCode::CodeRejected));
    }
    work.clear_code_attempts(person.id).await?;
    let closed =
        close_sessions_without_factor(app, work.as_mut(), person.id, Some(session.id)).await?;
    let enrolled = json!({
        "kind": "totp",
        "person_id": person.id.to_string(),
        "session_id": session.id.to_string(),
        "ended_session_ids": closed.name_sessions(),
        "refresh_tokens_revoked": closed.refresh_tokens,
        "sessions_ended": closed.sessions.len(),
    });
    record_event(
        app,
        work.as_mut(),
        EventKind::AuthenticatorEnrolled,
        enrolled,
    )
    .await?;
    work.commit().await?;
    Ok(())
}

/// Takes the authenticator of a person away, on behalf of an administrator:
/// what a person who lost their device asks for.
///
/// # Errors
///
/// Returns [`ErrorCode::AuthenticatorNotFound`] when the person has none, or
/// the storage failure.
pub async fn remove_totp(app: &App, caller: &AdminCaller, person: Uuid) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    if !work.delete_totp(person).await? {
        return Err(Failure::new(ErrorCode::AuthenticatorNotFound));
    }
    work.clear_code_attempts(person).await?;
    let removed = json!({
        "actor": { "client_id": caller.client.client_id },
        "kind": "totp",
        "person_id": person.to_string(),
    });
    record_event(app, work.as_mut(), EventKind::AuthenticatorRemoved, removed).await?;
    work.commit().await?;
    Ok(())
}

/// How long a started enrollment of a key waits for the key to answer.
const KEY_ENROLLMENT_LIFETIME: Duration = Duration::minutes(5);
/// How many keys a person may hold: enough for every device they own.
const MAX_SECURITY_KEYS: usize = 10;

/// Tells how many security keys the signed-in person holds.
///
/// # Errors
///
/// Returns [`ErrorCode::SessionRequired`] without a live session, or the
/// storage failure.
pub async fn count_security_keys(
    app: &App,
    realm: &str,
    ticket: Option<&SessionTicket>,
) -> Result<usize, Failure> {
    let mut found = require_signed_in_person(app, realm, ticket).await?;
    Ok(found.work.list_security_keys(found.person.id).await?.len())
}

/// Starts the enrollment of a security key for the signed-in person, who
/// proves again who they are with their password: a session someone else
/// got hold of enrolls nothing, and a browser the realm keeps for them is
/// counted apart, as at sign-in. Returns what the page hands to the browser.
/// Where keys are not served, it is refused before the password is hashed.
///
/// # Errors
///
/// Returns [`ErrorCode::SessionRequired`] without a live session,
/// [`ErrorCode::SecurityKeysNotServed`] where keys are not served,
/// [`ErrorCode::SignInFailed`] for a wrong password,
/// [`ErrorCode::SecondFactorProofRequired`] from a session the password
/// alone opened for a person who holds a factor, [`ErrorCode::KeyRejected`]
/// when the person holds as many keys as one may, or the storage failure.
pub async fn begin_key_enrollment(
    app: &App,
    realm: &str,
    ticket: Option<&SessionTicket>,
    password: Secret,
    caller: Option<IpAddr>,
    known_browsers: &[DeviceMark],
) -> Result<serde_json::Value, Failure> {
    let found = require_signed_in_person(app, realm, ticket).await?;
    if !app.security_keys.are_served() {
        return Err(Failure::new(ErrorCode::SecurityKeysNotServed));
    }
    let (scope, session, person) = (found.scope, found.session, found.person);
    // No transaction is held while the password is hashed.
    drop(found.work);
    let proven = verify_password(
        app,
        scope,
        &person.username,
        password,
        caller,
        known_browsers,
    )
    .await?;
    if proven.person.id != person.id {
        return Err(Failure::new(ErrorCode::SignInFailed));
    }

    let mut work = app.storage.begin(scope).await?;
    require_factor_proof(work.as_mut(), person.id, &session).await?;
    let held: Vec<Vec<u8>> = work
        .list_security_keys(person.id)
        .await?
        .into_iter()
        .map(|key| key.record)
        .collect();
    if held.len() >= MAX_SECURITY_KEYS {
        return Err(Failure::new(ErrorCode::KeyRejected));
    }
    let ceremony = app
        .security_keys
        .start_enrollment(person.id, &person.username, &held)
        .map_err(|_| {
            Failure::with_detail(
                ErrorCode::CryptoUnavailable,
                "the enrollment of a security key cannot be started",
            )
        })?;
    work.write_key_enrollment(
        person.id,
        &ceremony.state,
        app.now() + KEY_ENROLLMENT_LIFETIME,
    )
    .await?;
    work.commit().await?;
    Ok(ceremony.options)
}

/// Finishes the enrollment the signed-in person started, with what their
/// browser handed back. What was started serves once: a refused answer
/// ends it.
///
/// # Errors
///
/// Returns [`ErrorCode::SessionRequired`] without a live session,
/// [`ErrorCode::KeyRejected`] when nothing was started, when it expired, when
/// the answer proves no key, or when the key is enrolled already,
/// [`ErrorCode::SecondFactorProofRequired`] when a factor was set up since
/// it began, or the storage failure.
pub async fn finish_key_enrollment(
    app: &App,
    realm: &str,
    ticket: Option<&SessionTicket>,
    answer: &serde_json::Value,
) -> Result<(), Failure> {
    let rejected = || Failure::new(ErrorCode::KeyRejected);
    let mut found = require_signed_in_person(app, realm, ticket).await?;
    let (scope, session, person) = (found.scope, found.session, found.person);
    let state = found.work.take_key_enrollment(person.id, app.now()).await?;
    // Committed before the answer is judged: whatever it is worth, the
    // challenge is spent.
    found.work.commit().await?;
    let state = state.ok_or_else(rejected)?;
    let enrolled = match app.security_keys.finish_enrollment(&state, answer) {
        Ok(enrolled) => enrolled,
        Err(KeyRefusal::Refused | KeyRefusal::CopySuspected) => return Err(rejected()),
        Err(KeyRefusal::Failed) => {
            return Err(Failure::with_detail(
                ErrorCode::CryptoUnavailable,
                "the enrollment of a security key cannot be finished",
            ));
        }
    };

    let mut work = app.storage.begin(scope).await?;
    // Asked again: a factor may have been set up since the enrollment began.
    require_factor_proof(work.as_mut(), person.id, &session).await?;
    let key = SecurityKey {
        credential_id: enrolled.credential_id,
        person: person.id,
        record: enrolled.record,
        created_at: app.now(),
        last_used_at: None,
    };
    if !work.insert_security_key(&key).await? {
        return Err(rejected());
    }
    let closed =
        close_sessions_without_factor(app, work.as_mut(), person.id, Some(session.id)).await?;
    let told = json!({
        "kind": "security_key",
        "person_id": person.id.to_string(),
        "ended_session_ids": closed.name_sessions(),
        "refresh_tokens_revoked": closed.refresh_tokens,
        "session_id": session.id.to_string(),
        "sessions_ended": closed.sessions.len(),
    });
    record_event(app, work.as_mut(), EventKind::AuthenticatorEnrolled, told).await?;
    work.commit().await?;
    Ok(())
}

/// Takes every security key of a person away, on behalf of an administrator.
///
/// # Errors
///
/// Returns [`ErrorCode::SecurityKeyNotFound`] when the person holds none, or
/// the storage failure.
pub async fn remove_security_keys(
    app: &App,
    caller: &AdminCaller,
    person: Uuid,
) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    let removed = work.delete_security_keys(person).await?;
    if removed == 0 {
        return Err(Failure::new(ErrorCode::SecurityKeyNotFound));
    }
    let told = json!({
        "actor": { "client_id": caller.client.client_id },
        "kind": "security_key",
        "keys": removed,
        "person_id": person.to_string(),
    });
    record_event(app, work.as_mut(), EventKind::AuthenticatorRemoved, told).await?;
    work.commit().await?;
    Ok(())
}

/// Refuses to set up a factor from a session the password alone opened, for
/// a person who holds one already: whoever got hold of that session would
/// add a factor of their own to the account.
fn refuse_unproven_session(session: &Session, person_holds_factor: bool) -> Result<(), Failure> {
    if !proves_second_factor(session) && person_holds_factor {
        return Err(Failure::new(ErrorCode::SecondFactorProofRequired));
    }
    Ok(())
}

/// As [`refuse_unproven_session`], with what the person holds read again.
async fn require_factor_proof(
    work: &mut dyn UnitOfWork,
    person: Uuid,
    session: &Session,
) -> Result<(), Failure> {
    refuse_unproven_session(session, work.holds_second_factor(person).await?)
}

/// What the setting up of a factor ended, as its event tells it: the chain
/// names each session, since nothing else keeps when it ended.
struct ClosedSessions {
    sessions: Vec<Uuid>,
    refresh_tokens: u64,
}

impl ClosedSessions {
    /// The identifiers of the ended sessions, as the event writes them.
    fn name_sessions(&self) -> Vec<String> {
        self.sessions.iter().map(ToString::to_string).collect()
    }
}

/// Ends the sessions of a person the password alone opened, but `kept`,
/// with their refresh tokens: once a factor is set up, the password alone
/// would not open them. An offline grant the password alone proved ends too,
/// with its session. Two statements, whatever their number.
async fn close_sessions_without_factor(
    app: &App,
    work: &mut dyn UnitOfWork,
    person: Uuid,
    kept: Option<Uuid>,
) -> Result<ClosedSessions, Failure> {
    let mut ended = work
        .end_sessions_proven_only_by(person, &[AuthenticationMethod::Password], kept)
        .await?;
    ended.sort_unstable();
    let refresh_tokens = if ended.is_empty() {
        0
    } else {
        work.revoke_refresh_tokens_of_sessions(&ended, app.now())
            .await?
    };
    Ok(ClosedSessions {
        sessions: ended,
        refresh_tokens,
    })
}

/// Lets a person whose codes were suspended type them again, on behalf of an
/// administrator who checked it is them: their device is still theirs, and
/// someone else got the codes wrong.
///
/// # Errors
///
/// Returns [`ErrorCode::PersonNotFound`] or the storage failure.
pub async fn resume_codes(app: &App, caller: &AdminCaller, person: Uuid) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    work.read_person(person)
        .await?
        .ok_or(Failure::new(ErrorCode::PersonNotFound))?;
    work.clear_code_attempts(person).await?;
    let resumed = json!({
        "actor": { "client_id": caller.client.client_id },
        "person_id": person.to_string(),
    });
    record_event(app, work.as_mut(), EventKind::CodesResumed, resumed).await?;
    work.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::{
        EnrollmentState, begin_key_enrollment, begin_totp_enrollment, confirm_totp_enrollment,
        count_security_keys, describe_enrollment, finish_key_enrollment, remove_security_keys,
        remove_totp,
    };
    use crate::authz::capability::Capability;
    use crate::error::ErrorCode;
    use crate::login::session::SessionTicket;
    use crate::oidc::scenario::{PASSWORD, Scenario};
    use crate::secret::Secret;
    use crate::testkit::crypto::TrustingKeys;
    use crate::testkit::drive::complete;

    fn confirm(
        scenario: &Scenario,
        ticket: &SessionTicket,
        password: &str,
        code: &str,
    ) -> Result<(), ErrorCode> {
        complete(confirm_totp_enrollment(
            &scenario.app,
            "acme",
            Some(ticket),
            Secret::new(password.as_bytes().to_vec()),
            code,
            None,
            &[],
        ))
        .map_err(|failure| failure.code)
    }

    fn describe(scenario: &Scenario, ticket: &SessionTicket) -> EnrollmentState {
        complete(describe_enrollment(&scenario.app, "acme", Some(ticket))).expect("a state")
    }

    #[test]
    fn a_signed_in_person_enrolls_with_their_password_and_a_first_code() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        assert_eq!(describe(&scenario, &ticket), EnrollmentState::NotEnrolled);

        let offered = complete(begin_totp_enrollment(&scenario.app, "acme", Some(&ticket)))
            .expect("a secret to enroll");
        assert!(
            offered
                .uri
                .starts_with("otpauth://totp/https://id.example.test/realms/acme:ada?secret="),
            "{}",
            offered.uri
        );
        assert_eq!(describe(&scenario, &ticket), EnrollmentState::Pending);
        let code = scenario.read_code_now(&offered.typed_secret);

        assert_eq!(
            confirm(&scenario, &ticket, "not the password", &code),
            Err(ErrorCode::SignInFailed),
            "a session alone sets up nothing: the password is asked again"
        );
        assert_eq!(
            confirm(&scenario, &ticket, PASSWORD, "000000"),
            Err(ErrorCode::CodeRejected)
        );
        assert_eq!(describe(&scenario, &ticket), EnrollmentState::Pending);
        assert_eq!(confirm(&scenario, &ticket, PASSWORD, &code), Ok(()));

        assert_eq!(describe(&scenario, &ticket), EnrollmentState::Enrolled);
        assert_eq!(
            scenario.read_event_kinds().last().map(String::as_str),
            Some("authenticator.enrolled")
        );
        let again = complete(begin_totp_enrollment(&scenario.app, "acme", Some(&ticket)));
        assert_eq!(
            again.map(|_| ()).map_err(|failure| failure.code),
            Err(ErrorCode::SecondFactorProofRequired),
            "the password alone opened this session"
        );
        scenario.clock.advance(Duration::from_secs(30));
        let proved = scenario.sign_in_with_code(&offered.typed_secret);
        let again = complete(begin_totp_enrollment(&scenario.app, "acme", Some(&proved)));
        assert_eq!(
            again.map(|_| ()).map_err(|failure| failure.code),
            Err(ErrorCode::AuthenticatorAlreadyEnrolled),
            "an authenticator that was confirmed is not replaced from a session"
        );
    }

    #[test]
    fn a_browser_the_person_signed_in_from_sets_up_a_factor_through_a_locked_name() {
        use crate::login::flow::sign_in_with_password;

        let scenario = Scenario::start();
        let attempt = |password: &str| {
            complete(sign_in_with_password(
                &scenario.app,
                scenario.scope,
                "ada",
                Secret::new(password.as_bytes().to_vec()),
                None,
                &[],
            ))
        };
        let signed_in = attempt(PASSWORD)
            .expect("a right password")
            .into_signed_in()
            .expect("no factor yet");
        for _ in 0..5 {
            assert!(attempt("not the password").is_err());
        }
        let offered = complete(begin_totp_enrollment(
            &scenario.app,
            "acme",
            Some(&signed_in.ticket),
        ))
        .expect("a secret to enroll");
        let code = scenario.read_code_now(&offered.typed_secret);

        assert_eq!(
            confirm(&scenario, &signed_in.ticket, PASSWORD, &code),
            Err(ErrorCode::SignInFailed),
            "from elsewhere the name is locked"
        );
        let through_the_mark = complete(confirm_totp_enrollment(
            &scenario.app,
            "acme",
            Some(&signed_in.ticket),
            Secret::new(PASSWORD.as_bytes().to_vec()),
            &code,
            None,
            std::slice::from_ref(&signed_in.device_mark),
        ));
        assert_eq!(through_the_mark.map_err(|failure| failure.code), Ok(()));
    }

    #[test]
    fn the_sessions_the_password_alone_opened_end_when_a_factor_is_set_up() {
        let scenario = Scenario::start();
        let other = scenario.sign_in("openid");
        let owner = scenario.sign_in("openid").ticket;

        let secret = scenario.enroll_authenticator(&owner);

        assert_eq!(
            complete(describe_enrollment(
                &scenario.app,
                "acme",
                Some(&other.ticket)
            ))
            .map_err(|failure| failure.code),
            Err(ErrorCode::SessionRequired),
            "the other session ended when the factor was set up"
        );
        let refresh_token = other.tokens.refresh_token.expect("a refresh token");
        assert!(
            scenario.refresh(&refresh_token).is_err(),
            "a refresh token of the ended session gives nothing"
        );
        assert_eq!(
            describe(&scenario, &owner),
            EnrollmentState::Enrolled,
            "the session that set it up is kept"
        );
        let enrolled = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "authenticator.enrolled")
            .expect("the enrollment");
        assert_eq!(enrolled["payload"]["sessions_ended"], 1);
        assert_eq!(
            enrolled["payload"]["ended_session_ids"],
            serde_json::json!([other.ticket.session.to_string()]),
            "the chain names the session it ended"
        );
        assert_eq!(enrolled["payload"]["refresh_tokens_revoked"], 1);
        let proved = scenario.sign_in_with_code(&secret);
        assert_eq!(describe(&scenario, &proved), EnrollmentState::Enrolled);
    }

    #[test]
    fn a_session_the_password_alone_opened_answers_for_nothing_once_a_factor_is_set_up() {
        use crate::oidc::authorize::{Authorization, AuthorizationParameters, begin_authorization};

        let scenario = Scenario::start();
        // The session that sets the factor up is kept, as one a sign-in that
        // ran beside the setting up would have opened: neither proved it.
        let owner = scenario.sign_in("openid");
        scenario.enroll_authenticator(&owner.ticket);

        let refresh_token = owner.tokens.refresh_token.expect("a refresh token");
        assert!(
            scenario.refresh(&refresh_token).is_err(),
            "its refresh tokens give nothing"
        );
        let asked = AuthorizationParameters {
            response_type: Some("code"),
            client_id: Some("webapp"),
            redirect_uri: Some(crate::oidc::scenario::CALLBACK),
            scope: Some("openid"),
            state: None,
            nonce: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            code_challenge_method: Some("S256"),
            prompt: None,
            max_age: None,
            id_token_hint: None,
            caller: None,
            known_browsers: &[],
        };
        let begun = complete(begin_authorization(
            &scenario.app,
            "acme",
            asked,
            Some(&owner.ticket),
        ))
        .expect("an answer");
        assert!(
            matches!(begun, Authorization::SignInRequired { .. }),
            "it gives no code: the person signs in with the factor"
        );
    }

    #[test]
    fn a_secret_shown_again_replaces_the_one_nobody_confirmed() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        let first = complete(begin_totp_enrollment(&scenario.app, "acme", Some(&ticket)))
            .expect("a secret");
        let second = complete(begin_totp_enrollment(&scenario.app, "acme", Some(&ticket)))
            .expect("another secret");
        assert_ne!(first.typed_secret, second.typed_secret);

        assert_eq!(
            confirm(
                &scenario,
                &ticket,
                PASSWORD,
                &scenario.read_code_now(&first.typed_secret)
            ),
            Err(ErrorCode::CodeRejected),
            "the first secret is gone"
        );
        assert_eq!(
            confirm(
                &scenario,
                &ticket,
                PASSWORD,
                &scenario.read_code_now(&second.typed_secret)
            ),
            Ok(())
        );
    }

    #[test]
    fn nobody_enrolls_without_a_live_session() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let required = Err(ErrorCode::SessionRequired);

        let anonymous = complete(begin_totp_enrollment(&scenario.app, "acme", None));
        assert_eq!(
            anonymous.map(|_| ()).map_err(|failure| failure.code),
            required
        );

        scenario.clock.advance(Duration::from_hours(12));
        let expired = complete(begin_totp_enrollment(
            &scenario.app,
            "acme",
            Some(&signed_in.ticket),
        ));
        assert_eq!(
            expired.map(|_| ()).map_err(|failure| failure.code),
            required
        );
        assert_eq!(
            confirm(&scenario, &signed_in.ticket, PASSWORD, "000000"),
            Err(ErrorCode::SessionRequired)
        );
    }

    #[test]
    fn an_administrator_takes_an_authenticator_away_and_the_chain_says_who() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        scenario.enroll_authenticator(&ticket);
        let caller = scenario.name_operator(&[Capability::UserWrite]);
        let person = scenario.find_ada();

        assert_eq!(
            complete(remove_totp(&scenario.app, &caller, person)).map_err(|failure| failure.code),
            Ok(())
        );

        assert_eq!(describe(&scenario, &ticket), EnrollmentState::NotEnrolled);
        let removed = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "authenticator.removed")
            .expect("the removal");
        assert_eq!(removed["payload"]["actor"]["client_id"], "operator");
        assert_eq!(
            complete(remove_totp(&scenario.app, &caller, person)).map_err(|failure| failure.code),
            Err(ErrorCode::AuthenticatorNotFound)
        );
    }

    fn begin_key(
        scenario: &Scenario,
        ticket: &SessionTicket,
        password: &str,
    ) -> Result<Value, ErrorCode> {
        complete(begin_key_enrollment(
            &scenario.app,
            "acme",
            Some(ticket),
            Secret::new(password.as_bytes().to_vec()),
            None,
            &[],
        ))
        .map_err(|failure| failure.code)
    }

    fn finish_key(
        scenario: &Scenario,
        ticket: &SessionTicket,
        answer: &Value,
    ) -> Result<(), ErrorCode> {
        complete(finish_key_enrollment(
            &scenario.app,
            "acme",
            Some(ticket),
            answer,
        ))
        .map_err(|failure| failure.code)
    }

    fn count_keys(scenario: &Scenario, ticket: &SessionTicket) -> usize {
        complete(count_security_keys(&scenario.app, "acme", Some(ticket))).expect("a count")
    }

    #[test]
    fn a_signed_in_person_enrolls_a_key_with_their_password_and_the_answer_of_the_key() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        assert_eq!(count_keys(&scenario, &ticket), 0);
        assert_eq!(
            begin_key(&scenario, &ticket, "not the password"),
            Err(ErrorCode::SignInFailed),
            "a session alone enrolls nothing: the password is asked again"
        );
        let unasked = TrustingKeys::answer_enrollment(&json!({ "challenge": "challenge-0" }), "k1");
        assert_eq!(
            finish_key(&scenario, &ticket, &unasked),
            Err(ErrorCode::KeyRejected),
            "nothing was started"
        );

        let options = begin_key(&scenario, &ticket, PASSWORD).expect("a started enrollment");
        assert_eq!(options["user"], "ada");
        let answer = TrustingKeys::answer_enrollment(&options, "k1");
        assert_eq!(finish_key(&scenario, &ticket, &answer), Ok(()));

        assert_eq!(count_keys(&scenario, &ticket), 1);
        let enrolled = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .pop()
            .expect("an event");
        assert_eq!(enrolled["kind"], "authenticator.enrolled");
        assert_eq!(enrolled["payload"]["kind"], "security_key");
        assert_eq!(
            finish_key(&scenario, &ticket, &answer),
            Err(ErrorCode::KeyRejected),
            "what was started served once"
        );
    }

    #[test]
    fn an_answer_that_proves_no_key_ends_what_was_started() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        let options = begin_key(&scenario, &ticket, PASSWORD).expect("a started enrollment");

        let of_another = TrustingKeys::answer_enrollment(&json!({ "challenge": "another" }), "k1");
        assert_eq!(
            finish_key(&scenario, &ticket, &of_another),
            Err(ErrorCode::KeyRejected)
        );
        assert_eq!(
            finish_key(
                &scenario,
                &ticket,
                &TrustingKeys::answer_enrollment(&options, "k1")
            ),
            Err(ErrorCode::KeyRejected),
            "the refused answer spent the challenge"
        );
        assert_eq!(count_keys(&scenario, &ticket), 0);
    }

    #[test]
    fn a_later_start_replaces_what_was_started_and_what_was_started_waits_five_minutes() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        let first = begin_key(&scenario, &ticket, PASSWORD).expect("a started enrollment");
        let second = begin_key(&scenario, &ticket, PASSWORD).expect("a later start");
        assert_ne!(first["challenge"], second["challenge"]);
        assert_eq!(
            finish_key(
                &scenario,
                &ticket,
                &TrustingKeys::answer_enrollment(&first, "k1")
            ),
            Err(ErrorCode::KeyRejected),
            "the first challenge is gone"
        );

        let late = begin_key(&scenario, &ticket, PASSWORD).expect("a started enrollment");
        scenario.clock.advance(Duration::from_mins(5));
        assert_eq!(
            finish_key(
                &scenario,
                &ticket,
                &TrustingKeys::answer_enrollment(&late, "k1")
            ),
            Err(ErrorCode::KeyRejected)
        );

        let in_time = begin_key(&scenario, &ticket, PASSWORD).expect("a started enrollment");
        scenario.clock.advance(Duration::from_mins(4));
        assert_eq!(
            finish_key(
                &scenario,
                &ticket,
                &TrustingKeys::answer_enrollment(&in_time, "k1")
            ),
            Ok(())
        );
    }

    #[test]
    fn a_key_is_enrolled_once_and_a_person_holds_ten_at_most() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        scenario.enroll_security_key(&ticket, "k0");
        // From now on a session proves the key, or it adds none beside it.
        let ticket = scenario.sign_in_with_key("k0", 1);

        let options = begin_key(&scenario, &ticket, PASSWORD).expect("a started enrollment");
        assert_eq!(
            options["excluded"],
            json!(["k0"]),
            "the browser is told which keys are held already"
        );
        assert_eq!(
            finish_key(
                &scenario,
                &ticket,
                &TrustingKeys::answer_enrollment(&options, "k0")
            ),
            Err(ErrorCode::KeyRejected)
        );

        for name in 1..10 {
            scenario.enroll_security_key(&ticket, &format!("k{name}"));
        }
        assert_eq!(count_keys(&scenario, &ticket), 10);
        assert_eq!(
            begin_key(&scenario, &ticket, PASSWORD),
            Err(ErrorCode::KeyRejected)
        );
    }

    #[test]
    fn a_key_set_up_ends_the_sessions_the_password_alone_opened_and_asks_itself_next() {
        let scenario = Scenario::start();
        let other = scenario.sign_in("openid").ticket;
        let owner = scenario.sign_in("openid").ticket;

        scenario.enroll_security_key(&owner, "k1");

        assert_eq!(
            begin_key(&scenario, &other, PASSWORD),
            Err(ErrorCode::SessionRequired),
            "the other session ended when the key was set up"
        );
        assert_eq!(
            begin_key(&scenario, &owner, PASSWORD),
            Err(ErrorCode::SecondFactorProofRequired),
            "the session that set it up did not prove it"
        );
        let proved = scenario.sign_in_with_key("k1", 1);
        assert!(begin_key(&scenario, &proved, PASSWORD).is_ok());
    }

    #[test]
    fn a_session_the_password_alone_opened_adds_no_key_beside_an_authenticator() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        let secret = scenario.enroll_authenticator(&ticket);

        assert_eq!(
            begin_key(&scenario, &ticket, PASSWORD),
            Err(ErrorCode::SecondFactorProofRequired)
        );
        let proved = scenario.sign_in_with_code(&secret);
        let options = begin_key(&scenario, &proved, PASSWORD).expect("a started enrollment");
        assert_eq!(
            finish_key(
                &scenario,
                &proved,
                &TrustingKeys::answer_enrollment(&options, "k1")
            ),
            Ok(())
        );
    }

    #[test]
    fn an_administrator_takes_every_key_away_and_the_chain_says_who_and_how_many() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        scenario.enroll_security_key(&ticket, "k1");
        let ticket = scenario.sign_in_with_key("k1", 1);
        scenario.enroll_security_key(&ticket, "k2");
        let caller = scenario.name_operator(&[Capability::UserWrite]);
        let person = scenario.find_ada();
        let remove = || {
            complete(remove_security_keys(&scenario.app, &caller, person))
                .map_err(|failure| failure.code)
        };

        assert_eq!(remove(), Ok(()));

        assert_eq!(count_keys(&scenario, &ticket), 0);
        let removed = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .pop()
            .expect("an event");
        assert_eq!(removed["kind"], "authenticator.removed");
        assert_eq!(removed["payload"]["actor"]["client_id"], "operator");
        assert_eq!(removed["payload"]["kind"], "security_key");
        assert_eq!(removed["payload"]["keys"], 2);
        assert_eq!(remove(), Err(ErrorCode::SecurityKeyNotFound));
    }

    #[test]
    fn a_session_the_password_alone_opened_confirms_no_application_once_a_key_is_set_up() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        let offered = complete(begin_totp_enrollment(&scenario.app, "acme", Some(&ticket)))
            .expect("a secret to enroll");

        scenario.enroll_security_key(&ticket, "k1");

        let code = scenario.read_code_now(&offered.typed_secret);
        assert_eq!(
            confirm(&scenario, &ticket, PASSWORD, &code),
            Err(ErrorCode::SecondFactorProofRequired),
            "a key was set up since the secret was shown"
        );
        assert_eq!(describe(&scenario, &ticket), EnrollmentState::Pending);
    }

    #[test]
    fn a_session_the_password_alone_opened_finishes_no_key_once_an_application_is_set_up() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        let options = begin_key(&scenario, &ticket, PASSWORD).expect("a started enrollment");

        scenario.enroll_authenticator(&ticket);

        assert_eq!(
            finish_key(
                &scenario,
                &ticket,
                &TrustingKeys::answer_enrollment(&options, "k1")
            ),
            Err(ErrorCode::SecondFactorProofRequired),
            "an application was set up since the key was asked"
        );
        assert_eq!(count_keys(&scenario, &ticket), 0);
    }

    #[test]
    fn where_keys_are_not_served_adding_one_is_refused_before_the_password_is_judged() {
        use std::sync::Arc;

        use crate::testkit::crypto::UnservedKeys;

        let mut scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        scenario.app.security_keys = Arc::new(UnservedKeys);

        assert_eq!(
            begin_key(&scenario, &ticket, "not the password"),
            Err(ErrorCode::SecurityKeysNotServed),
            "a wrong password is not judged: nothing was hashed"
        );
        assert_eq!(
            begin_key(&scenario, &ticket, PASSWORD),
            Err(ErrorCode::SecurityKeysNotServed)
        );
    }

    /// Counts one more code typed by `person`, and answers how many that makes.
    fn count_one_more_code(scenario: &Scenario, person: uuid::Uuid) -> u32 {
        complete(async {
            let mut work = scenario
                .app
                .storage
                .begin(scenario.scope)
                .await
                .expect("a unit of work");
            let counted = work
                .count_code_attempt(person, scenario.app.now())
                .await
                .expect("a count");
            work.commit().await.expect("a commit");
            counted
        })
    }

    fn give_code(scenario: &Scenario, person: uuid::Uuid, code: &str) -> Result<(), ErrorCode> {
        use crate::login::flow::finish_sign_in_with_code;

        complete(finish_sign_in_with_code(
            &scenario.app,
            scenario.scope,
            person,
            code,
            None,
            &[],
        ))
        .map(|_| ())
        .map_err(|failure| failure.code)
    }

    #[test]
    fn an_application_set_up_starts_with_no_code_counted_against_its_person() {
        use crate::login::steps::totp::MAX_CODE_FAILURES;

        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        let person = scenario.find_ada();
        // Left by codes counted before the application was set up.
        for _ in 0..MAX_CODE_FAILURES {
            count_one_more_code(&scenario, person);
        }

        let secret = scenario.enroll_authenticator(&ticket);

        assert_eq!(
            give_code(&scenario, person, &scenario.read_code_now(&secret)),
            Ok(()),
            "the application is not born suspended"
        );
    }

    #[test]
    fn an_administrator_who_takes_an_application_away_forgets_the_codes_typed_for_it() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        scenario.enroll_authenticator(&ticket);
        let person = scenario.find_ada();
        for _ in 0..3 {
            assert_eq!(
                give_code(&scenario, person, "000000"),
                Err(ErrorCode::CodeRejected)
            );
        }
        let caller = scenario.name_operator(&[Capability::UserWrite]);

        complete(remove_totp(&scenario.app, &caller, person)).expect("removed");

        assert_eq!(
            count_one_more_code(&scenario, person),
            1,
            "the three codes went with the application"
        );
    }
}
