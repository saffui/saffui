//! The flow of signing in: what a person owes, and the session that opens
//! once all of it is proven. A step proves one thing and opens nothing.

use std::net::IpAddr;

use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::device::{DeviceMark, MOST_BROWSERS_PER_PERSON, issue_device_mark};
use super::session::{AuthenticationMethod, SessionTicket, open_session};
use super::steps::password::{ProvenPassword, verify_password};
use super::steps::totp::verify_code;
use super::steps::webauthn::{KeyProofStart, start_key_proof, verify_key};
use super::store::KnownBrowser;
use super::throttle::Brake;
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::directory::Person;
use crate::error::{ErrorCode, Failure};
use crate::ports::crypto::KeyCeremony;
use crate::secret::Secret;
use crate::tenancy::RealmScope;

/// A person who just signed in, the ticket of their new session, and the
/// mark their browser keeps from now on.
#[derive(Debug)]
pub struct SignedIn {
    pub person: Person,
    pub session: Uuid,
    pub ticket: SessionTicket,
    pub device_mark: DeviceMark,
}

/// What a person owes after their password. One of the two is enough.
#[derive(Debug)]
pub struct SecondFactor {
    pub person: Person,
    /// They set up an authenticator application: one of its codes will do.
    pub code: bool,
    /// They hold a security key, and keys are served here: its answer to
    /// this ceremony will do.
    pub key: Option<KeyCeremony>,
}

/// Where the password leaves a person.
#[derive(Debug)]
pub enum FirstStep {
    /// The password was all they owed.
    SignedIn(SignedIn),
    /// They set up a second factor and owe it. No session exists yet, and
    /// their browser is given no mark.
    SecondFactorRequired(SecondFactor),
}

impl FirstStep {
    /// The session, when the password was all the person owed.
    #[must_use]
    pub fn into_signed_in(self) -> Option<SignedIn> {
        match self {
            Self::SignedIn(signed_in) => Some(signed_in),
            Self::SecondFactorRequired(_) => None,
        }
    }
}

/// Opens the session of a person who proved all they owe. The browser that
/// proved it is cleared, and kept for the person.
async fn open_session_for(
    app: &App,
    scope: RealmScope,
    person: Person,
    typed: &str,
    brake: &Brake,
    methods: &[AuthenticationMethod],
) -> Result<SignedIn, Failure> {
    let mut work = app.storage.begin(scope).await?;
    brake.forget_browser_failures(work.as_mut()).await?;
    let device_mark = issue_device_mark(app, scope, typed, brake.browser())?;
    let browser = KnownBrowser {
        device: device_mark.device,
        person: person.id,
        expires_at: OffsetDateTime::from_unix_timestamp(device_mark.expires_at)
            .map_err(|_| Failure::new(ErrorCode::Internal))?,
    };
    work.remember_browser(&browser, MOST_BROWSERS_PER_PERSON)
        .await?;
    let (session, ticket) = open_session(app, work.as_mut(), person.id, methods).await?;
    let names: Vec<&str> = methods.iter().map(|method| method.name()).collect();
    let opened = json!({
        "methods": names,
        "person_id": person.id.to_string(),
        "session_id": session.id.to_string(),
    });
    record_event(app, work.as_mut(), EventKind::SessionOpened, opened).await?;
    work.commit().await?;
    Ok(SignedIn {
        person,
        session: session.id,
        ticket,
        device_mark,
    })
}

/// Takes the name and the password of a person. Signs them in when that is
/// all they owe, and says so when they owe a second factor: a code, or the
/// answer of a key to the challenge started here. Where keys are not served,
/// a person who also set up an application owes its code.
///
/// # Errors
///
/// As [`verify_password`], [`ErrorCode::SecurityKeysNotServed`] after the
/// right password of a person whose only factor is a key where keys are not
/// served, or the storage failure.
pub async fn sign_in_with_password(
    app: &App,
    scope: RealmScope,
    typed_name: &str,
    password: Secret,
    caller: Option<IpAddr>,
    known_browsers: &[DeviceMark],
) -> Result<FirstStep, Failure> {
    let ProvenPassword {
        person,
        typed,
        brake,
    } = verify_password(app, scope, typed_name, password, caller, known_browsers).await?;
    let mut work = app.storage.begin(scope).await?;
    let code = work
        .read_totp(person.id)
        .await?
        .is_some_and(|authenticator| authenticator.confirmed_at.is_some());
    let key = match start_key_proof(app, work.as_mut(), person.id).await? {
        KeyProofStart::Started(ceremony) => Some(ceremony),
        KeyProofStart::NoKeyHeld => None,
        KeyProofStart::NotServed if code => None,
        KeyProofStart::NotServed => return Err(Failure::new(ErrorCode::SecurityKeysNotServed)),
    };
    drop(work);
    if code || key.is_some() {
        return Ok(FirstStep::SecondFactorRequired(SecondFactor {
            person,
            code,
            key,
        }));
    }
    let methods = [AuthenticationMethod::Password];
    open_session_for(app, scope, person, &typed, &brake, &methods)
        .await
        .map(FirstStep::SignedIn)
}

/// Reads the person who owes a second factor, as long as they still may sign in.
async fn read_person_who_owes(
    app: &App,
    scope: RealmScope,
    person: Uuid,
    refusal: ErrorCode,
) -> Result<Person, Failure> {
    let mut work = app.storage.begin(scope).await?;
    work.read_person(person)
        .await?
        .filter(|person| person.enabled)
        .ok_or(Failure::new(refusal))
}

/// Takes the answer of a security key a person owes after their password,
/// and signs them in.
///
/// # Errors
///
/// Returns [`ErrorCode::KeyRejected`] when the person is gone or disabled
/// since their password, and otherwise as [`verify_key`].
pub async fn finish_sign_in_with_key(
    app: &App,
    scope: RealmScope,
    person: Uuid,
    state: &[u8],
    answer: &serde_json::Value,
    caller: Option<IpAddr>,
    known_browsers: &[DeviceMark],
) -> Result<SignedIn, Failure> {
    let person = read_person_who_owes(app, scope, person, ErrorCode::KeyRejected).await?;
    let brake = verify_key(app, scope, &person, state, answer, caller, known_browsers).await?;
    let typed = person.username.clone();
    let methods = [
        AuthenticationMethod::Password,
        AuthenticationMethod::SecurityKey,
    ];
    open_session_for(app, scope, person, &typed, &brake, &methods).await
}

/// Takes the code a person owes after their password, and signs them in.
///
/// # Errors
///
/// Returns [`ErrorCode::CodeRejected`] when the person is gone or disabled
/// since their password, and otherwise as [`verify_code`].
pub async fn finish_sign_in_with_code(
    app: &App,
    scope: RealmScope,
    person: Uuid,
    code: &str,
    caller: Option<IpAddr>,
    known_browsers: &[DeviceMark],
) -> Result<SignedIn, Failure> {
    let person = read_person_who_owes(app, scope, person, ErrorCode::CodeRejected).await?;
    let brake = verify_code(app, scope, &person, code, caller, known_browsers).await?;
    let typed = person.username.clone();
    let methods = [
        AuthenticationMethod::Password,
        AuthenticationMethod::OneTimeCode,
    ];
    open_session_for(app, scope, person, &typed, &brake, &methods).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use uuid::Uuid;

    use super::{
        FirstStep, SignedIn, finish_sign_in_with_code, finish_sign_in_with_key,
        sign_in_with_password,
    };
    use crate::error::ErrorCode;
    use crate::login::device::DeviceMark;
    use crate::login::session::AuthenticationMethod;
    use crate::oidc::scenario::{PASSWORD, Scenario};
    use crate::ports::crypto::KeyCeremony;
    use crate::secret::Secret;
    use crate::testkit::crypto::{TrustingKeys, UnservedKeys};
    use crate::testkit::drive::complete;

    /// A person with an authenticator, and the secret their application holds.
    fn start_enrolled() -> (Scenario, String) {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        let secret = scenario.enroll_authenticator(&ticket);
        (scenario, secret)
    }

    fn give_password(
        scenario: &Scenario,
        password: &str,
        marks: &[DeviceMark],
    ) -> Result<FirstStep, ErrorCode> {
        complete(sign_in_with_password(
            &scenario.app,
            scenario.scope,
            "ada",
            Secret::new(password.as_bytes().to_vec()),
            None,
            marks,
        ))
        .map_err(|failure| failure.code)
    }

    /// Gives the password of `ada` and returns who owes a code.
    fn owe_a_code(scenario: &Scenario, marks: &[DeviceMark]) -> Uuid {
        match give_password(scenario, PASSWORD, marks).expect("a right password") {
            FirstStep::SecondFactorRequired(owed) => {
                assert!(owed.code && owed.key.is_none());
                owed.person.id
            }
            FirstStep::SignedIn(_) => panic!("a person with an authenticator owes a code"),
        }
    }

    fn give_code(
        scenario: &Scenario,
        person: Uuid,
        code: &str,
        marks: &[DeviceMark],
    ) -> Result<SignedIn, ErrorCode> {
        complete(finish_sign_in_with_code(
            &scenario.app,
            scenario.scope,
            person,
            code,
            None,
            marks,
        ))
        .map_err(|failure| failure.code)
    }

    fn count_sessions_opened(scenario: &Scenario) -> usize {
        scenario
            .read_event_kinds()
            .iter()
            .filter(|kind| *kind == "session.opened")
            .count()
    }

    #[test]
    fn a_person_with_an_authenticator_gets_no_session_from_their_password_alone() {
        let (scenario, secret) = start_enrolled();
        let opened_before = count_sessions_opened(&scenario);

        let person = owe_a_code(&scenario, &[]);

        assert_eq!(count_sessions_opened(&scenario), opened_before);
        let signed_in = give_code(&scenario, person, &scenario.read_code_now(&secret), &[])
            .expect("a right code");
        assert_eq!(count_sessions_opened(&scenario), opened_before + 1);
        let session = complete(async {
            let mut work = scenario
                .app
                .storage
                .begin(scenario.scope)
                .await
                .expect("a unit of work");
            work.read_session(signed_in.session)
                .await
                .expect("a read")
                .expect("the session")
                .session
        });
        assert_eq!(
            session.methods,
            [
                AuthenticationMethod::Password,
                AuthenticationMethod::OneTimeCode
            ]
        );
    }

    #[test]
    fn a_code_serves_once_and_the_code_of_another_minute_does_not_serve() {
        let (scenario, secret) = start_enrolled();
        let person = owe_a_code(&scenario, &[]);
        let code = scenario.read_code_now(&secret);

        assert!(give_code(&scenario, person, &code, &[]).is_ok());
        assert_eq!(
            give_code(&scenario, person, &code, &[]).map(|_| ()),
            Err(ErrorCode::CodeRejected),
            "a code someone read over a shoulder is spent"
        );

        scenario.clock.advance(Duration::from_mins(5));
        assert_eq!(
            give_code(&scenario, person, &code, &[]).map(|_| ()),
            Err(ErrorCode::CodeRejected)
        );
        assert!(give_code(&scenario, person, &scenario.read_code_now(&secret), &[]).is_ok());
    }

    #[test]
    fn guessed_codes_lock_the_name_as_guessed_passwords_do() {
        let (scenario, secret) = start_enrolled();
        let person = owe_a_code(&scenario, &[]);

        for _ in 0..5 {
            assert_eq!(
                give_code(&scenario, person, "000000", &[]).map(|_| ()),
                Err(ErrorCode::CodeRejected)
            );
        }

        assert_eq!(
            give_code(&scenario, person, &scenario.read_code_now(&secret), &[]).map(|_| ()),
            Err(ErrorCode::CodeRejected),
            "the right code comes too late: the name is locked"
        );
        assert_eq!(
            give_password(&scenario, PASSWORD, &[]).map(|_| ()),
            Err(ErrorCode::SignInFailed),
            "the guesses of both steps are counted under one name"
        );
    }

    #[test]
    fn ten_wrong_codes_in_a_row_suspend_the_codes_of_a_person_until_an_administrator_resumes_them()
    {
        use crate::authz::admin::authorize_admin_call;
        use crate::authz::capability::Capability;
        use crate::login::enroll::resume_codes;
        use crate::testkit::fixtures::create_administrator;

        let (scenario, secret) = start_enrolled();
        let person = owe_a_code(&scenario, &[]);
        let next_step = || scenario.clock.advance(Duration::from_secs(30));
        // Each guess from an address of its own: only the person is counted.
        let mut addresses = (1..=u8::MAX).map(|last| std::net::IpAddr::from([192, 0, 2, last]));
        let mut guess = |code: &str| {
            complete(finish_sign_in_with_code(
                &scenario.app,
                scenario.scope,
                person,
                code,
                addresses.next(),
                &[],
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        };

        // A right code forgets the wrong ones before it.
        for _ in 0..9 {
            assert_eq!(guess("000000"), Err(ErrorCode::CodeRejected));
        }
        assert_eq!(guess(&scenario.read_code_now(&secret)), Ok(()));
        next_step();
        for _ in 0..10 {
            assert_eq!(guess("000000"), Err(ErrorCode::CodeRejected));
        }
        assert_eq!(
            guess(&scenario.read_code_now(&secret)),
            Err(ErrorCode::CodeRejected),
            "suspended: even the right code is refused"
        );
        assert_eq!(
            scenario
                .read_event_kinds()
                .iter()
                .filter(|kind| *kind == "authenticator.codes_suspended")
                .count(),
            1
        );

        let token = complete(create_administrator(
            &scenario.app,
            "acme",
            scenario.scope,
            "operator",
            &[Capability::UserWrite],
        ));
        let operator = complete(authorize_admin_call(
            &scenario.app,
            "acme",
            Some(&token),
            Capability::UserWrite,
        ))
        .expect("an administrator");
        complete(resume_codes(&scenario.app, &operator, person)).expect("resumed");
        next_step();
        assert_eq!(guess(&scenario.read_code_now(&secret)), Ok(()));
    }

    #[test]
    fn a_code_is_asked_of_nobody_who_was_disabled_meanwhile() {
        let (scenario, secret) = start_enrolled();
        let person = owe_a_code(&scenario, &[]);
        scenario.storage.disable_person("ada");

        assert_eq!(
            give_code(&scenario, person, &scenario.read_code_now(&secret), &[]).map(|_| ()),
            Err(ErrorCode::CodeRejected)
        );
    }

    #[test]
    fn a_browser_the_person_signed_in_from_passes_a_lock_at_the_code_as_at_the_password() {
        let (scenario, secret) = start_enrolled();
        let person = owe_a_code(&scenario, &[]);
        let mark = give_code(&scenario, person, &scenario.read_code_now(&secret), &[])
            .expect("a right code")
            .device_mark;
        scenario.clock.advance(Duration::from_secs(30));
        for _ in 0..5 {
            assert_eq!(
                give_password(&scenario, "not the password", &[]).map(|_| ()),
                Err(ErrorCode::SignInFailed)
            );
        }

        let marks = std::slice::from_ref(&mark);
        let person = owe_a_code(&scenario, marks);
        assert_eq!(
            give_code(&scenario, person, &scenario.read_code_now(&secret), &[]).map(|_| ()),
            Err(ErrorCode::CodeRejected),
            "from elsewhere the name is locked"
        );
        assert!(
            give_code(&scenario, person, &scenario.read_code_now(&secret), marks).is_ok(),
            "the browser the person signed in from is counted apart"
        );
    }

    /// A person who holds the security key `k1`.
    fn start_with_a_key() -> Scenario {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        scenario.enroll_security_key(&ticket, "k1");
        scenario
    }

    /// Gives the password of `ada` and returns who owes the answer of a key,
    /// and what the key is asked.
    fn owe_a_key(scenario: &Scenario) -> (Uuid, KeyCeremony) {
        match give_password(scenario, PASSWORD, &[]).expect("a right password") {
            FirstStep::SecondFactorRequired(owed) => {
                assert!(!owed.code);
                (owed.person.id, owed.key.expect("a started proof"))
            }
            FirstStep::SignedIn(_) => panic!("a person with a key owes its answer"),
        }
    }

    fn give_key(
        scenario: &Scenario,
        person: Uuid,
        asked: &KeyCeremony,
        counter: u64,
    ) -> Result<SignedIn, ErrorCode> {
        let answer = TrustingKeys::answer_proof(&asked.options, "k1", counter);
        complete(finish_sign_in_with_key(
            &scenario.app,
            scenario.scope,
            person,
            &asked.state,
            &answer,
            None,
            &[],
        ))
        .map_err(|failure| failure.code)
    }

    #[test]
    fn a_person_with_a_key_gets_no_session_from_their_password_alone_and_one_from_its_answer() {
        let scenario = start_with_a_key();
        let opened_before = count_sessions_opened(&scenario);

        let (person, asked) = owe_a_key(&scenario);

        assert_eq!(count_sessions_opened(&scenario), opened_before);
        let signed_in = give_key(&scenario, person, &asked, 1).expect("a right answer");
        let session = complete(async {
            let mut work = scenario
                .app
                .storage
                .begin(scenario.scope)
                .await
                .expect("a unit of work");
            work.read_session(signed_in.session)
                .await
                .expect("a read")
                .expect("the session")
                .session
        });
        assert_eq!(
            session.methods,
            [
                AuthenticationMethod::Password,
                AuthenticationMethod::SecurityKey
            ]
        );
    }

    #[test]
    fn an_answer_whose_counter_does_not_move_forward_is_refused() {
        let scenario = start_with_a_key();
        let (person, asked) = owe_a_key(&scenario);
        assert!(give_key(&scenario, person, &asked, 3).is_ok());

        let (person, asked) = owe_a_key(&scenario);
        assert_eq!(
            give_key(&scenario, person, &asked, 3).map(|_| ()),
            Err(ErrorCode::KeyRejected),
            "a copy of the key answers with a counter that stood still"
        );
        assert_eq!(
            scenario.read_event_kinds().last().map(String::as_str),
            Some("authenticator.key_copy_suspected"),
            "and the chain says so"
        );
        assert_eq!(
            give_key(&scenario, person, &asked, 2).map(|_| ()),
            Err(ErrorCode::KeyRejected)
        );
        assert!(give_key(&scenario, person, &asked, 4).is_ok());
    }

    #[test]
    fn a_key_taken_away_after_the_challenge_was_made_proves_nothing() {
        use crate::authz::admin::authorize_admin_call;
        use crate::authz::capability::Capability;
        use crate::login::enroll::remove_security_keys;
        use crate::testkit::fixtures::create_administrator;

        let scenario = start_with_a_key();
        let (person, asked) = owe_a_key(&scenario);
        let token = complete(create_administrator(
            &scenario.app,
            "acme",
            scenario.scope,
            "operator",
            &[Capability::UserWrite],
        ));
        let operator = complete(authorize_admin_call(
            &scenario.app,
            "acme",
            Some(&token),
            Capability::UserWrite,
        ))
        .expect("an administrator");
        complete(remove_security_keys(&scenario.app, &operator, person)).expect("removed");

        assert_eq!(
            give_key(&scenario, person, &asked, 1).map(|_| ()),
            Err(ErrorCode::KeyRejected)
        );
    }

    #[test]
    fn refused_answers_lock_the_name_as_wrong_codes_do() {
        let scenario = start_with_a_key();
        let (person, asked) = owe_a_key(&scenario);
        let of_another = TrustingKeys::answer_proof(&asked.options, "not-held", 1);
        for _ in 0..5 {
            let refused = complete(finish_sign_in_with_key(
                &scenario.app,
                scenario.scope,
                person,
                &asked.state,
                &of_another,
                None,
                &[],
            ));
            assert_eq!(
                refused.map(|_| ()).map_err(|failure| failure.code),
                Err(ErrorCode::KeyRejected)
            );
        }

        assert_eq!(
            give_key(&scenario, person, &asked, 1).map(|_| ()),
            Err(ErrorCode::KeyRejected),
            "the right answer comes too late: the name is locked"
        );
    }

    #[test]
    fn a_person_with_a_code_and_a_key_is_offered_both_and_let_in_by_either() {
        let (scenario, secret) = start_enrolled();
        let proved = scenario.sign_in_with_code(&secret);
        scenario.enroll_security_key(&proved, "k1");
        scenario.clock.advance(Duration::from_secs(30));

        let FirstStep::SecondFactorRequired(owed) =
            give_password(&scenario, PASSWORD, &[]).expect("a right password")
        else {
            panic!("a person with two factors owes one");
        };
        assert!(owed.code, "a code is offered");
        let asked = owed.key.expect("and a key");
        assert!(give_key(&scenario, owed.person.id, &asked, 1).is_ok());

        let person = owe_a_code_beside_a_key(&scenario);
        assert!(give_code(&scenario, person, &scenario.read_code_now(&secret), &[]).is_ok());
    }

    /// Gives the password of `ada`, who holds a code and a key, and returns
    /// who owes one of them.
    fn owe_a_code_beside_a_key(scenario: &Scenario) -> Uuid {
        match give_password(scenario, PASSWORD, &[]).expect("a right password") {
            FirstStep::SecondFactorRequired(owed) => {
                assert!(owed.code && owed.key.is_some());
                owed.person.id
            }
            FirstStep::SignedIn(_) => panic!("a person with two factors owes one"),
        }
    }

    /// Gives a wrong code for `person` `times` times, from an address of its
    /// own each time: only the person and the name are counted.
    fn guess_codes(scenario: &Scenario, person: Uuid, times: u32) {
        for last in 1..=times {
            let address = std::net::IpAddr::from([192, 0, 2, u8::try_from(last).expect("a byte")]);
            let refused = complete(finish_sign_in_with_code(
                &scenario.app,
                scenario.scope,
                person,
                "000000",
                Some(address),
                &[],
            ));
            assert_eq!(
                refused.map(|_| ()).map_err(|failure| failure.code),
                Err(ErrorCode::CodeRejected)
            );
        }
    }

    /// Spends what `address` may attempt in the window, on a name nobody
    /// has: one attempt more is refused before anything is hashed.
    fn spend_attempts_of(scenario: &Scenario, address: std::net::IpAddr) {
        use crate::login::throttle::MAX_RECENT_ATTEMPTS_PER_ADDRESS;

        let attempt = || {
            complete(sign_in_with_password(
                &scenario.app,
                scenario.scope,
                "nobody",
                Secret::new(b"a guess".to_vec()),
                Some(address),
                &[],
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        };
        for _ in 0..MAX_RECENT_ATTEMPTS_PER_ADDRESS {
            assert_eq!(attempt(), Err(ErrorCode::SignInFailed));
        }
        assert_eq!(
            attempt(),
            Err(ErrorCode::HashingBusy),
            "the address spent what it may attempt"
        );
    }

    #[test]
    fn a_second_step_is_not_counted_against_what_its_address_may_attempt() {
        let address = std::net::IpAddr::from([203, 0, 113, 7]);
        let (scenario, secret) = start_enrolled();
        let person = owe_a_code(&scenario, &[]);
        spend_attempts_of(&scenario, address);

        let by_code = complete(finish_sign_in_with_code(
            &scenario.app,
            scenario.scope,
            person,
            &scenario.read_code_now(&secret),
            Some(address),
            &[],
        ));
        assert_eq!(
            by_code.map(|_| ()).map_err(|failure| failure.code),
            Ok(()),
            "nothing is hashed for a code"
        );

        let scenario = start_with_a_key();
        let (person, asked) = owe_a_key(&scenario);
        spend_attempts_of(&scenario, address);
        let by_key = complete(finish_sign_in_with_key(
            &scenario.app,
            scenario.scope,
            person,
            &asked.state,
            &TrustingKeys::answer_proof(&asked.options, "k1", 1),
            Some(address),
            &[],
        ));
        assert_eq!(
            by_key.map(|_| ()).map_err(|failure| failure.code),
            Ok(()),
            "nor for the answer of a key"
        );
    }

    #[test]
    fn a_key_that_counts_nothing_answers_zero_each_time_and_is_let_in_each_time() {
        let scenario = start_with_a_key();

        for _ in 0..2 {
            let (person, asked) = owe_a_key(&scenario);
            assert_eq!(
                give_key(&scenario, person, &asked, 0).map(|_| ()),
                Ok(()),
                "a counter that stays at zero tells no copy"
            );
        }
    }

    #[test]
    fn a_proven_key_forgets_the_codes_the_person_got_wrong_short_of_a_suspension() {
        use crate::login::steps::totp::MAX_CODE_FAILURES;

        let (scenario, secret) = start_enrolled();
        let proved = scenario.sign_in_with_code(&secret);
        scenario.enroll_security_key(&proved, "k1");
        let person = owe_a_code_beside_a_key(&scenario);
        guess_codes(&scenario, person, MAX_CODE_FAILURES - 1);
        // Past the window that locks the name for whoever comes from no address.
        scenario.clock.advance(Duration::from_mins(10));

        scenario.sign_in_with_key("k1", 1);

        // Counted once more in a unit of work that is not committed.
        let counted = complete(async {
            let mut work = scenario
                .app
                .storage
                .begin(scenario.scope)
                .await
                .expect("a unit of work");
            work.count_code_attempt(person, scenario.app.now())
                .await
                .expect("a count")
        });
        assert_eq!(counted, 1, "the key forgot the nine wrong codes");
    }

    #[test]
    fn a_proven_key_lets_the_person_in_and_leaves_their_suspended_codes_suspended() {
        use crate::login::steps::totp::MAX_CODE_FAILURES;

        let (scenario, secret) = start_enrolled();
        let proved = scenario.sign_in_with_code(&secret);
        scenario.enroll_security_key(&proved, "k1");
        let person = owe_a_code_beside_a_key(&scenario);
        guess_codes(&scenario, person, MAX_CODE_FAILURES);
        scenario.clock.advance(Duration::from_mins(10));

        scenario.sign_in_with_key("k1", 1);

        let person = owe_a_code_beside_a_key(&scenario);
        assert_eq!(
            give_code(&scenario, person, &scenario.read_code_now(&secret), &[]).map(|_| ()),
            Err(ErrorCode::CodeRejected),
            "only an administrator resumes suspended codes"
        );
    }

    #[test]
    fn codes_given_by_a_person_without_an_application_are_not_counted_and_suspend_nothing() {
        use crate::login::steps::totp::MAX_CODE_FAILURES;

        let scenario = start_with_a_key();
        let (person, _) = owe_a_key(&scenario);
        guess_codes(&scenario, person, MAX_CODE_FAILURES);

        assert!(
            !scenario
                .read_event_kinds()
                .iter()
                .any(|kind| kind == "authenticator.codes_suspended"),
            "a person who has no codes has none suspended"
        );
        // Counted once more in a unit of work that is not committed.
        let counted = complete(async {
            let mut work = scenario
                .app
                .storage
                .begin(scenario.scope)
                .await
                .expect("a unit of work");
            work.count_code_attempt(person, scenario.app.now())
                .await
                .expect("a count")
        });
        assert_eq!(
            counted, 1,
            "none of the codes was counted against the person"
        );
    }

    #[test]
    fn where_keys_are_not_served_a_person_with_a_key_and_an_application_owes_the_code() {
        let (mut scenario, secret) = start_enrolled();
        let proved = scenario.sign_in_with_code(&secret);
        scenario.enroll_security_key(&proved, "k1");
        scenario.clock.advance(Duration::from_secs(30));
        scenario.app.security_keys = Arc::new(UnservedKeys);

        let person = owe_a_code(&scenario, &[]);

        assert!(give_code(&scenario, person, &scenario.read_code_now(&secret), &[]).is_ok());
    }

    #[test]
    fn where_keys_are_not_served_a_person_with_only_a_key_is_told_so_after_their_password() {
        let mut scenario = start_with_a_key();
        scenario.app.security_keys = Arc::new(UnservedKeys);
        let opened_before = count_sessions_opened(&scenario);

        assert_eq!(
            give_password(&scenario, "not the password", &[]).map(|_| ()),
            Err(ErrorCode::SignInFailed),
            "nobody who does not know the password is told"
        );
        assert_eq!(
            give_password(&scenario, PASSWORD, &[]).map(|_| ()),
            Err(ErrorCode::SecurityKeysNotServed)
        );
        assert_eq!(count_sessions_opened(&scenario), opened_before);
    }
}
