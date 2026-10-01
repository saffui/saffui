mod support;

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use auth::login::authenticator::{Answer, Answered, Authenticator, verify_answer};
use auth::login::enrolment::{self, Enrolment};
use auth::login::step::Outcome;
use auth::login::wallet::{Asked, Asking, Presented, Purpose, Unasked, Wallet};
use auth::login::{Lock, PassedSteps, Progress, Unrunnable, run_flow};
use chrono::Utc;
use models::auditable::AuditableModel;
use models::entities::auth::{
    AuthenticationExecutionMutationModel, AuthenticationFlowMutationModel,
    AuthenticatorRequirement, ExecutionStep,
};
use models::entities::credentials::{CredentialModel, CredentialSecret, CredentialType};
use models::entities::realm::RealmModel;
use models::entities::user::{RequiredAction, UserCreateModel, UserModel};
use secrecy::SecretBox;
use serde_json::{Value, json};
use store::providers::directory::{credentials, users, wallet_identities};
use store::providers::realms;
use store::providers::realms::{auth_flows, realm_features};
use store::tenancy::{TenantContext, UnitOfWork};
use support::{Fixture, provider};

fn tenant() -> TenantContext {
    TenantContext::new("acme", "main")
}

fn meta() -> AuditableModel {
    AuditableModel::from_creator("acme".to_owned(), "root".to_owned())
}

/// A flow with one step, at the requirement asked for.
async fn plant_flow(
    transaction: &UnitOfWork,
    requirement: AuthenticatorRequirement,
    authenticator: &str,
) -> String {
    let flow = AuthenticationFlowMutationModel {
        alias: "browser".into(),
        provider_id: "basic-flow".into(),
        description: String::new(),
        top_level: Some(true),
        built_in: Some(false),
    }
    .into_model("browser".into(), "main".into(), meta());
    auth_flows::create_flow(transaction, &flow).await.unwrap();

    let execution = AuthenticationExecutionMutationModel {
        alias: "the-password".into(),
        flow_id: "browser".into(),
        priority: 10,
        step: ExecutionStep::Authenticator {
            authenticator: authenticator.to_owned(),
            config_id: None,
        },
        requirement,
    }
    .into_model("exec-1".into(), "main".into(), meta());
    auth_flows::create_execution(transaction, &execution)
        .await
        .unwrap();

    "browser".to_owned()
}

/// A password credential for the fixture's user, hashed the way the realm asks.
async fn plant_password(transaction: &UnitOfWork, password: &str) {
    let held = crypto::password::StoredPassword::hash_argon2id(
        &provider(),
        crypto::provider::Argon2Params::default(),
        &SecretBox::new(Box::new(password.to_owned())),
    )
    .expect("a hash");
    let crypto::password::StoredPassword::Argon2id { encoded } = held else {
        panic!("argon2id is what was asked for");
    };

    let credential = CredentialModel {
        credential_id: "cred-1".into(),
        realm_id: "main".into(),
        user_id: "ada".into(),
        credential_type: CredentialType::Password,
        user_label: None,
        secret: CredentialSecret::new(encoded),
        otp: None,
        priority: 0,
        metadata: meta(),
    };
    credentials::create(transaction, &credential).await.unwrap();
}

/// The whole point: the right password admits, the wrong one refuses, and no
/// answer at all asks rather than refusing.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_password_flow_admits_refuses_and_asks() {
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&tenant()).await;

    let flow = plant_flow(&transaction, AuthenticatorRequirement::Required, "password").await;
    plant_password(&transaction, "correct horse").await;

    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();
    let user = store::providers::directory::users::load(&transaction, "ada")
        .await
        .unwrap()
        .unwrap();

    // Nothing answered: the caller is asked, and told which step asks.
    let asked = run_flow(
        &transaction,
        &provider(),
        &realm,
        &origin(),
        &flow,
        Some(&user),
        &[],
        &PassedSteps::new(),
        &serde_json::Value::Null,
        None,
        &[],
        None,
        None,
        Lock::Applies,
        Utc::now(),
    )
    .await
    .map(|(progress, _)| progress)
    .unwrap();
    assert_eq!(
        asked,
        Progress::Waiting {
            execution_id: "exec-1".to_owned(),
            asks: None,
            remember: serde_json::Map::new(),
            passed: PassedSteps::new(),
        },
        "a step with no answer refused instead of asking"
    );

    let right = Answer::Password(SecretBox::new(Box::new("correct horse".to_owned())));
    assert!(matches!(
        run_flow(
            &transaction,
            &provider(),
            &realm,
            &origin(),
            &flow,
            Some(&user),
            std::slice::from_ref(&right),
            &PassedSteps::new(),
            &serde_json::Value::Null,
            None,
            &[],
            None,
            None,
            Lock::Applies,
            Utc::now(),
        )
        .await
        .map(|(progress, _)| progress)
        .unwrap(),
        Progress::Admitted { .. }
    ));

    let wrong = Answer::Password(SecretBox::new(Box::new("battery staple".to_owned())));
    assert_eq!(
        run_flow(
            &transaction,
            &provider(),
            &realm,
            &origin(),
            &flow,
            Some(&user),
            std::slice::from_ref(&wrong),
            &PassedSteps::new(),
            &serde_json::Value::Null,
            None,
            &[],
            None,
            None,
            Lock::Applies,
            Utc::now(),
        )
        .await
        .map(|(progress, _)| progress)
        .unwrap(),
        Progress::Refused
    );
}

/// A step an earlier round of the login passed counts without its answer, as
/// the authenticator it ran and nothing else: rewritten since to run another,
/// it asks again.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_step_the_login_passed_counts_as_what_it_ran() {
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&tenant()).await;

    let flow = plant_flow(&transaction, AuthenticatorRequirement::Required, "password").await;
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();
    let user = store::providers::directory::users::load(&transaction, "ada")
        .await
        .unwrap()
        .unwrap();
    let unanswered = async |already: &PassedSteps| {
        run_flow(
            &transaction,
            &provider(),
            &realm,
            &origin(),
            &flow,
            Some(&user),
            &[],
            already,
            &serde_json::Value::Null,
            None,
            &[],
            None,
            None,
            Lock::Applies,
            Utc::now(),
        )
        .await
        .map(|(progress, _)| progress)
        .unwrap()
    };

    let counted = PassedSteps::from([("exec-1".to_owned(), Authenticator::Password)]);
    assert_eq!(
        unanswered(&counted).await,
        Progress::Admitted {
            passed: counted.clone()
        },
        "a step the login passed was asked again"
    );

    let rewritten = PassedSteps::from([("exec-1".to_owned(), Authenticator::Totp)]);
    assert_eq!(
        unanswered(&rewritten).await,
        Progress::Waiting {
            execution_id: "exec-1".to_owned(),
            asks: None,
            remember: serde_json::Map::new(),
            passed: PassedSteps::new(),
        },
        "a step counted as an authenticator it no longer runs"
    );
}

/// A name nobody answers to refuses, and it does so having spent what a
/// verification spends: a login that answers faster for an unknown name than
/// for a known one publishes which names exist.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_unknown_subject_is_refused_like_a_wrong_password() {
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&tenant()).await;

    let flow = plant_flow(&transaction, AuthenticatorRequirement::Required, "password").await;
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();

    let offered = Answer::Password(SecretBox::new(Box::new("anything".to_owned())));
    assert_eq!(
        run_flow(
            &transaction,
            &provider(),
            &realm,
            &origin(),
            &flow,
            None,
            std::slice::from_ref(&offered),
            &PassedSteps::new(),
            &serde_json::Value::Null,
            None,
            &[],
            None,
            None,
            Lock::Applies,
            Utc::now(),
        )
        .await
        .map(|(progress, _)| progress)
        .unwrap(),
        Progress::Refused
    );
}

/// A step naming an authenticator this build does not have is refused where the
/// flow is read. Skipped, it would be a step that does nothing, and a step that
/// does nothing among alternatives is a way in nobody wrote.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_step_this_build_cannot_run_stops_the_flow() {
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&tenant()).await;

    let flow = plant_flow(
        &transaction,
        AuthenticatorRequirement::Alternative,
        "telepathy",
    )
    .await;
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();

    assert!(matches!(
        run_flow(
            &transaction,
            &provider(),
            &realm,
            &origin(),
            &flow,
            None,
            &[],
            &PassedSteps::new(),
            &serde_json::Value::Null,
            None,
            &[],
            None,
            None,
            Lock::Applies,
            Utc::now(),
        )
        .await
        .map(|(progress, _)| progress),
        Err(Unrunnable::Unknown(_))
    ));
}

/// A flow the realm does not have is not a refusal on the merits.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_flow_that_is_not_there_is_not_a_refusal() {
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&tenant()).await;
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();

    assert_eq!(
        run_flow(
            &transaction,
            &provider(),
            &realm,
            &origin(),
            "no-such-flow",
            None,
            &[],
            &PassedSteps::new(),
            &serde_json::Value::Null,
            None,
            &[],
            None,
            None,
            Lock::Applies,
            Utc::now(),
        )
        .await
        .map(|(progress, _)| progress)
        .expect_err("no flow"),
        Unrunnable::NoSuchFlow
    );
}

/// A disabled step runs nothing, so a flow whose only step is disabled admits
/// nobody rather than everybody.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_flow_whose_only_step_is_disabled_admits_nobody() {
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&tenant()).await;

    let flow = plant_flow(&transaction, AuthenticatorRequirement::Disabled, "password").await;
    plant_password(&transaction, "correct horse").await;
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();
    let user = store::providers::directory::users::load(&transaction, "ada")
        .await
        .unwrap()
        .unwrap();

    let right = Answer::Password(SecretBox::new(Box::new("correct horse".to_owned())));
    assert_eq!(
        run_flow(
            &transaction,
            &provider(),
            &realm,
            &origin(),
            &flow,
            Some(&user),
            std::slice::from_ref(&right),
            &PassedSteps::new(),
            &serde_json::Value::Null,
            None,
            &[],
            None,
            None,
            Lock::Applies,
            Utc::now(),
        )
        .await
        .map(|(progress, _)| progress)
        .unwrap(),
        Progress::Refused,
        "a disabled step let somebody in"
    );
}

/// Where the suite's deployment answers from. A relying party is built from it,
/// so a flow that runs a key needs one even when no key is enrolled.
fn origin() -> config::serving::PublicOrigin {
    config::serving::PublicOrigin::parse("https://id.test").expect("a usable origin")
}

/// The login every presentation in these cases is bound to.
const LOGIN: &str = "login-1";
const ISSUER: &str = "did:web:id.example";
const MINE: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
const THEIRS: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const ANOTHER: &str = "0000000000000000000000000000000000000000000000000000000000000002";

/// The verifier is experimental and off unless the process runs it, and the
/// first call decides for the whole binary: every wallet case turns it on
/// before anything reads what the process runs.
fn wallet_running() {
    commons::feature::install(
        commons::feature::FeatureSet::resolve("+wallet-verifier", |_| false)
            .expect("a set that resolves"),
    );
    assert!(
        commons::feature::installed().is_enabled(commons::feature::Feature::WalletVerifier),
        "the process does not run the wallet verifier"
    );
}

/// A verifier answering what each case scripts, keeping what it was asked.
struct ScriptedWallet {
    offers: Result<(), Unasked>,
    stands: Mutex<Result<Presented, ()>>,
    asked: Mutex<Vec<(Purpose, String, Option<String>)>>,
    read: Mutex<Vec<(String, String)>>,
}

impl ScriptedWallet {
    fn offering(offers: Result<(), Unasked>) -> Self {
        ScriptedWallet {
            offers,
            stands: Mutex::new(Ok(Presented::Waiting)),
            asked: Mutex::new(Vec::new()),
            read: Mutex::new(Vec::new()),
        }
    }

    fn stand(&self, presented: Presented) {
        *self.stands.lock().unwrap() = Ok(presented);
    }

    fn stand_unreadable(&self) {
        *self.stands.lock().unwrap() = Err(());
    }

    fn asked(&self) -> Vec<(Purpose, String, Option<String>)> {
        self.asked.lock().unwrap().clone()
    }

    fn read(&self) -> Vec<(String, String)> {
        self.read.lock().unwrap().clone()
    }

    fn bound(&self) -> Asking<'_> {
        Asking {
            verifier: self,
            login_session: LOGIN,
        }
    }
}

impl Wallet for ScriptedWallet {
    fn ask<'a>(
        &'a self,
        _transaction: &'a UnitOfWork,
        purpose: Purpose,
        login_session: &'a str,
        user_id: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Asked, Unasked>> + Send + 'a>> {
        Box::pin(async move {
            self.offers?;
            let mut asked = self.asked.lock().unwrap();
            asked.push((
                purpose,
                login_session.to_owned(),
                user_id.map(str::to_owned),
            ));
            Ok(drawn_request(asked.len()))
        })
    }

    fn standing<'a>(
        &'a self,
        _transaction: &'a UnitOfWork,
        request_id: &'a str,
        login_session: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Presented, ()>> + Send + 'a>> {
        Box::pin(async move {
            self.read
                .lock()
                .unwrap()
                .push((request_id.to_owned(), login_session.to_owned()));
            self.stands.lock().unwrap().clone()
        })
    }

    // Spending a code is the login's, ahead of the flow; the flow only ever
    // reads where the request it kept stands.
    fn redeem<'a>(
        &'a self,
        _transaction: &'a UnitOfWork,
        _request_id: &'a str,
        _login_session: &'a str,
        _response_code: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Presented>, ()>> + Send + 'a>> {
        Box::pin(async move { Err(()) })
    }
}

/// The request the scripted verifier hands out on its nth ask.
fn drawn_request(nth: usize) -> Asked {
    Asked {
        request_id: format!("request-{nth}"),
        uri: format!("openid4vp://?request_uri=https%3A%2F%2Fid.test%2Frequest%2F{nth}"),
    }
}

/// What a page is shown for a request, drawing and all.
fn shown_for(asked: &Asked) -> Value {
    json!({ "wallet": { "uri": asked.uri, "qr": commons::qr::draw_qr_svg(&asked.uri) } })
}

/// What a round keeps of a request.
fn kept_for(asked: &Asked) -> Value {
    json!({ "request": asked.request_id, "uri": asked.uri })
}

fn identified(digest: &str) -> Presented {
    Presented::Identified {
        issuer: ISSUER.to_owned(),
        digest: digest.to_owned(),
    }
}

/// A step after the one `plant_flow` planted.
async fn plant_next_step(
    transaction: &UnitOfWork,
    execution_id: &str,
    requirement: AuthenticatorRequirement,
    authenticator: &str,
) {
    let execution = AuthenticationExecutionMutationModel {
        alias: format!("the-{authenticator}"),
        flow_id: "browser".into(),
        priority: 20,
        step: ExecutionStep::Authenticator {
            authenticator: authenticator.to_owned(),
            config_id: None,
        },
        requirement,
    }
    .into_model(execution_id.into(), "main".into(), meta());
    auth_flows::create_execution(transaction, &execution)
        .await
        .unwrap();
}

async fn plant_bob(transaction: &UnitOfWork) {
    let bob = UserCreateModel {
        user_name: "bob".into(),
        enabled: true,
        email: String::new(),
        email_verified: None,
        phone_number: None,
        phone_number_verified: None,
        required_actions: None,
        not_before: None,
        user_storage: None,
        attributes: None,
        is_service_account: None,
        service_account_client_link: None,
    }
    .into_model("bob".into(), "main".into(), meta());
    users::create(transaction, &bob).await.unwrap();
}

async fn load_ada(transaction: &UnitOfWork) -> UserModel {
    users::load(transaction, "ada").await.unwrap().unwrap()
}

#[allow(
    clippy::too_many_arguments,
    reason = "one round, as the engine runs it"
)]
async fn run_round(
    transaction: &UnitOfWork,
    realm: &RealmModel,
    flow: &str,
    subject: Option<&UserModel>,
    answers: &[Answer],
    notes: &Value,
    wallet: &ScriptedWallet,
) -> Progress {
    run_flow(
        transaction,
        &provider(),
        realm,
        &origin(),
        flow,
        subject,
        answers,
        &PassedSteps::new(),
        notes,
        None,
        &[],
        Some(wallet.bound()),
        None,
        Lock::Applies,
        Utc::now(),
    )
    .await
    .map(|(progress, _)| progress)
    .unwrap()
}

/// A wallet step asks once a password named the person, waits on that one
/// request for as many rounds as it stays open, and passes on the identity
/// the account linked, never on another. A request run out is asked again,
/// and so is one the wallet declined, saying so.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_wallet_step_waits_on_its_request_and_passes_on_the_linked_identity() {
    wallet_running();
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&tenant()).await;
    let flow = plant_flow(&transaction, AuthenticatorRequirement::Required, "password").await;
    plant_next_step(
        &transaction,
        "exec-2",
        AuthenticatorRequirement::Required,
        "wallet",
    )
    .await;
    plant_password(&transaction, "correct horse").await;
    wallet_identities::link(&transaction, "ada", ISSUER, MINE, &Utc::now())
        .await
        .unwrap();
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();
    let ada = load_ada(&transaction).await;
    let wallet = ScriptedWallet::offering(Ok(()));
    let right = || Answer::Password(SecretBox::new(Box::new("correct horse".to_owned())));

    // Nobody named: the password is asked for, and no wallet.
    assert_eq!(
        run_round(
            &transaction,
            &realm,
            &flow,
            None,
            &[],
            &Value::Null,
            &wallet
        )
        .await,
        Progress::Waiting {
            execution_id: "exec-1".to_owned(),
            asks: None,
            remember: serde_json::Map::new(),
            passed: PassedSteps::new(),
        }
    );
    assert_eq!(wallet.asked(), []);

    let first = drawn_request(1);
    let waiting_on = |asked: &Asked, shown: Value| Progress::Waiting {
        execution_id: "exec-2".to_owned(),
        asks: Some(shown),
        remember: [("wallet".to_owned(), kept_for(asked))]
            .into_iter()
            .collect(),
        passed: PassedSteps::from([("exec-1".to_owned(), Authenticator::Password)]),
    };
    assert_eq!(
        run_round(
            &transaction,
            &realm,
            &flow,
            Some(&ada),
            &[right()],
            &Value::Null,
            &wallet
        )
        .await,
        waiting_on(&first, shown_for(&first))
    );
    assert_eq!(
        wallet.asked(),
        [(Purpose::Factor, LOGIN.to_owned(), Some("ada".to_owned()))]
    );

    // The same request, read for this login, while it stays open.
    let notes = json!({ "wallet": kept_for(&first) });
    assert_eq!(
        run_round(
            &transaction,
            &realm,
            &flow,
            Some(&ada),
            &[right()],
            &notes,
            &wallet
        )
        .await,
        waiting_on(&first, shown_for(&first))
    );
    assert_eq!(wallet.asked().len(), 1, "an open request was asked again");
    assert_eq!(wallet.read(), [("request-1".to_owned(), LOGIN.to_owned())]);

    wallet.stand(identified(MINE));
    assert_eq!(
        run_round(
            &transaction,
            &realm,
            &flow,
            Some(&ada),
            &[right()],
            &notes,
            &wallet
        )
        .await,
        Progress::Admitted {
            passed: PassedSteps::from([
                ("exec-1".to_owned(), Authenticator::Password),
                ("exec-2".to_owned(), Authenticator::Wallet),
            ]),
        }
    );
    wallet.stand(identified(THEIRS));
    assert_eq!(
        run_round(
            &transaction,
            &realm,
            &flow,
            Some(&ada),
            &[right()],
            &notes,
            &wallet
        )
        .await,
        Progress::Refused,
        "an identity this account never linked passed"
    );
    wallet.stand(Presented::Identified {
        issuer: "did:web:elsewhere.example".to_owned(),
        digest: MINE.to_owned(),
    });
    assert_eq!(
        run_round(
            &transaction,
            &realm,
            &flow,
            Some(&ada),
            &[right()],
            &notes,
            &wallet
        )
        .await,
        Progress::Refused,
        "the digest passed under an issuer it was never linked from"
    );

    wallet.stand(Presented::Lapsed);
    let second = drawn_request(2);
    assert_eq!(
        run_round(
            &transaction,
            &realm,
            &flow,
            Some(&ada),
            &[right()],
            &notes,
            &wallet
        )
        .await,
        waiting_on(&second, shown_for(&second))
    );
    wallet.stand(Presented::Unproven);
    let third = drawn_request(3);
    let mut refused = shown_for(&third);
    refused["refused"] = json!(true);
    assert_eq!(
        run_round(
            &transaction,
            &realm,
            &flow,
            Some(&ada),
            &[right()],
            &notes,
            &wallet
        )
        .await,
        waiting_on(&third, refused)
    );

    wallet.stand_unreadable();
    assert_eq!(
        run_round(
            &transaction,
            &realm,
            &flow,
            Some(&ada),
            &[right()],
            &notes,
            &wallet
        )
        .await,
        Progress::Refused,
        "a presentation nobody could read passed"
    );
    assert_eq!(
        wallet.asked().len(),
        3,
        "an unreadable request was asked again"
    );
}

/// What the step answers before it asks anything: failed with no verifier
/// and for an account that linked nothing, waiting while nobody is named,
/// and skipped where the realm has nothing to ask by or closed the factor,
/// which leaves what a step that cannot run leaves to the flow.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_wallet_step_asks_only_what_can_be_answered() {
    wallet_running();
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&tenant()).await;
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();
    let ada = load_ada(&transaction).await;
    let step = async |subject: Option<&UserModel>, wallet: Option<Asking<'_>>| -> Answered {
        verify_answer(
            &transaction,
            &provider(),
            &realm,
            &origin(),
            subject,
            Authenticator::Wallet,
            &[],
            None,
            None,
            &[],
            wallet,
        )
        .await
    };
    let offering = ScriptedWallet::offering(Ok(()));

    let answered = step(Some(&ada), None).await;
    assert_eq!(answered.outcome, Outcome::Failed, "no verifier");
    let answered = step(None, Some(offering.bound())).await;
    assert_eq!(answered.outcome, Outcome::Pending, "nobody named");
    assert!(answered.asks.is_none(), "{:?}", answered.asks);
    let answered = step(Some(&ada), Some(offering.bound())).await;
    assert_eq!(answered.outcome, Outcome::Failed, "nothing linked");
    assert_eq!(offering.asked(), [], "a wallet was asked for nothing");

    wallet_identities::link(&transaction, "ada", ISSUER, MINE, &Utc::now())
        .await
        .unwrap();
    let not_offered = ScriptedWallet::offering(Err(Unasked::NotOffered));
    let answered = step(Some(&ada), Some(not_offered.bound())).await;
    assert_eq!(answered.outcome, Outcome::Skipped, "no profile");
    let unavailable = ScriptedWallet::offering(Err(Unasked::Unavailable));
    let answered = step(Some(&ada), Some(unavailable.bound())).await;
    assert_eq!(answered.outcome, Outcome::Failed, "asking failed");

    realm_features::keep_wish(&transaction, "wallet-verifier", false, "root")
        .await
        .unwrap();
    let answered = step(Some(&ada), Some(offering.bound())).await;
    assert_eq!(answered.outcome, Outcome::Skipped, "the realm closed it");
    assert_eq!(offering.asked(), [], "a closed factor asked a wallet");
}

/// What a page is shown for a sign-in: the link alone.
fn shown_for_sign_in(asked: &Asked) -> Value {
    json!({ "wallet": { "uri": asked.uri, "same_device": true } })
}

/// A sign-in asks a wallet only once the person asks, shows its link and never
/// a drawing of it, and names nobody in asking. It answers like the proof
/// where it cannot run.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_wallet_sign_in_asks_only_once_asked_and_shows_no_drawing() {
    wallet_running();
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&tenant()).await;
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();
    let step = async |answers: &[Answer], wallet: Option<Asking<'_>>| -> Answered {
        verify_answer(
            &transaction,
            &provider(),
            &realm,
            &origin(),
            None,
            Authenticator::WalletSignIn,
            answers,
            None,
            None,
            &[],
            wallet,
        )
        .await
    };
    let offering = ScriptedWallet::offering(Ok(()));

    let answered = step(&[Answer::WalletAsk], None).await;
    assert_eq!(answered.outcome, Outcome::Failed, "no verifier");
    let answered = step(&[], Some(offering.bound())).await;
    assert_eq!(answered.outcome, Outcome::Pending, "not asked yet");
    assert!(answered.asks.is_none(), "{:?}", answered.asks);
    assert_eq!(offering.asked(), [], "a wallet was asked unasked");

    let answered = step(&[Answer::WalletAsk], Some(offering.bound())).await;
    assert_eq!(answered.outcome, Outcome::Pending);
    let challenge = answered.asks.expect("a challenge");
    let first = drawn_request(1);
    assert_eq!(challenge.shown, shown_for_sign_in(&first));
    assert_eq!(challenge.remembered, kept_for(&first));
    assert_eq!(
        offering.asked(),
        [(Purpose::SignIn, LOGIN.to_owned(), None)]
    );

    let not_offered = ScriptedWallet::offering(Err(Unasked::NotOffered));
    let answered = step(&[Answer::WalletAsk], Some(not_offered.bound())).await;
    assert_eq!(answered.outcome, Outcome::Skipped, "no profile");
    let unavailable = ScriptedWallet::offering(Err(Unasked::Unavailable));
    let answered = step(&[Answer::WalletAsk], Some(unavailable.bound())).await;
    assert_eq!(answered.outcome, Outcome::Failed, "asking failed");

    realm_features::keep_wish(&transaction, "wallet-verifier", false, "root")
        .await
        .unwrap();
    let answered = step(&[Answer::WalletAsk], Some(offering.bound())).await;
    assert_eq!(answered.outcome, Outcome::Skipped, "the realm closed it");
    assert_eq!(offering.asked().len(), 1, "a closed sign-in asked a wallet");
}

/// A sign-in waits on its request until the browser that asked brings the
/// wallet's code back, and passes only then, on the identity the person it
/// named linked. Answered and not brought back, it passes nobody, a person
/// named by a typed name included: the link may have been forwarded to
/// whoever answered it. An identity no account linked is asked again, said,
/// and so are a request run out, a refusal and a person asking again.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_wallet_sign_in_passes_only_on_what_this_browser_brought_back() {
    wallet_running();
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&tenant()).await;
    let flow = plant_flow(
        &transaction,
        AuthenticatorRequirement::Required,
        "wallet-sign-in",
    )
    .await;
    wallet_identities::link(&transaction, "ada", ISSUER, MINE, &Utc::now())
        .await
        .unwrap();
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();
    let ada = load_ada(&transaction).await;
    let wallet = ScriptedWallet::offering(Ok(()));
    let first = drawn_request(1);
    let notes = json!({ "wallet-sign-in": kept_for(&first) });
    let waiting_on = |asked: &Asked, shown: Value| Progress::Waiting {
        execution_id: "exec-1".to_owned(),
        asks: Some(shown),
        remember: [("wallet-sign-in".to_owned(), kept_for(asked))]
            .into_iter()
            .collect(),
        passed: PassedSteps::new(),
    };
    let redeemed = |digest: &str| Presented::Redeemed {
        issuer: ISSUER.to_owned(),
        digest: digest.to_owned(),
    };

    for (standing, subject) in [
        (Presented::Waiting, None),
        (identified(MINE), None),
        (identified(MINE), Some(&ada)),
    ] {
        wallet.stand(standing.clone());
        assert_eq!(
            run_round(&transaction, &realm, &flow, subject, &[], &notes, &wallet).await,
            waiting_on(&first, shown_for_sign_in(&first)),
            "{standing:?} for {:?}",
            subject.map(|person| &person.user_id)
        );
    }
    assert_eq!(wallet.asked(), [], "an open request was asked again");

    wallet.stand(redeemed(MINE));
    assert_eq!(
        run_round(
            &transaction,
            &realm,
            &flow,
            Some(&ada),
            &[],
            &notes,
            &wallet
        )
        .await,
        Progress::Admitted {
            passed: PassedSteps::from([("exec-1".to_owned(), Authenticator::WalletSignIn)]),
        }
    );
    wallet.stand(redeemed(THEIRS));
    assert_eq!(
        run_round(
            &transaction,
            &realm,
            &flow,
            Some(&ada),
            &[],
            &notes,
            &wallet
        )
        .await,
        Progress::Refused,
        "an identity this person never linked passed"
    );

    let said = |nth: usize, flag: Option<&str>| {
        let asked = drawn_request(nth);
        let mut shown = shown_for_sign_in(&asked);
        if let Some(flag) = flag {
            shown[flag] = json!(true);
        }
        waiting_on(&asked, shown)
    };
    wallet.stand(redeemed(MINE));
    assert_eq!(
        run_round(&transaction, &realm, &flow, None, &[], &notes, &wallet).await,
        said(1, Some("unlinked"))
    );
    wallet.stand(Presented::Lapsed);
    assert_eq!(
        run_round(&transaction, &realm, &flow, None, &[], &notes, &wallet).await,
        said(2, None)
    );
    wallet.stand(Presented::Unproven);
    assert_eq!(
        run_round(&transaction, &realm, &flow, None, &[], &notes, &wallet).await,
        said(3, Some("refused"))
    );
    wallet.stand(Presented::Waiting);
    assert_eq!(
        run_round(
            &transaction,
            &realm,
            &flow,
            None,
            &[Answer::WalletAsk],
            &notes,
            &wallet
        )
        .await,
        said(4, None),
        "a person asking again was held on the request before"
    );
    assert!(
        wallet
            .asked()
            .iter()
            .all(|(purpose, _, named)| *purpose == Purpose::SignIn && named.is_none()),
        "{:?}",
        wallet.asked()
    );

    wallet.stand_unreadable();
    assert_eq!(
        run_round(&transaction, &realm, &flow, None, &[], &notes, &wallet).await,
        Progress::Refused,
        "a sign-in nobody could read passed"
    );
}

/// One round of the ceremony that links an identity, as a login runs it.
async fn run_linking(
    transaction: &UnitOfWork,
    realm: &RealmModel,
    subject: &UserModel,
    notes: &Value,
    declined: bool,
    wallet: &ScriptedWallet,
) -> Enrolment {
    enrolment::required(
        transaction,
        &provider(),
        &tenant(),
        realm,
        &origin(),
        subject,
        enrolment::Answers {
            declined,
            ..enrolment::Answers::default()
        },
        notes,
        None,
        Some(wallet.bound()),
    )
    .await
}

/// What a ceremony round asked, as the page is told it and as the notes keep
/// it.
fn read_asked(round: Enrolment) -> (&'static str, Value, Value) {
    match round {
        Enrolment::Asked {
            named, challenge, ..
        } => (named, challenge.shown, challenge.remembered),
        other => panic!("the ceremony did not ask: {other:?}"),
    }
}

async fn owes_linking(transaction: &UnitOfWork) -> bool {
    load_ada(transaction)
        .await
        .required_actions
        .unwrap_or_default()
        .contains(&RequiredAction::LinkWalletIdentity)
}

/// The ceremony asks the person's wallet, waits on that request, and links
/// the identity it proves, striking the instruction. An identity another
/// account holds, a second one from the same issuer and a wallet that
/// declined are each said, and the wallet asked again; an identity the
/// account holds already settles it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_linking_ceremony_links_what_the_wallet_proves_and_says_what_stands_in_the_way() {
    wallet_running();
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&tenant()).await;
    plant_bob(&transaction).await;
    wallet_identities::link(&transaction, "bob", ISSUER, THEIRS, &Utc::now())
        .await
        .unwrap();
    users::require_action(&transaction, "ada", RequiredAction::LinkWalletIdentity)
        .await
        .unwrap();
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();
    let ada = load_ada(&transaction).await;
    let wallet = ScriptedWallet::offering(Ok(()));

    let first = drawn_request(1);
    let asked = |asked: &Asked, said: &[&str]| {
        let mut shown = shown_for(asked);
        for flag in said {
            shown[*flag] = json!(true);
        }
        ("link-wallet-identity", shown, kept_for(asked))
    };
    let round = run_linking(&transaction, &realm, &ada, &Value::Null, false, &wallet).await;
    assert_eq!(read_asked(round), asked(&first, &[]));
    assert_eq!(
        wallet.asked(),
        [(Purpose::Link, LOGIN.to_owned(), Some("ada".to_owned()))]
    );

    let notes = json!({ "link-wallet-identity": kept_for(&first) });
    let round = run_linking(&transaction, &realm, &ada, &notes, false, &wallet).await;
    assert_eq!(read_asked(round), asked(&first, &[]));
    assert_eq!(wallet.read(), [("request-1".to_owned(), LOGIN.to_owned())]);

    wallet.stand(Presented::Lapsed);
    let round = run_linking(&transaction, &realm, &ada, &notes, false, &wallet).await;
    assert_eq!(read_asked(round), asked(&drawn_request(2), &[]));
    wallet.stand(Presented::Unproven);
    let round = run_linking(&transaction, &realm, &ada, &notes, false, &wallet).await;
    assert_eq!(read_asked(round), asked(&drawn_request(3), &["refused"]));
    wallet.stand(identified(THEIRS));
    let round = run_linking(&transaction, &realm, &ada, &notes, false, &wallet).await;
    assert_eq!(
        read_asked(round),
        asked(&drawn_request(4), &["held_elsewhere"])
    );
    assert_eq!(
        wallet_identities::holder(&transaction, ISSUER, THEIRS)
            .await
            .unwrap()
            .as_deref(),
        Some("bob")
    );

    wallet.stand(identified(MINE));
    let round = run_linking(&transaction, &realm, &ada, &notes, false, &wallet).await;
    assert!(matches!(round, Enrolment::Settled), "{round:?}");
    assert_eq!(
        wallet_identities::holder(&transaction, ISSUER, MINE)
            .await
            .unwrap()
            .as_deref(),
        Some("ada")
    );
    assert!(!owes_linking(&transaction).await, "the instruction stood");

    // Asked by an application now: optional, and declinable.
    let notes = json!({
        "enrol": "link-wallet-identity",
        "link-wallet-identity": kept_for(&first),
    });
    wallet.stand(identified(ANOTHER));
    let round = run_linking(&transaction, &realm, &ada, &notes, false, &wallet).await;
    assert_eq!(
        read_asked(round),
        asked(&drawn_request(5), &["issuer_linked", "optional"])
    );
    wallet.stand(identified(MINE));
    let round = run_linking(&transaction, &realm, &ada, &notes, false, &wallet).await;
    assert!(matches!(round, Enrolment::Settled), "{round:?}");
    let round = run_linking(&transaction, &realm, &ada, &notes, true, &wallet).await;
    assert!(matches!(round, Enrolment::Settled), "{round:?}");
    assert_eq!(
        wallet.asked().len(),
        5,
        "a declined ceremony asked a wallet"
    );
    assert_eq!(
        wallet_identities::of_user(&transaction, "ada")
            .await
            .unwrap()
            .len(),
        1
    );

    // A realm that keeps no profile leaves the instruction standing.
    users::require_action(&transaction, "ada", RequiredAction::LinkWalletIdentity)
        .await
        .unwrap();
    let not_offered = ScriptedWallet::offering(Err(Unasked::NotOffered));
    let round = run_linking(
        &transaction,
        &realm,
        &ada,
        &Value::Null,
        false,
        &not_offered,
    )
    .await;
    assert!(matches!(round, Enrolment::Settled), "{round:?}");
    let unasked = enrolment::required(
        &transaction,
        &provider(),
        &tenant(),
        &realm,
        &origin(),
        &ada,
        enrolment::Answers::default(),
        &Value::Null,
        None,
        None,
    )
    .await;
    assert!(matches!(unasked, Enrolment::Settled), "{unasked:?}");
    assert!(owes_linking(&transaction).await, "the instruction went");

    // What cannot be read or asked ends the round rather than linking.
    let unavailable = ScriptedWallet::offering(Err(Unasked::Unavailable));
    let round = run_linking(
        &transaction,
        &realm,
        &ada,
        &Value::Null,
        false,
        &unavailable,
    )
    .await;
    assert!(matches!(round, Enrolment::Refused), "{round:?}");
    let notes = json!({ "link-wallet-identity": kept_for(&first) });
    wallet.stand_unreadable();
    let round = run_linking(&transaction, &realm, &ada, &notes, false, &wallet).await;
    assert!(matches!(round, Enrolment::Refused), "{round:?}");
}
