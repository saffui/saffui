//! Running a flow against what a realm holds.

mod support;

use chrono::Utc;
use models::auditable::AuditableModel;
use models::entities::auth::{
    AuthenticationExecutionMutationModel, AuthenticationFlowMutationModel,
    AuthenticatorRequirement, ExecutionStep,
};
use models::entities::credentials::{CredentialModel, CredentialSecret, CredentialType};
use secrecy::SecretBox;
use services::login::authenticator::Answer;
use services::login::{Progress, Unrunnable, run_flow};
use store::providers::{auth_flows, credentials, realms};
use store::tenancy::TenantContext;
use support::{Fixture, provider};

fn tenant() -> TenantContext {
    TenantContext::new("acme", "main")
}

fn meta() -> AuditableModel {
    AuditableModel::from_creator("acme".to_owned(), "root".to_owned())
}

/// A flow with one step, at the requirement asked for.
async fn plant_flow(
    transaction: &deadpool_postgres::Transaction<'_>,
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
async fn plant_password(transaction: &deadpool_postgres::Transaction<'_>, password: &str) {
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
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

    let flow = plant_flow(&transaction, AuthenticatorRequirement::Required, "password").await;
    plant_password(&transaction, "correct horse").await;

    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();
    let user = store::providers::users::load(&transaction, "ada")
        .await
        .unwrap()
        .unwrap();

    // Nothing answered: the caller is asked, and told which step asks.
    let asked = run_flow(
        &transaction,
        &provider(),
        &realm,
        &flow,
        Some(&user),
        &[],
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(
        asked,
        Progress::Waiting {
            execution_id: "exec-1".to_owned()
        },
        "a step with no answer refused instead of asking"
    );

    let right = Answer::Password(SecretBox::new(Box::new("correct horse".to_owned())));
    assert!(matches!(
        run_flow(
            &transaction,
            &provider(),
            &realm,
            &flow,
            Some(&user),
            std::slice::from_ref(&right),
            Utc::now()
        )
        .await
        .unwrap(),
        Progress::Admitted { .. }
    ));

    let wrong = Answer::Password(SecretBox::new(Box::new("battery staple".to_owned())));
    assert_eq!(
        run_flow(
            &transaction,
            &provider(),
            &realm,
            &flow,
            Some(&user),
            std::slice::from_ref(&wrong),
            Utc::now()
        )
        .await
        .unwrap(),
        Progress::Refused
    );
}

/// A name nobody answers to refuses, and it does so having spent what a
/// verification spends: a login that answers faster for an unknown name than
/// for a known one publishes which names exist.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_unknown_subject_is_refused_like_a_wrong_password() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

    let flow = plant_flow(&transaction, AuthenticatorRequirement::Required, "password").await;
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();

    let offered = Answer::Password(SecretBox::new(Box::new("anything".to_owned())));
    assert_eq!(
        run_flow(
            &transaction,
            &provider(),
            &realm,
            &flow,
            None,
            std::slice::from_ref(&offered),
            Utc::now()
        )
        .await
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
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

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
            &flow,
            None,
            &[],
            Utc::now()
        )
        .await,
        Err(Unrunnable::Unknown(_))
    ));
}

/// A flow the realm does not have is not a refusal on the merits.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_flow_that_is_not_there_is_not_a_refusal() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();

    assert_eq!(
        run_flow(
            &transaction,
            &provider(),
            &realm,
            "no-such-flow",
            None,
            &[],
            Utc::now()
        )
        .await
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
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

    let flow = plant_flow(&transaction, AuthenticatorRequirement::Disabled, "password").await;
    plant_password(&transaction, "correct horse").await;
    let realm = realms::load(&transaction, "main").await.unwrap().unwrap();
    let user = store::providers::users::load(&transaction, "ada")
        .await
        .unwrap()
        .unwrap();

    let right = Answer::Password(SecretBox::new(Box::new("correct horse".to_owned())));
    assert_eq!(
        run_flow(
            &transaction,
            &provider(),
            &realm,
            &flow,
            Some(&user),
            std::slice::from_ref(&right),
            Utc::now()
        )
        .await
        .unwrap(),
        Progress::Refused,
        "a disabled step let somebody in"
    );
}
