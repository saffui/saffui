//! Flows, their steps and the actions a realm asks for, against a database.

mod support;

use models::auditable::AuditableModel;
use models::entities::auth::{
    AuthenticationExecutionMutationModel, AuthenticationFlowModel, AuthenticationFlowMutationModel,
    AuthenticatorConfigMutationModel, AuthenticatorRequirement, ExecutionStep,
    RequiredActionMutationModel,
};
use models::entities::realm::RealmCreateModel;
use models::entities::user::RequiredAction;
use store::providers::{auth_flows, realms};
use store::tenancy::TenantContext;
use support::Fixture;

fn metadata() -> AuditableModel {
    AuditableModel::from_creator("acme".to_owned(), "root".to_owned())
}

fn flow(id: &str, alias: &str, top_level: bool) -> AuthenticationFlowModel {
    AuthenticationFlowMutationModel {
        alias: alias.to_owned(),
        provider_id: "basic-flow".to_owned(),
        description: String::new(),
        top_level: Some(top_level),
        built_in: Some(false),
    }
    .into_model(id.to_owned(), "main".to_owned(), metadata())
}

fn step(
    id: &str,
    flow_id: &str,
    priority: i32,
    step: ExecutionStep,
) -> models::entities::auth::AuthenticationExecutionModel {
    AuthenticationExecutionMutationModel {
        alias: id.to_owned(),
        flow_id: flow_id.to_owned(),
        priority,
        step,
        requirement: AuthenticatorRequirement::Required,
    }
    .into_model(id.to_owned(), "main".to_owned(), metadata())
}

fn authenticator(name: &str, config_id: Option<&str>) -> ExecutionStep {
    ExecutionStep::Authenticator {
        authenticator: name.to_owned(),
        config_id: config_id.map(str::to_owned),
    }
}

async fn second_realm(fixture: &Fixture) {
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::tenant_wide("acme"))
        .await;
    let realm = RealmCreateModel {
        name: "other".into(),
        display_name: "Other".into(),
        enabled: true,
    }
    .into_model("other".into(), metadata());
    realms::create(&transaction, &realm).await.unwrap();
    transaction.commit().await.unwrap();
    drop(connection);
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_flow_comes_back_by_its_identifier_and_by_its_alias() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    auth_flows::create_flow(&transaction, &flow("flow-1", "browser", true))
        .await
        .unwrap();
    auth_flows::create_flow(&transaction, &flow("flow-2", "otp-conditional", false))
        .await
        .unwrap();

    let by_id = auth_flows::load_flow(&transaction, "flow-1")
        .await
        .unwrap()
        .expect("the flow was not found where it was written");
    assert_eq!(by_id.alias, "browser");
    assert_eq!(by_id.top_level, Some(true));

    let by_alias = auth_flows::flow_by_alias(&transaction, "browser")
        .await
        .unwrap()
        .expect("the alias found nothing");
    assert_eq!(by_alias.flow_id, "flow-1");

    // Only a flow a login may start at is offered as a starting point.
    let starts: Vec<String> = auth_flows::top_level_flows(&transaction)
        .await
        .unwrap()
        .into_iter()
        .map(|f| f.flow_id)
        .collect();
    assert_eq!(starts, vec!["flow-1".to_owned()]);
}

/// A step runs one thing, and the row cannot say otherwise.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_step_runs_an_authenticator_or_a_flow_and_comes_back_as_the_one_it_runs() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    auth_flows::create_flow(&transaction, &flow("flow-1", "browser", true))
        .await
        .unwrap();
    auth_flows::create_flow(&transaction, &flow("flow-2", "otp-conditional", false))
        .await
        .unwrap();
    auth_flows::create_config(
        &transaction,
        &AuthenticatorConfigMutationModel {
            alias: "otp-config".to_owned(),
            configs: None,
        }
        .into_model("config-1".to_owned(), "main".to_owned(), metadata()),
    )
    .await
    .unwrap();

    auth_flows::create_execution(
        &transaction,
        &step("exec-1", "flow-1", 10, authenticator("auth-cookie", None)),
    )
    .await
    .unwrap();
    auth_flows::create_execution(
        &transaction,
        &step(
            "exec-2",
            "flow-1",
            20,
            authenticator("auth-otp", Some("config-1")),
        ),
    )
    .await
    .unwrap();
    auth_flows::create_execution(
        &transaction,
        &step(
            "exec-3",
            "flow-1",
            30,
            ExecutionStep::SubFlow {
                flow_id: "flow-2".to_owned(),
            },
        ),
    )
    .await
    .unwrap();

    let steps = auth_flows::executions_of(&transaction, "flow-1")
        .await
        .unwrap();
    assert_eq!(steps.len(), 3);
    assert_eq!(
        steps.iter().map(|s| s.priority).collect::<Vec<_>>(),
        vec![10, 20, 30],
        "the steps did not come back in the order they run"
    );
    assert_eq!(
        steps[1].step,
        authenticator("auth-otp", Some("config-1")),
        "a step lost the settings it reads"
    );
    assert_eq!(
        steps[2].step.sub_flow(),
        Some("flow-2"),
        "a nested step did not name the flow it runs"
    );
    assert_eq!(steps[0].step.sub_flow(), None);
}

/// Two steps of one flow sharing a position would leave which runs first to
/// whichever row was read first.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn two_steps_of_one_flow_cannot_share_a_position() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    auth_flows::create_flow(&transaction, &flow("flow-1", "browser", true))
        .await
        .unwrap();
    auth_flows::create_execution(
        &transaction,
        &step("exec-1", "flow-1", 10, authenticator("auth-cookie", None)),
    )
    .await
    .unwrap();

    assert!(
        auth_flows::create_execution(
            &transaction,
            &step("exec-2", "flow-1", 10, authenticator("auth-otp", None)),
        )
        .await
        .is_err(),
        "two steps of one flow took the same position"
    );
}

/// A swap passes through a state where two steps share a position, which is why
/// the constraint is deferrable.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn two_steps_may_trade_positions_in_one_transaction() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    auth_flows::create_flow(&transaction, &flow("flow-1", "browser", true))
        .await
        .unwrap();
    auth_flows::create_execution(
        &transaction,
        &step("exec-1", "flow-1", 10, authenticator("auth-cookie", None)),
    )
    .await
    .unwrap();
    auth_flows::create_execution(
        &transaction,
        &step("exec-2", "flow-1", 20, authenticator("auth-otp", None)),
    )
    .await
    .unwrap();

    auth_flows::reorder(&transaction, &[("exec-1", 20), ("exec-2", 10)])
        .await
        .expect("a swap was refused halfway through");

    let order: Vec<String> = auth_flows::executions_of(&transaction, "flow-1")
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.execution_id)
        .collect();
    assert_eq!(order, vec!["exec-2".to_owned(), "exec-1".to_owned()]);
}

/// Written as raw statements, because the provider cannot express either wrong
/// state and a constraint nothing can reach is a constraint nobody checks.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_step_that_runs_both_or_neither_is_refused() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    auth_flows::create_flow(&transaction, &flow("flow-1", "browser", true))
        .await
        .unwrap();
    auth_flows::create_flow(&transaction, &flow("flow-2", "nested", false))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let cases = [
        (
            "NULL",
            "NULL",
            "NULL",
            "a step that runs nothing was recorded",
        ),
        (
            "'auth-otp'",
            "NULL",
            "'flow-2'",
            "a step that runs an authenticator and a flow was recorded",
        ),
        (
            "NULL",
            "'config-1'",
            "'flow-2'",
            "a nested step was given settings of its own",
        ),
        (
            "NULL",
            "NULL",
            "'flow-1'",
            "a flow was recorded as one of its own steps",
        ),
    ];

    for (index, (authenticator, config, sub_flow, what)) in cases.iter().enumerate() {
        let mut connection = fixture.connection().await;
        let transaction = fixture
            .scoped(&mut connection, &TenantContext::new("acme", "main"))
            .await;
        let statement = format!(
            "INSERT INTO authentication_executions \
                 (tenant, realm_id, execution_id, alias, flow_id, priority, requirement, \
                  authenticator, config_id, sub_flow_id) \
             VALUES ('acme', 'main', 'bad-{index}', 'bad', 'flow-1', {index}, 'required', \
                     {authenticator}, {config}, {sub_flow})"
        );
        let refused = transaction.execute(statement.as_str(), &[]).await.is_err();
        drop(transaction);
        drop(connection);
        assert!(refused, "{what}");
    }
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_asks_for_the_actions_it_registered_as_default() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    for (id, action, default, priority) in [
        ("action-1", RequiredAction::VerifyEmail, true, 20),
        ("action-2", RequiredAction::ConfigureTotp, true, 10),
        ("action-3", RequiredAction::UpdatePassword, false, 5),
    ] {
        auth_flows::register_action(
            &transaction,
            &RequiredActionMutationModel {
                provider_id: format!("{id}-provider"),
                action,
                name: id.to_owned(),
                display_name: id.to_owned(),
                description: String::new(),
                enabled: Some(true),
                default_action: Some(default),
                on_time_action: Some(false),
                priority: Some(priority),
            }
            .into_model(id.to_owned(), "main".to_owned(), metadata()),
        )
        .await
        .unwrap();
    }

    let asked: Vec<RequiredAction> = auth_flows::default_actions(&transaction)
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.action)
        .collect();
    assert_eq!(
        asked,
        vec![RequiredAction::ConfigureTotp, RequiredAction::VerifyEmail],
        "the default actions are the ones marked default, in the order they are asked"
    );
}

/// One registration per action, or the realm asks for it twice.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_action_is_registered_once() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    for id in ["action-1", "action-2"] {
        let registered = auth_flows::register_action(
            &transaction,
            &RequiredActionMutationModel {
                provider_id: "verify-email-provider".to_owned(),
                action: RequiredAction::VerifyEmail,
                name: id.to_owned(),
                display_name: id.to_owned(),
                description: String::new(),
                enabled: Some(true),
                default_action: Some(true),
                on_time_action: Some(false),
                priority: Some(0),
            }
            .into_model(id.to_owned(), "main".to_owned(), metadata()),
        )
        .await;

        if id == "action-2" {
            assert!(
                registered.is_err(),
                "one action was registered twice in one realm"
            );
        } else {
            registered.unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn removing_a_flow_takes_its_steps() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    auth_flows::create_flow(&transaction, &flow("flow-1", "browser", true))
        .await
        .unwrap();
    auth_flows::create_execution(
        &transaction,
        &step("exec-1", "flow-1", 10, authenticator("auth-cookie", None)),
    )
    .await
    .unwrap();

    assert!(
        auth_flows::delete_flow(&transaction, "flow-1")
            .await
            .unwrap()
    );
    assert!(
        auth_flows::executions_of(&transaction, "flow-1")
            .await
            .unwrap()
            .is_empty(),
        "a step outlived the flow it belonged to"
    );
    assert!(
        !auth_flows::delete_flow(&transaction, "flow-1")
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_flow_is_not_visible_from_another_realm() {
    let fixture = Fixture::with_user().await;
    second_realm(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    auth_flows::create_flow(&transaction, &flow("flow-1", "browser", true))
        .await
        .unwrap();
    auth_flows::create_execution(
        &transaction,
        &step("exec-1", "flow-1", 10, authenticator("auth-cookie", None)),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    assert!(
        auth_flows::load_flow(&transaction, "flow-1")
            .await
            .unwrap()
            .is_none(),
        "another realm of the same tenant read the flow"
    );
    assert!(
        auth_flows::flow_by_alias(&transaction, "browser")
            .await
            .unwrap()
            .is_none(),
        "another realm found the flow by its alias"
    );
    assert!(
        auth_flows::executions_of(&transaction, "flow-1")
            .await
            .unwrap()
            .is_empty(),
        "another realm read the steps"
    );
    assert!(
        auth_flows::top_level_flows(&transaction)
            .await
            .unwrap()
            .is_empty(),
        "another realm was offered the flow as a starting point"
    );
}
