use deadpool_postgres::Transaction;
use models::entities::auth::{
    AuthenticationExecutionModel, AuthenticationFlowModel, AuthenticatorConfigModel,
    AuthenticatorRequirement, ExecutionStep, RequiredActionModel,
};
use models::entities::user::RequiredAction;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const FLOW_COLUMNS: &str = "tenant, realm_id, flow_id, alias, provider_id, description, \
                            top_level, built_in, created_by, created_at, updated_by, \
                            updated_at, version";

const EXECUTION_COLUMNS: &str = "tenant, realm_id, execution_id, alias, flow_id, priority, \
                                 requirement, authenticator, config_id, sub_flow_id, \
                                 created_by, created_at, updated_by, updated_at, version";

const CONFIG_COLUMNS: &str = "tenant, realm_id, config_id, alias, configs, created_by, \
                              created_at, updated_by, updated_at, version";

const ACTION_COLUMNS: &str = "tenant, realm_id, action_id, action, provider_id, name, \
                              display_name, description, enabled, default_action, \
                              on_time_action, priority, created_by, created_at, updated_by, \
                              updated_at, version";

/// Record a flow.
pub async fn create_flow(
    transaction: &Transaction<'_>,
    flow: &AuthenticationFlowModel,
) -> StoreResult<()> {
    // Bound to locals: the write set holds references, and a temporary made in
    // the list dies at the end of the statement that built it.
    let top_level = flow.top_level.unwrap_or(false);
    let built_in = flow.built_in.unwrap_or(false);

    let set = WriteSet::insert(vec![
        col("tenant", &flow.metadata.tenant),
        col("realm_id", &flow.realm_id),
        col("flow_id", &flow.flow_id),
        col("alias", &flow.alias),
        col("provider_id", &flow.provider_id),
        col("description", &flow.description),
        col("top_level", &top_level),
        col("built_in", &built_in),
        col("created_by", &flow.metadata.created_by),
    ]);

    transaction
        .execute(
            statement::insert("authentication_flows", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One flow of this realm, by the identifier it was created with.
pub async fn load_flow(
    transaction: &Transaction<'_>,
    flow_id: &str,
) -> StoreResult<Option<AuthenticationFlowModel>> {
    let statement = format!("SELECT {FLOW_COLUMNS} FROM authentication_flows WHERE flow_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&flow_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_flow))
}

/// One flow of this realm, by the name an admin gave it.
pub async fn flow_by_alias(
    transaction: &Transaction<'_>,
    alias: &str,
) -> StoreResult<Option<AuthenticationFlowModel>> {
    let statement = format!("SELECT {FLOW_COLUMNS} FROM authentication_flows WHERE alias = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&alias])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_flow))
}

/// The flows a login may start at.
pub async fn top_level_flows(
    transaction: &Transaction<'_>,
) -> StoreResult<Vec<AuthenticationFlowModel>> {
    let statement = format!(
        "SELECT {FLOW_COLUMNS} FROM authentication_flows \
         WHERE top_level ORDER BY alias ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_flow)
        .collect())
}

/// Remove a flow, and say whether there was one to remove.
pub async fn delete_flow(transaction: &Transaction<'_>, flow_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM authentication_flows WHERE flow_id = $1",
            &[&flow_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Record a step.
pub async fn create_execution(
    transaction: &Transaction<'_>,
    execution: &AuthenticationExecutionModel,
) -> StoreResult<()> {
    // Exactly one of the two is written, which is what the schema checks.
    let (authenticator, config_id, sub_flow_id) = match &execution.step {
        ExecutionStep::Authenticator {
            authenticator,
            config_id,
        } => (Some(authenticator.clone()), config_id.clone(), None),
        ExecutionStep::SubFlow { flow_id } => (None, None, Some(flow_id.clone())),
    };

    let set = WriteSet::insert(vec![
        col("tenant", &execution.metadata.tenant),
        col("realm_id", &execution.realm_id),
        col("execution_id", &execution.execution_id),
        col("alias", &execution.alias),
        col("flow_id", &execution.flow_id),
        col("priority", &execution.priority),
        col("requirement", &execution.requirement),
        col("authenticator", &authenticator),
        col("config_id", &config_id),
        col("sub_flow_id", &sub_flow_id),
        col("created_by", &execution.metadata.created_by),
    ]);

    transaction
        .execute(
            statement::insert("authentication_executions", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The steps of one flow, in the order they run.
///
/// The order is stated rather than left to the plan: it decides which
/// authenticator a user meets first.
/// Change what one step costs the flow.
pub async fn set_requirement(
    transaction: &Transaction<'_>,
    execution_id: &str,
    requirement: AuthenticatorRequirement,
) -> StoreResult<bool> {
    let changed = transaction
        .execute(
            "UPDATE authentication_executions SET requirement = $2 WHERE execution_id = $1",
            &[&execution_id, &requirement],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

pub async fn executions_of(
    transaction: &Transaction<'_>,
    flow_id: &str,
) -> StoreResult<Vec<AuthenticationExecutionModel>> {
    let statement = format!(
        "SELECT {EXECUTION_COLUMNS} FROM authentication_executions \
         WHERE flow_id = $1 ORDER BY priority ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[&flow_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_execution)
        .collect())
}

/// Move a step to a position, freeing the position it leaves.
///
/// The unique constraint on the position is deferred for the statement, because
/// a swap passes through a state where two steps share one position and comes
/// out of it in the same transaction.
pub async fn reorder(transaction: &Transaction<'_>, moves: &[(&str, i32)]) -> StoreResult<()> {
    transaction
        .execute("SET CONSTRAINTS one_step_per_position DEFERRED", &[])
        .await
        .map_err(|_| StoreError::Backend)?;

    for (execution_id, priority) in moves {
        transaction
            .execute(
                "UPDATE authentication_executions SET priority = $2, updated_at = now() \
                 WHERE execution_id = $1",
                &[execution_id, priority],
            )
            .await
            .map_err(|_| StoreError::Backend)?;
    }
    Ok(())
}

/// Record a configuration.
pub async fn create_config(
    transaction: &Transaction<'_>,
    config: &AuthenticatorConfigModel,
) -> StoreResult<()> {
    let configs = config
        .configs
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)?;

    let set = WriteSet::insert(vec![
        col("tenant", &config.metadata.tenant),
        col("realm_id", &config.realm_id),
        col("config_id", &config.config_id),
        col("alias", &config.alias),
        col("configs", &configs),
        col("created_by", &config.metadata.created_by),
    ]);

    transaction
        .execute(
            statement::insert("authenticator_configs", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One configuration of this realm.
pub async fn load_config(
    transaction: &Transaction<'_>,
    config_id: &str,
) -> StoreResult<Option<AuthenticatorConfigModel>> {
    let statement =
        format!("SELECT {CONFIG_COLUMNS} FROM authenticator_configs WHERE config_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&config_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_config))
}

/// Register an action a realm may ask a user for.
pub async fn register_action(
    transaction: &Transaction<'_>,
    action: &RequiredActionModel,
) -> StoreResult<()> {
    let enabled = action.enabled.unwrap_or(true);
    let default_action = action.default_action.unwrap_or(false);
    let on_time_action = action.on_time_action.unwrap_or(false);
    let priority = action.priority.unwrap_or(0);

    let set = WriteSet::insert(vec![
        col("tenant", &action.metadata.tenant),
        col("realm_id", &action.realm_id),
        col("action_id", &action.action_id),
        col("action", &action.action),
        col("provider_id", &action.provider_id),
        col("name", &action.name),
        col("display_name", &action.display_name),
        col("description", &action.description),
        col("enabled", &enabled),
        col("default_action", &default_action),
        col("on_time_action", &on_time_action),
        col("priority", &priority),
        col("created_by", &action.metadata.created_by),
    ]);

    transaction
        .execute(
            statement::insert("required_actions", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The actions a new user of this realm is given, in the order they are asked.
pub async fn default_actions(
    transaction: &Transaction<'_>,
) -> StoreResult<Vec<RequiredActionModel>> {
    let statement = format!(
        "SELECT {ACTION_COLUMNS} FROM required_actions \
         WHERE default_action AND enabled ORDER BY priority ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_action)
        .collect())
}

fn read_flow(row: Row) -> AuthenticationFlowModel {
    AuthenticationFlowModel {
        flow_id: row.get("flow_id"),
        realm_id: row.get("realm_id"),
        alias: row.get("alias"),
        provider_id: row.get("provider_id"),
        description: row.get("description"),
        top_level: Some(row.get("top_level")),
        built_in: Some(row.get("built_in")),
        metadata: audit(&row),
    }
}

/// The row says which kind by which column it filled, and the schema is what
/// guarantees it filled exactly one.
fn read_execution(row: Row) -> AuthenticationExecutionModel {
    let step = match row.get::<_, Option<String>>("sub_flow_id") {
        Some(flow_id) => ExecutionStep::SubFlow { flow_id },
        None => ExecutionStep::Authenticator {
            authenticator: row.get("authenticator"),
            config_id: row.get("config_id"),
        },
    };

    AuthenticationExecutionModel {
        execution_id: row.get("execution_id"),
        realm_id: row.get("realm_id"),
        alias: row.get("alias"),
        flow_id: row.get("flow_id"),
        priority: row.get("priority"),
        step,
        requirement: row.get::<_, AuthenticatorRequirement>("requirement"),
        metadata: audit(&row),
    }
}

fn read_config(row: Row) -> AuthenticatorConfigModel {
    AuthenticatorConfigModel {
        config_id: row.get("config_id"),
        realm_id: row.get("realm_id"),
        alias: row.get("alias"),
        configs: row
            .get::<_, Option<serde_json::Value>>("configs")
            .and_then(|value| serde_json::from_value(value).ok()),
        metadata: audit(&row),
    }
}

fn read_action(row: Row) -> RequiredActionModel {
    RequiredActionModel {
        action_id: row.get("action_id"),
        realm_id: row.get("realm_id"),
        provider_id: row.get("provider_id"),
        action: row.get::<_, RequiredAction>("action"),
        name: row.get("name"),
        display_name: row.get("display_name"),
        description: row.get("description"),
        enabled: Some(row.get("enabled")),
        default_action: Some(row.get("default_action")),
        on_time_action: Some(row.get("on_time_action")),
        priority: Some(row.get("priority")),
        metadata: audit(&row),
    }
}

fn audit(row: &Row) -> models::auditable::AuditableModel {
    models::auditable::AuditableModel {
        tenant: row.get("tenant"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
        updated_by: row.get("updated_by"),
        updated_at: row.get("updated_at"),
        version: row.get("version"),
    }
}
