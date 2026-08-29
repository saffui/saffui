use std::str::FromStr;

use auth::login::authenticator::Authenticator;
use crypto::provider::CryptoProvider;
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::auth::{
    AuthenticationExecutionModel, AuthenticationExecutionMutationModel, AuthenticationFlowModel,
    AuthenticationFlowMutationModel, AuthenticatorRequirement, ExecutionStep, RequiredActionModel,
    RequiredActionMutationModel,
};
use models::entities::user::RequiredAction;
use store::providers::{auth_flows, users};

/// The alias every realm's browser login rests on when no client says
/// otherwise. Spelled in the authorize path; deleting the flow it names
/// would end every login of the realm.
const RESTING_FLOW: &str = "browser";

/// Why a flow, a step or an action could not be written. Verified before
/// writing, like the directory: the store underneath flattens every refusal
/// into a backend error.
#[derive(Debug, thiserror::Error)]
pub enum Unwritable {
    #[error("one with this alias already exists")]
    AlreadyExists,
    #[error("this action is already registered")]
    ActionExists,
    #[error("no such flow")]
    NotFound,
    #[error("no such execution")]
    NoSuchExecution,
    #[error("no such action")]
    NoSuchAction,
    #[error("no such user")]
    NoSuchUser,
    /// Deletion refused while a login would run it: the realm's resting
    /// flow, one a client is bound to, or the last step of such a flow.
    #[error("{0}")]
    StillRun(&'static str),
    #[error("{0}")]
    Invalid(String),
    #[error("the store could not be written")]
    Backend,
}

fn draw(provider: &dyn CryptoProvider, prefix: &str) -> Result<String, Unwritable> {
    let mut bytes = [0_u8; 16];
    provider
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Unwritable::Backend)?;
    Ok(format!("{prefix}-{}", BASE64URL_NOPAD.encode(&bytes)))
}

pub async fn flows(
    transaction: &Transaction<'_>,
) -> Result<Vec<AuthenticationFlowModel>, Unwritable> {
    auth_flows::top_level_flows(transaction)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn get_flow(
    transaction: &Transaction<'_>,
    flow_id: &str,
) -> Result<(AuthenticationFlowModel, Vec<AuthenticationExecutionModel>), Unwritable> {
    let flow = auth_flows::load_flow(transaction, flow_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)?;
    let steps = auth_flows::executions_of(transaction, flow_id)
        .await
        .map_err(|_| Unwritable::Backend)?;
    Ok((flow, steps))
}

pub async fn create_flow(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    mut asked: AuthenticationFlowMutationModel,
) -> Result<AuthenticationFlowModel, Unwritable> {
    if asked.alias.trim().is_empty() {
        return Err(Unwritable::Invalid("a flow answers to an alias".to_owned()));
    }
    if auth_flows::flow_by_alias(transaction, &asked.alias)
        .await
        .map_err(|_| Unwritable::Backend)?
        .is_some()
    {
        return Err(Unwritable::AlreadyExists);
    }
    // Built-in is the provisioner's word for what a deployment stands on; a
    // caller does not get to borrow it.
    asked.built_in = Some(false);
    let flow = asked.into_model(
        draw(provider, "flow")?,
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    auth_flows::create_flow(transaction, &flow)
        .await
        .map_err(|_| Unwritable::Backend)?;
    Ok(flow)
}

/// Whether a login runs this flow: it is the realm's resting one, or a
/// client is bound to its alias by name.
async fn still_run(transaction: &Transaction<'_>, alias: &str) -> Result<bool, Unwritable> {
    if alias == RESTING_FLOW {
        return Ok(true);
    }
    auth_flows::alias_bound_to_a_client(transaction, alias)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn delete_flow(transaction: &Transaction<'_>, flow_id: &str) -> Result<(), Unwritable> {
    let flow = auth_flows::load_flow(transaction, flow_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)?;
    if still_run(transaction, &flow.alias).await? {
        return Err(Unwritable::StillRun(
            "a login still runs this flow, so it is not deleted",
        ));
    }
    auth_flows::delete_flow(transaction, flow_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

pub async fn add_execution(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    flow_id: &str,
    mut asked: AuthenticationExecutionMutationModel,
) -> Result<AuthenticationExecutionModel, Unwritable> {
    auth_flows::load_flow(transaction, flow_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)?;
    // The path names the flow; a body naming another is not a second choice.
    asked.flow_id = flow_id.to_owned();

    match &asked.step {
        // The catalogue of authenticators lives in the build. Recording a
        // name nothing runs would configure a step every login then fails
        // on, which is worse than dead: it is load-bearing garbage.
        ExecutionStep::Authenticator { authenticator, .. } => {
            if Authenticator::from_str(authenticator).is_err() {
                return Err(Unwritable::Invalid(format!(
                    "no authenticator answers to {authenticator}; one of: password, totp, webauthn, magic-link"
                )));
            }
        }
        // A step that runs another flow has to name one that exists.
        ExecutionStep::SubFlow { flow_id: inner } => {
            if auth_flows::load_flow(transaction, inner)
                .await
                .map_err(|_| Unwritable::Backend)?
                .is_none()
            {
                return Err(Unwritable::Invalid(format!("no flow answers to {inner}")));
            }
        }
    }

    let step = asked.into_model(
        draw(provider, "exec")?,
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    auth_flows::create_execution(transaction, &step)
        .await
        .map_err(|_| Unwritable::Backend)?;
    Ok(step)
}

pub async fn set_requirement(
    transaction: &Transaction<'_>,
    execution_id: &str,
    requirement: AuthenticatorRequirement,
) -> Result<(), Unwritable> {
    auth_flows::set_requirement(transaction, execution_id, requirement)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NoSuchExecution)
}

pub async fn remove_execution(
    transaction: &Transaction<'_>,
    execution_id: &str,
) -> Result<(), Unwritable> {
    let step = auth_flows::load_execution(transaction, execution_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NoSuchExecution)?;
    // Taking the last step out of a flow a login runs leaves that login
    // nothing to run: every attempt would then fail on an empty flow.
    let flow = auth_flows::load_flow(transaction, &step.flow_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::Backend)?;
    let siblings = auth_flows::executions_of(transaction, &step.flow_id)
        .await
        .map_err(|_| Unwritable::Backend)?;
    if siblings.len() == 1 && still_run(transaction, &flow.alias).await? {
        return Err(Unwritable::StillRun(
            "the last step of a flow a login runs, so it is not removed",
        ));
    }
    auth_flows::delete_execution(transaction, execution_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NoSuchExecution)
}

pub async fn reorder(
    transaction: &Transaction<'_>,
    flow_id: &str,
    moves: &[(String, i32)],
) -> Result<(), Unwritable> {
    let steps = auth_flows::executions_of(transaction, flow_id)
        .await
        .map_err(|_| Unwritable::Backend)?;
    if steps.is_empty() {
        return Err(Unwritable::NotFound);
    }
    for (execution_id, _) in moves {
        if !steps.iter().any(|step| &step.execution_id == execution_id) {
            return Err(Unwritable::NoSuchExecution);
        }
    }
    let borrowed: Vec<(&str, i32)> = moves
        .iter()
        .map(|(execution_id, priority)| (execution_id.as_str(), *priority))
        .collect();
    auth_flows::reorder(transaction, &borrowed)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn actions(
    transaction: &Transaction<'_>,
) -> Result<Vec<RequiredActionModel>, Unwritable> {
    auth_flows::list_actions(transaction)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn register_action(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    asked: RequiredActionMutationModel,
) -> Result<RequiredActionModel, Unwritable> {
    if auth_flows::load_action(transaction, asked.action)
        .await
        .map_err(|_| Unwritable::Backend)?
        .is_some()
    {
        return Err(Unwritable::ActionExists);
    }
    let action = asked.into_model(
        draw(provider, "ra")?,
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    auth_flows::register_action(transaction, &action)
        .await
        .map_err(|_| Unwritable::Backend)?;
    Ok(action)
}

pub async fn rework_action(
    transaction: &Transaction<'_>,
    action: RequiredAction,
    by: &str,
    asked: RequiredActionMutationModel,
) -> Result<RequiredActionModel, Unwritable> {
    if asked.action != action {
        return Err(Unwritable::Invalid(
            "a registration answers for one action and does not change it".to_owned(),
        ));
    }
    let standing = auth_flows::load_action(transaction, action)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NoSuchAction)?;
    let mut rewritten = asked.into_model(
        standing.action_id.clone(),
        standing.realm_id.clone(),
        standing.metadata.clone(),
    );
    rewritten.metadata.updated_by = Some(by.to_owned());
    if !auth_flows::update_action(transaction, &rewritten)
        .await
        .map_err(|_| Unwritable::Backend)?
    {
        return Err(Unwritable::NoSuchAction);
    }
    auth_flows::load_action(transaction, action)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NoSuchAction)
}

pub async fn unregister_action(
    transaction: &Transaction<'_>,
    action: RequiredAction,
) -> Result<(), Unwritable> {
    let standing = auth_flows::load_action(transaction, action)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NoSuchAction)?;
    auth_flows::delete_action(transaction, &standing.action_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NoSuchAction)
}

/// Ask one more thing of a person at their next login.
pub async fn require_of_user(
    transaction: &Transaction<'_>,
    user_id: &str,
    action: RequiredAction,
) -> Result<(), Unwritable> {
    let mut person = users::load(transaction, user_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NoSuchUser)?;
    let held = person.required_actions.get_or_insert_with(Vec::new);
    if !held.contains(&action) {
        held.push(action);
        users::update(transaction, &person)
            .await
            .map_err(|_| Unwritable::Backend)?;
    }
    Ok(())
}

/// Stop asking. Clearing what was never asked changes nothing and is not an
/// error, which is also what the login's own clearing does.
pub async fn release_user(
    transaction: &Transaction<'_>,
    user_id: &str,
    action: RequiredAction,
) -> Result<(), Unwritable> {
    users::load(transaction, user_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NoSuchUser)?;
    users::clear_required_action(transaction, user_id, action)
        .await
        .map_err(|_| Unwritable::Backend)?;
    Ok(())
}
