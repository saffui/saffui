//! Agents, administered: a client with a capability root and a service
//! account, born whole in one transaction or not at all.
//!
//! Keyless by default, deliberately: an agent authenticates through its
//! platform (the jwt-bearer rails), so the resting registration stores no
//! credential anywhere. A secret exists only where the operator asked for
//! one, drawn on the server and handed back exactly once.

use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::attributes::AttributeValue;
use models::entities::client::{ClientCreateModel, ClientModel, Protocol};
use models::entities::user::UserCreateModel;
use store::providers::{clients, users};

use crate::capability;

/// How many tools one root may name. Past this, a root is a directory,
/// and a directory is what scopes are for.
const MOST_CAPABILITIES: usize = 100;

/// The agent session ceiling an operator may write: a day. The realm's
/// access lifespan still caps every minted token below it.
const LONGEST_SESSION: i32 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("a client with this identifier already exists")]
    AlreadyExists,
    #[error("no agent answers to this identifier")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
    #[error("the store could not be written")]
    Unwritable,
}

fn invalid(said: impl Into<String>) -> Refused {
    Refused::Invalid(said.into())
}

/// Every rule the root must hold, said once for both doors: each entry
/// well-formed in the reader's own grammar, deduplicated, bounded.
fn checked_root(entries: &[String]) -> Result<Vec<String>, Refused> {
    let mut kept: Vec<String> = Vec::new();
    for held in entries {
        capability::well_formed(held).map_err(|why| invalid(format!("`{held}`: {why}")))?;
        if !kept.iter().any(|known| known == held) {
            kept.push(held.clone());
        }
    }
    if kept.is_empty() {
        return Err(invalid(
            "an agent names at least one capability; an agent that may do nothing is not one",
        ));
    }
    if kept.len() > MOST_CAPABILITIES {
        return Err(invalid(format!(
            "a root names at most {MOST_CAPABILITIES} capabilities"
        )));
    }
    Ok(kept)
}

fn checked_session(seconds: Option<i32>) -> Result<Option<i32>, Refused> {
    match seconds {
        Some(held) if !(1..=LONGEST_SESSION).contains(&held) => Err(invalid(format!(
            "an agent session runs from 1 to {LONGEST_SESSION} seconds"
        ))),
        other => Ok(other),
    }
}

/// What one registered agent looks like to whoever asked.
#[derive(Debug, serde::Serialize)]
pub struct AgentBrief {
    pub client_id: String,
    pub name: String,
    pub enabled: bool,
    pub capabilities: Vec<String>,
    pub session_seconds: Option<i32>,
    /// Whether a client secret exists at all. Its value is never here.
    pub keyed: bool,
    /// The instant every earlier token was cut, when one was.
    pub not_before: Option<i32>,
}

fn brief_of(client: &ClientModel) -> Option<AgentBrief> {
    let bag = client.configs.as_ref()?;
    let root = bag
        .get(crate::grant::AGENT_CAPABILITIES)?
        .as_str()?
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    Some(AgentBrief {
        client_id: client.client_id.clone(),
        name: client.name.clone(),
        enabled: client.enabled != Some(false),
        capabilities: root,
        session_seconds: bag
            .get(crate::grant::AGENT_SESSION_SECONDS)
            .and_then(AttributeValue::as_str)
            .and_then(|held| held.trim().parse().ok()),
        keyed: client.secret.is_some(),
        not_before: client.not_before,
    })
}

/// Register an agent: the client, its capability root, and its service
/// account, in this one transaction. No secret is stored: the platform is
/// the credential, and a caller that wants one asks the secret rotation
/// door afterwards, eyes open.
#[allow(
    clippy::too_many_arguments,
    reason = "a birth names everything it writes, once, in one signature"
)]
pub async fn register(
    transaction: &Transaction<'_>,
    provider: &dyn crypto::provider::CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    client_id: &str,
    capabilities: &[String],
    session_seconds: Option<i32>,
) -> Result<AgentBrief, Refused> {
    let root = checked_root(capabilities)?;
    let session = checked_session(session_seconds)?;
    if client_id.trim().is_empty() || client_id.len() > 200 {
        return Err(invalid("an agent's identifier is 1 to 200 characters"));
    }
    if clients::load(transaction, client_id)
        .await
        .map_err(|_| Refused::Unwritable)?
        .is_some()
    {
        return Err(Refused::AlreadyExists);
    }

    let metadata = AuditableModel::from_creator(tenant.to_owned(), by.to_owned());
    let mut client = ClientCreateModel {
        name: client_id.to_owned(),
        display_name: client_id.to_owned(),
        description: "An AI agent".to_owned(),
        enabled: Some(true),
    }
    .into_model(client_id.to_owned(), realm_id.to_owned(), metadata.clone());
    client.protocol = Some(Protocol::OpenId);
    // Confidential with no stored credential: nobody authenticates *as*
    // this client at the token endpoint; its platform vouches for it and
    // the exchange takes it from there.
    client.public_client = Some(false);
    client.service_account_enabled = Some(true);
    client.standard_flow_enabled = Some(false);
    client.direct_access_grants_enabled = Some(false);
    client.implicit_flow_enabled = Some(false);
    let bag = client.configs.get_or_insert_with(Default::default);
    bag.insert(
        "token.exchange.enabled".to_owned(),
        AttributeValue::Bool(true),
    );
    bag.insert(
        crate::grant::AGENT_CAPABILITIES.to_owned(),
        AttributeValue::Str(root.join(" ")),
    );
    if let Some(seconds) = session {
        bag.insert(
            crate::grant::AGENT_SESSION_SECONDS.to_owned(),
            AttributeValue::Str(seconds.to_string()),
        );
    }
    clients::create(transaction, &client)
        .await
        .map_err(|_| Refused::Unwritable)?;
    clients::update(transaction, &client)
        .await
        .map_err(|_| Refused::Unwritable)?;

    // The account the agent acts as, tied by the link and not by a name, so
    // renaming it never points the client at somebody else.
    let identity = crypto::provider::uuid_from({
        let mut drawn = [0_u8; 16];
        provider
            .rand()
            .fill(&mut drawn)
            .map_err(|_| Refused::Unwritable)?;
        drawn
    });
    let mut account = UserCreateModel {
        user_name: format!("service-account-{client_id}"),
        enabled: true,
        email: String::new(),
        email_verified: None,
        phone_number: None,
        phone_number_verified: None,
        required_actions: None,
        not_before: None,
        user_storage: None,
        attributes: None,
        is_service_account: Some(true),
        service_account_client_link: Some(client_id.to_owned()),
    }
    .into_model(identity, realm_id.to_owned(), metadata);
    account.email_verified = Some(false);
    users::create(transaction, &account)
        .await
        .map_err(|_| Refused::Unwritable)?;

    brief_of(&client).ok_or(Refused::Unwritable)
}

/// Every agent this realm holds: the clients whose bag names a root.
pub async fn list(transaction: &Transaction<'_>) -> Result<Vec<AgentBrief>, Refused> {
    let query = store::query::list_query::ListQuery::new(models::paging::Window {
        first: 0,
        max: 1000,
        clamped: false,
    });
    let held = clients::list(transaction, &query, false)
        .await
        .map_err(|_| Refused::Unwritable)?;
    Ok(held.items.iter().filter_map(brief_of).collect())
}

pub async fn get(transaction: &Transaction<'_>, client_id: &str) -> Result<AgentBrief, Refused> {
    clients::load(transaction, client_id)
        .await
        .map_err(|_| Refused::Unwritable)?
        .as_ref()
        .and_then(brief_of)
        .ok_or(Refused::NotFound)
}

/// Reshape the root and the span: additions and removals named one by one,
/// validated before anything is written, and a removal that would empty
/// the root refuses whole rather than leaving an agent that is not one.
pub async fn reshape(
    transaction: &Transaction<'_>,
    client_id: &str,
    add: &[String],
    remove: &[String],
    session_seconds: Option<i32>,
) -> Result<AgentBrief, Refused> {
    let mut client = clients::load(transaction, client_id)
        .await
        .map_err(|_| Refused::Unwritable)?
        .ok_or(Refused::NotFound)?;
    let Some(current) = brief_of(&client) else {
        return Err(Refused::NotFound);
    };
    for held in add.iter().chain(remove) {
        capability::well_formed(held).map_err(|why| invalid(format!("`{held}`: {why}")))?;
    }
    let mut root = current.capabilities.clone();
    root.retain(|held| !remove.contains(held));
    for held in add {
        if !root.iter().any(|known| known == held) {
            root.push(held.clone());
        }
    }
    if root.is_empty() {
        return Err(invalid(
            "the removal would leave no capability: revoke or disable the client instead",
        ));
    }
    let root = checked_root(&root)?;
    let session = checked_session(session_seconds)?;

    let bag = client.configs.get_or_insert_with(Default::default);
    bag.insert(
        crate::grant::AGENT_CAPABILITIES.to_owned(),
        AttributeValue::Str(root.join(" ")),
    );
    if let Some(seconds) = session {
        bag.insert(
            crate::grant::AGENT_SESSION_SECONDS.to_owned(),
            AttributeValue::Str(seconds.to_string()),
        );
    }
    clients::update(transaction, &client)
        .await
        .map_err(|_| Refused::Unwritable)?;
    get(transaction, client_id).await
}
