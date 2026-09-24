//! The outbox's side of a telling: who listens for it, which tellings are due,
//! and how each is put away once tried.

use models::entities::authz::IdentityProviderModel;
use store::providers::events::outbox;
pub use store::providers::events::outbox::{OutboxEvent, USER_DELETED};
use store::providers::federation::brokering;
use store::tenancy::UnitOfWork;

use super::caep::{self, Receiver};
use super::webhook::{self, Webhook};
use crate::scim::outbound::{self, Connector};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the outbox could not be read or written")]
pub struct Unkept;

/// Everybody a telling may go to, each beside the row it was read from:
/// switched on, and still reading as what it is.
pub struct Listeners {
    pub connectors: Vec<(IdentityProviderModel, Connector)>,
    pub receivers: Vec<(IdentityProviderModel, Receiver)>,
    pub webhooks: Vec<(IdentityProviderModel, Webhook)>,
}

pub async fn read_listeners(transaction: &UnitOfWork) -> Result<Listeners, Unkept> {
    let mut listeners = Listeners {
        connectors: Vec::new(),
        receivers: Vec::new(),
        webhooks: Vec::new(),
    };
    // One row is one kind at most: each kind is a value of the same key.
    for row in brokering::list_providers(transaction)
        .await
        .map_err(|_| Unkept)?
    {
        if row.enabled == Some(false) {
            continue;
        }
        if outbound::is_outbound(&row)
            && let Ok(connector) = Connector::parse(&row)
        {
            listeners.connectors.push((row, connector));
        } else if caep::is_receiver(&row)
            && let Ok(receiver) = Receiver::parse(&row)
        {
            listeners.receivers.push((row, receiver));
        } else if webhook::is_webhook(&row)
            && let Ok(hook) = Webhook::parse(&row)
        {
            listeners.webhooks.push((row, hook));
        }
    }
    Ok(listeners)
}

/// The tellings due now, oldest first and `ceiling` at most, claimed for this
/// pass: the next attempt moves out `backoff_seconds` before the work starts.
pub async fn read_due_events(
    transaction: &UnitOfWork,
    ceiling: i64,
    backoff_seconds: i64,
) -> Result<Vec<OutboxEvent>, Unkept> {
    outbox::due(transaction, ceiling, backoff_seconds)
        .await
        .map_err(|_| Unkept)
}

/// Put a telling away as delivered.
pub async fn mark_delivered(transaction: &UnitOfWork, event_id: i64) -> Result<(), Unkept> {
    outbox::delivered(transaction, event_id)
        .await
        .map_err(|_| Unkept)
}

/// Give a telling up, out loud: dead is a state an operator can see.
pub async fn mark_dead(transaction: &UnitOfWork, event_id: i64) -> Result<(), Unkept> {
    outbox::dead(transaction, event_id)
        .await
        .map_err(|_| Unkept)
}
