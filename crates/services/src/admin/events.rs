//! What happened in a realm, as the console reads it: the sign-in log, the
//! committed events after a cursor, the tellings given up on, and a replay of
//! retained ones to one webhook.

use models::entities::authz::IdentityProviderModel;
use store::providers::events::login_events::{self, LoginEvent};
use store::providers::events::outbox::{self, OutboxEvent};
use store::providers::federation::brokering;
use store::tenancy::UnitOfWork;

use crate::messaging::webhook::Webhook;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unevented {
    #[error("no connector answers to that alias")]
    NoSuchConnector,
    /// In words the administrator is meant to read.
    #[error("{0}")]
    Invalid(&'static str),
    #[error("the store could not be read or written")]
    Backend,
}

/// The retained tellings a replay to one webhook carries: at most the
/// ceiling asked for, filtered to the kinds it wants, with the last one kept
/// and whether the range held more.
#[derive(Debug, Clone)]
pub struct Replay {
    pub events: Vec<OutboxEvent>,
    pub stopped_at: Option<i64>,
    pub more: bool,
}

/// One page of the sign-in log, and its total when counting was asked for.
pub async fn list_sign_ins(
    transaction: &UnitOfWork,
    first: i64,
    max: i64,
    count: bool,
) -> Result<(Vec<LoginEvent>, Option<i64>), Unevented> {
    login_events::list(transaction, first, max, count)
        .await
        .map_err(|_| Unevented::Backend)
}

/// Committed events after a consumer's cursor, whatever their delivery.
pub async fn events_after(
    transaction: &UnitOfWork,
    last_event_id: i64,
    limit: i64,
) -> Result<Vec<OutboxEvent>, Unevented> {
    outbox::list_events_after_id(transaction, last_event_id, limit)
        .await
        .map_err(|_| Unevented::Backend)
}

/// Every telling given up on, newest first.
pub async fn dead_letters(
    transaction: &UnitOfWork,
    limit: i64,
) -> Result<Vec<OutboxEvent>, Unevented> {
    outbox::dead_list(transaction, limit)
        .await
        .map_err(|_| Unevented::Backend)
}

/// Put one dead telling back in the queue, due at once.
pub async fn requeue_dead_letter(transaction: &UnitOfWork, event_id: i64) -> Result<(), Unevented> {
    outbox::requeue(transaction, event_id)
        .await
        .map_err(|_| Unevented::Backend)?
        .then_some(())
        .ok_or(Unevented::Invalid("no dead telling answers to this id"))
}

/// The one connector a replay goes to: it must exist, be switched on, and be
/// a webhook.
pub async fn webhook_to_replay(
    transaction: &UnitOfWork,
    alias: &str,
) -> Result<(IdentityProviderModel, Webhook), Unevented> {
    let row = brokering::provider_by_alias(transaction, alias)
        .await
        .map_err(|_| Unevented::Backend)?
        .ok_or(Unevented::NoSuchConnector)?;
    if row.enabled == Some(false) {
        return Err(Unevented::Invalid("the connector is disabled"));
    }
    let hook =
        Webhook::parse(&row).map_err(|_| Unevented::Invalid("only a webhook takes a replay"))?;
    Ok((row, hook))
}

/// The retained range from `from` to `to`, at most `ceiling` of it, kept to
/// what this webhook wants.
pub async fn plan_replay(
    transaction: &UnitOfWork,
    hook: &Webhook,
    from: i64,
    to: Option<i64>,
    ceiling: i64,
) -> Result<Replay, Unevented> {
    let held = outbox::retained(transaction, from, to, ceiling + 1)
        .await
        .map_err(|_| Unevented::Backend)?;
    let more = held.len() as i64 > ceiling;
    let events: Vec<OutboxEvent> = held
        .into_iter()
        .take(ceiling as usize)
        .filter(|event| hook.wants(&event.kind))
        .collect();
    let stopped_at = events.last().map(|event| event.event_id);
    Ok(Replay {
        events,
        stopped_at,
        more,
    })
}
