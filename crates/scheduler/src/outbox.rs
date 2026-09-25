//! One realm's outbox pass: each due telling handed to every listener, and put
//! away once all of them took it.

use config::serving::Egress;
use outbound::Sealing;
use outbound::pushes::{opened_bearer, opened_webhook_secret, push_json, push_one, push_set};
use services::messaging::outbox;
use store::tenancy::UnitOfWork;

pub struct Told {
    pub delivered: u64,
    pub failed: u64,
    pub dead: u64,
}

const DELIVERY_CEILING: i64 = 50;
const DEAD_AFTER: i32 = 8;

/// One realm's outbox pass: each due telling goes to every connector, and a
/// telling only counts delivered when every connector took it.
pub async fn deliver_outbox(
    transaction: &UnitOfWork,
    sealing: &Sealing,
    origin: &config::serving::PublicOrigin,
    context: &store::tenancy::TenantContext,
    egress: Egress,
    backoff_seconds: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Told, ()> {
    let mut told = Told {
        delivered: 0,
        failed: 0,
        dead: 0,
    };
    let listeners = outbox::read_listeners(transaction).await.map_err(|_| ())?;
    // The realm's keys, only when somebody is listening for signed events.
    let ring = if listeners.receivers.is_empty() {
        None
    } else {
        store::keyring::load(
            transaction,
            &sealing.envelope,
            &context.tenant,
            &context.realm_id,
        )
        .await
        .ok()
    };
    let issuer = origin.issuer(&context.realm_id);

    let due = outbox::read_due_events(transaction, DELIVERY_CEILING, backoff_seconds)
        .await
        .map_err(|_| ())?;
    for event in due {
        // A change to how someone signs in owes them a notice, settled apart from
        // this telling: noted once, however often the telling is retried.
        services::messaging::notices::note_owed_notice(transaction, &event)
            .await
            .map_err(|_| ())?;
        // The lifecycle converges before anything leaves the house: the
        // provisioned apps should see the person as the rules already made
        // them.
        if services::governance::lifecycle::converge_event(transaction, &event)
            .await
            .is_err()
        {
            told.failed += 1;
            continue;
        }
        // Nobody to tell is a telling done, not one to retry forever: with
        // no push attempted, `landed` stays true and the event is put away.
        let mut landed = true;
        if let Some((uri, body)) =
            services::messaging::caep::security_event(&event.kind, &event.payload)
        {
            for (row, receiver) in &listeners.receivers {
                if !receiver.wants(uri) {
                    continue;
                }
                let minted = match &ring {
                    Some(ring) => services::messaging::caep::minted_set(
                        transaction,
                        &services::oidc::grant::Signing {
                            provider: sealing.provider.as_ref(),
                            ring,
                            envelope: &sealing.envelope,
                        },
                        &issuer,
                        receiver,
                        &event,
                        uri,
                        body.clone(),
                        now,
                    )
                    .await
                    .ok(),
                    None => None,
                };
                let Some(set) = minted else {
                    landed = false;
                    continue;
                };
                match receiver.delivery {
                    // A collector's tokens wait here; queueing is delivery.
                    services::messaging::caep::Delivery::Poll => {
                        if services::messaging::caep::queue_set(transaction, &row.internal_id, &set)
                            .await
                            .is_err()
                        {
                            landed = false;
                        }
                    }
                    services::messaging::caep::Delivery::Push => {
                        let bearer = opened_bearer(transaction, sealing, context, row).await;
                        if !push_set(receiver, bearer.as_deref(), &set.token, egress).await {
                            landed = false;
                        }
                    }
                }
            }
        }
        // The connectors speak person; a session or credential happening is
        // not theirs to provision.
        if event.kind.starts_with("user.") {
            for (row, connector) in &listeners.connectors {
                let bearer = opened_bearer(transaction, sealing, context, row).await;
                if !push_one(connector, bearer.as_deref(), &event, egress).await {
                    landed = false;
                }
            }
        }
        // The webhooks take every kind their filter admits, as one signed
        // JSON body: the signature covers these exact bytes, so the body is
        // rendered once and rides verbatim.
        if listeners
            .webhooks
            .iter()
            .any(|(_, hook)| hook.wants(&event.kind))
        {
            let body = serde_json::json!({
                "event_id": event.event_id,
                "kind": event.kind,
                "realm": context.realm_id,
                "user_id": event.user_id,
                "occurred_at": event.occurred_at.to_rfc3339(),
                "payload": event.payload,
            })
            .to_string();
            for (row, hook) in &listeners.webhooks {
                if !hook.wants(&event.kind) {
                    continue;
                }
                let signed = opened_webhook_secret(transaction, sealing, context, row)
                    .await
                    .and_then(|secret| {
                        services::messaging::webhook::signature(
                            sealing.provider.as_ref(),
                            &secret,
                            body.as_bytes(),
                        )
                    });
                let Some(signature) = signed else {
                    landed = false;
                    continue;
                };
                if !push_json(
                    hook,
                    &signature,
                    &event.kind,
                    event.event_id,
                    body.clone(),
                    egress,
                )
                .await
                {
                    landed = false;
                }
            }
        }
        if landed {
            outbox::mark_delivered(transaction, event.event_id)
                .await
                .map_err(|_| ())?;
            told.delivered += 1;
        } else if event.attempts >= DEAD_AFTER {
            outbox::mark_dead(transaction, event.event_id)
                .await
                .map_err(|_| ())?;
            told.dead += 1;
            tracing::warn!(
                event = event.event_id,
                kind = event.kind,
                "a telling was given up on; it stays visible as dead"
            );
        } else {
            told.failed += 1;
        }
    }
    Ok(told)
}
