//! The sign-in log, read side. Recording is the engine's, gated by the
//! realm's events_enabled switch; this only pages through what it kept.

use std::collections::{HashSet, VecDeque};

use actix_web::{HttpRequest, HttpResponse, ResponseError, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use models::paging::PagingParams;
use store::tenancy::{Tenancy, TenantContext};

use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

const LIVE_EVENTS_REPLAY_LIMIT: i64 = 500;

#[derive(serde::Deserialize)]
pub struct LiveEventsReplayQuery {
    pub after_event_id: Option<i64>,
    pub limit: Option<i64>,
}

fn live_events_replay_limit(asked: &LiveEventsReplayQuery) -> Result<i64, ApiError> {
    let limit = asked.limit.unwrap_or(100);
    if limit <= 0 {
        return Err(ApiError::new(ErrorCode::BadRequest));
    }
    Ok(limit.min(LIVE_EVENTS_REPLAY_LIMIT))
}

fn to_live_event_summary(
    tenant: &str,
    event: &store::providers::events::outbox::OutboxEvent,
) -> store::live::Told {
    store::live::Told {
        tenant: tenant.to_owned(),
        realm: event.realm_id.clone(),
        event_id: event.event_id,
        kind: event.kind.clone(),
        user_id: event.user_id.clone(),
        occurred_at: event.occurred_at.to_rfc3339(),
    }
}

pub async fn list_sign_ins(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    paging: web::Query<PagingParams>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let window = paging
        .window()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;

    let (events, total) = store::providers::events::login_events::list(
        &transaction,
        window.first,
        window.max,
        paging.count.unwrap_or(false),
    )
    .await
    .map_err(|_| ApiError::new(ErrorCode::InternalError))?;

    let items: Vec<_> = events
        .into_iter()
        .map(|held| {
            serde_json::json!({
                "id": held.id,
                "recorded_at": held.recorded_at,
                "kind": held.kind,
                "user_id": held.user_id,
                "client_id": held.client_id,
                "session_id": held.session_id,
                "ip": held.ip,
                "user_agent": held.user_agent,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": items,
        "first": window.first,
        "max": window.max,
        "total": total,
    })))
}

/// Read committed event summaries after a live consumer's cursor. Delivery
/// state is intentionally ignored: this is the console's event history, not
/// a connector replay.
pub async fn replay_live_events(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    query: web::Query<LiveEventsReplayQuery>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = query.into_inner();
    let last_event_id = asked.after_event_id.unwrap_or(0);
    if last_event_id < 0 {
        return Err(ApiError::new(ErrorCode::BadRequest));
    }
    let limit = live_events_replay_limit(&asked)?;
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let stored_events = store::providers::events::outbox::list_events_after_id(
        &transaction,
        last_event_id,
        limit + 1,
    )
    .await
    .map_err(|_| internal())?;
    let more = stored_events.len() as i64 > limit;
    let items: Vec<_> = stored_events
        .into_iter()
        .take(limit as usize)
        .map(|event| to_live_event_summary(&admin.context.tenant.tenant, &event))
        .collect();
    let next_event_id = items.last().map(|event| event.event_id);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": items,
        "next_event_id": next_event_id,
        "more": more,
    })))
}

/// The live feed: every committed emission of this realm, as it happens,
/// over Server-Sent Events. A reconnect replays retained summaries after the
/// client's last event id before returning to the broadcast feed.
pub async fn stream(
    admin: web::ReqData<Admin>,
    request: HttpRequest,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    feed: Option<web::Data<tokio::sync::broadcast::Sender<store::live::Told>>>,
) -> HttpResponse {
    let Some(feed) = feed else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({ "message": "this deployment runs no live feed" }));
    };
    let realm_id = path.into_inner();
    let tenant = admin.context.tenant.tenant.clone();
    let watching = feed.subscribe();
    let last_event_id = request
        .headers()
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 0)
        .unwrap_or(0);
    let mut replay_events = VecDeque::new();
    let mut has_more_replay_events = false;
    if last_event_id > 0 {
        let transaction = match tenancy.begin(&TenantContext::new(&tenant, &realm_id)).await {
            Ok(transaction) => transaction,
            Err(why) => return refuse_unopened_work(why).error_response(),
        };
        let Ok(stored_events) = store::providers::events::outbox::list_events_after_id(
            &transaction,
            last_event_id,
            LIVE_EVENTS_REPLAY_LIMIT + 1,
        )
        .await
        else {
            return HttpResponse::InternalServerError().finish();
        };
        has_more_replay_events = stored_events.len() as i64 > LIVE_EVENTS_REPLAY_LIMIT;
        replay_events.extend(
            stored_events
                .into_iter()
                .take(LIVE_EVENTS_REPLAY_LIMIT as usize)
                .map(|event| to_live_event_summary(&tenant, &event)),
        );
    }
    // The feed is subscribed before the store is read, so nothing committed
    // between the two is lost; what lands in both is said once, by the replay.
    let replayed: HashSet<i64> = replay_events.iter().map(|event| event.event_id).collect();
    let frames = futures_util::stream::unfold(
        (
            watching,
            tenant,
            realm_id,
            replay_events,
            has_more_replay_events,
            replayed,
        ),
        |(
            mut watching,
            tenant,
            realm_id,
            mut replay_events,
            has_more_replay_events,
            mut replayed,
        )| async move {
            loop {
                if let Some(event) = replay_events.pop_front() {
                    let body = serde_json::to_string(&event).unwrap_or_default();
                    let framed = format!(
                        "event: {}\nid: {}\ndata: {}\n\n",
                        event.kind, event.event_id, body
                    );
                    let bytes: Result<actix_web::web::Bytes, std::convert::Infallible> =
                        Ok(actix_web::web::Bytes::from(framed));
                    return Some((
                        bytes,
                        (
                            watching,
                            tenant,
                            realm_id,
                            replay_events,
                            has_more_replay_events,
                            replayed,
                        ),
                    ));
                }
                if has_more_replay_events {
                    return None;
                }
                let framed = tokio::select! {
                    told = watching.recv() => match told {
                        Ok(told) if told.tenant == tenant && told.realm == realm_id => {
                            if replayed.remove(&told.event_id) {
                                continue;
                            }
                            let body = serde_json::to_string(&told).unwrap_or_default();
                            format!("event: {}\nid: {}\ndata: {}\n\n", told.kind, told.event_id, body)
                        }
                        // Another realm's happening, or frames missed while
                        // lagging: nothing to say, keep listening.
                        Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                    },
                    // A quiet realm still proves the line is open.
                    () = tokio::time::sleep(std::time::Duration::from_secs(25)) =>
                        ": keep-alive\n\n".to_owned(),
                };
                let bytes: Result<actix_web::web::Bytes, std::convert::Infallible> =
                    Ok(actix_web::web::Bytes::from(framed));
                return Some((
                    bytes,
                    (
                        watching,
                        tenant,
                        realm_id,
                        replay_events,
                        has_more_replay_events,
                        replayed,
                    ),
                ));
            }
        },
    );
    HttpResponse::Ok()
        .insert_header(("content-type", "text/event-stream"))
        .insert_header(("cache-control", "no-cache"))
        .streaming(frames)
}

/// The dead-letter queue: every telling given up on, newest first.
pub async fn dead_letters(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let held = store::providers::events::outbox::dead_list(&transaction, 200)
        .await
        .map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(
        held.iter()
            .map(|event| {
                serde_json::json!({
                    "event_id": event.event_id,
                    "kind": event.kind,
                    "user_id": event.user_id,
                    "attempts": event.attempts,
                    "occurred_at": event.occurred_at.to_rfc3339(),
                })
            })
            .collect::<Vec<_>>(),
    ))
}

/// Put one dead telling back in the queue, due at once.
pub async fn requeue(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, i64)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, event_id) = path.into_inner();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let requeued = store::providers::events::outbox::requeue(&transaction, event_id)
        .await
        .map_err(|_| internal())?;
    if !requeued {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "no dead telling answers to this id".to_owned(),
        ));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

#[derive(serde::Deserialize)]
pub struct RedeliveryAsk {
    pub from_event_id: i64,
    pub to_event_id: Option<i64>,
    /// A redelivery tells what it would do unless told to do it.
    #[serde(default = "stand_back")]
    pub dry_run: bool,
}

fn stand_back() -> bool {
    true
}

/// At most this many tellings per ask; the answer carries where it
/// stopped, so the operator continues from there.
const REPLAY_CEILING: i64 = 500;

/// Re-deliver a range of retained tellings to the one webhook the path names:
/// the gap after an outage, or a consumer onboarded late. One connector and
/// never all of them, since a redelivery that fanned out would reach every
/// listener that already heard. Bounded by the outbox's own retention, a dry
/// run by default, and every delivery carries its original id, so the far
/// side's dedup makes the operation safe to repeat.
pub async fn redeliver_to_connector(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<crate::api::config::Sealing>,
    egress: web::Data<config::serving::Egress>,
    path: web::Path<(String, String)>,
    body: web::Json<RedeliveryAsk>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, alias) = path.into_inner();
    let asked = body.into_inner();
    let context = TenantContext::new(&admin.context.tenant.tenant, &realm_id);
    let transaction = tenancy
        .begin(&context)
        .await
        .map_err(refuse_unopened_work)?;

    let row = store::providers::brokering::provider_by_alias(&transaction, &alias)
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| ApiError::new(ErrorCode::IdentityProviderNotFound))?;
    if row.enabled == Some(false) {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "the connector is disabled".to_owned(),
        ));
    }
    let hook = services::messaging::webhook::Webhook::parse(&row).map_err(|_| {
        ApiError::with_detail(
            ErrorCode::ValidationError,
            "only a webhook takes a replay".to_owned(),
        )
    })?;

    let held = store::providers::events::outbox::retained(
        &transaction,
        asked.from_event_id,
        asked.to_event_id,
        REPLAY_CEILING + 1,
    )
    .await
    .map_err(|_| internal())?;
    let more = held.len() as i64 > REPLAY_CEILING;
    let held: Vec<_> = held
        .into_iter()
        .take(REPLAY_CEILING as usize)
        .filter(|event| hook.wants(&event.kind))
        .collect();
    let stopped_at = held.last().map(|event| event.event_id);

    if asked.dry_run {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "dry_run": true,
            "would_deliver": held.len(),
            "stopped_at": stopped_at,
            "more": more,
        })));
    }

    let secret = crate::federation::opened_webhook_secret(&transaction, &sealing, &context, &row)
        .await
        .ok_or_else(|| {
            ApiError::with_detail(
                ErrorCode::ValidationError,
                "the webhook's secret could not be opened".to_owned(),
            )
        })?;
    let (mut delivered, mut failed) = (0, 0);
    for event in &held {
        let body = serde_json::json!({
            "event_id": event.event_id,
            "kind": event.kind,
            "realm": context.realm_id,
            "user_id": event.user_id,
            "occurred_at": event.occurred_at.to_rfc3339(),
            "payload": event.payload,
        })
        .to_string();
        let Some(signature) = services::messaging::webhook::signature(
            sealing.provider.as_ref(),
            &secret,
            body.as_bytes(),
        ) else {
            failed += 1;
            continue;
        };
        if crate::federation::push_json(
            &hook,
            &signature,
            &event.kind,
            event.event_id,
            body,
            **egress,
        )
        .await
        {
            delivered += 1;
        } else {
            failed += 1;
        }
    }
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "dry_run": false,
        "delivered": delivered,
        "failed": failed,
        "stopped_at": stopped_at,
        "more": more,
    })))
}

#[cfg(test)]
mod tests {
    use super::{LiveEventsReplayQuery, live_events_replay_limit};

    #[test]
    fn live_events_replay_limit_is_bounded() {
        assert_eq!(
            live_events_replay_limit(&LiveEventsReplayQuery {
                after_event_id: None,
                limit: None
            })
            .unwrap(),
            100
        );
        assert_eq!(
            live_events_replay_limit(&LiveEventsReplayQuery {
                after_event_id: None,
                limit: Some(900)
            })
            .unwrap(),
            500
        );
        assert!(
            live_events_replay_limit(&LiveEventsReplayQuery {
                after_event_id: None,
                limit: Some(0)
            })
            .is_err()
        );
    }
}
