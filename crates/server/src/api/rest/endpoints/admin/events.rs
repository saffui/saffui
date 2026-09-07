//! The sign-in log, read side. Recording is the engine's, gated by the
//! realm's events_enabled switch; this only pages through what it kept.

use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::paging::PagingParams;
use store::tenancy::{Tenancy, TenantContext};

use crate::middleware::admin_guard::Admin;

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

pub async fn list_sign_ins(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    paging: web::Query<PagingParams>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let window = paging
        .window()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;
    let mut connection = pool
        .get()
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;

    let (events, total) = store::providers::login_events::list(
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

/// The live feed: every committed emission of this realm, as it happens,
/// over Server-Sent Events. Best-effort by contract: a watcher that lags
/// misses frames and the store misses nothing, so the log below stays the
/// place to ask what happened.
pub async fn stream(
    admin: web::ReqData<Admin>,
    path: web::Path<String>,
    feed: Option<web::Data<tokio::sync::broadcast::Sender<crate::live::Told>>>,
) -> HttpResponse {
    let Some(feed) = feed else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({ "message": "this deployment runs no live feed" }));
    };
    let realm_id = path.into_inner();
    let tenant = admin.context.tenant.tenant.clone();
    let watching = feed.subscribe();
    let frames = futures_util::stream::unfold(
        (watching, tenant, realm_id),
        |(mut watching, tenant, realm_id)| async move {
            loop {
                let framed = tokio::select! {
                    told = watching.recv() => match told {
                        Ok(told) if told.tenant == tenant && told.realm == realm_id => {
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
                return Some((bytes, (watching, tenant, realm_id)));
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
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    let held = store::providers::outbox::dead_list(&transaction, 200)
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
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, i64)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, event_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    let requeued = store::providers::outbox::requeue(&transaction, event_id)
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
