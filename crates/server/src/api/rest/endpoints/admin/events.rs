//! The sign-in log, read side. Recording is the engine's, gated by the
//! realm's events_enabled switch; this only pages through what it kept.

use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::paging::PagingParams;
use store::tenancy::{Tenancy, TenantContext};

use crate::middleware::admin_guard::Admin;

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
