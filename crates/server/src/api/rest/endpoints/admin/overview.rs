use actix_web::{HttpResponse, web};
use commons::http::ApiError;
use store::tenancy::Tenancy;

use crate::api::rest::endpoints::within;
use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;

fn internal() -> ApiError {
    ApiError::new(commons::error::ErrorCode::InternalError)
}

/// The numbers the overview opens with, answered together.
///
/// One request and one transaction rather than four of each: the page shows
/// them as a single strip, so fetching them apart bought nothing and cost a
/// round trip and a connection per number.
///
/// Every count is over rows the realm owns, and the tables lead their primary
/// key with the realm, so each is the realm's size rather than the
/// deployment's. Nothing here aggregates a history: a figure that would need
/// walking the event table belongs to a pre-aggregation this deployment has
/// deliberately not built.
pub async fn read(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;

    let counted = services::admin::realms::read_overview(&transaction)
        .await
        .map_err(|_| internal())?;

    let mut answer = serde_json::json!({
        "users": counted.users,
        "clients": counted.clients,
        "sessions": counted.sessions,
        "pending_requests": counted.pending_requests,
        "queue": counted.waiting_events,
    });
    // Absent where this build measures nothing, so the console leaves the box
    // out rather than printing a placeholder for a reading that never comes.
    if let Some(millis) = crate::metrics::slow_tail_millis() {
        answer["slow_tail_millis"] = serde_json::json!(millis.round() as i64);
    }
    Ok(HttpResponse::Ok().json(answer))
}
