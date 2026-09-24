//! A realm's mark: the one piece of its look that is a file rather than a token.

use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use services::theme::{Unusable, weigh_logo};
use store::tenancy::Tenancy;

use crate::api::rest::endpoints::within;
use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;

/// Keep this realm's mark, weighed on its own bytes.
///
/// The body is the picture itself rather than a field inside an envelope: it
/// arrives as it will be served, so nothing decodes, re-encodes or re-wraps it
/// between the weighing and the keeping.
pub async fn keep(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    body: web::Bytes,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let kind = weigh_logo(&body).map_err(refused)?;

    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let held = store::providers::realms::set_logo(&transaction, &realm_id, Some((&body, kind)))
        .await
        .map_err(|_| internal())?;
    if !held {
        return Err(ApiError::new(ErrorCode::RealmNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Take the mark away; the pages fall back to the letters they drew before.
pub async fn forget(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let held = store::providers::realms::set_logo(&transaction, &realm_id, None)
        .await
        .map_err(|_| internal())?;
    if !held {
        return Err(ApiError::new(ErrorCode::RealmNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Whether this realm keeps one, and what it is. The bytes are not answered
/// here: a console draws the mark from the public address like any browser.
pub async fn describe(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let held = store::providers::realms::logo_of(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "held": held.is_some(),
        "media_type": held.as_ref().map(|(_, kind)| kind.clone()),
        "bytes": held.as_ref().map(|(held, _)| held.len()),
    })))
}

fn refused(why: Unusable) -> ApiError {
    ApiError::with_detail(ErrorCode::ValidationError, why.to_string())
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
