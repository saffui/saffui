use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use services::admin::requests::{self, Unaskable};
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

fn refused(why: Unaskable) -> ApiError {
    match why {
        Unaskable::NotFound => ApiError::new(ErrorCode::RoleNotFound),
        Unaskable::Backend => internal(),
        told => ApiError::with_detail(ErrorCode::ValidationError, told.to_string()),
    }
}

fn shaped(asked: &store::providers::requests::AccessRequest) -> serde_json::Value {
    json!({
        "request_id": asked.request_id,
        "user_id": asked.user_id,
        "role_id": asked.role_id,
        "reason": asked.reason,
        "expires_at": asked.expires_at.map(|end| end.to_rfc3339()),
        "state": asked.state,
        "asked_by": asked.asked_by,
        "decided_by": asked.decided_by,
        "decided_at": asked.decided_at.map(|at| at.to_rfc3339()),
        "decided_reason": asked.decided_reason,
        "created_at": asked.created_at.to_rfc3339(),
    })
}

pub async fn list(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = requests::list(&transaction).await.map_err(refused)?;
    Ok(HttpResponse::Ok().json(held.iter().map(shaped).collect::<Vec<_>>()))
}

#[derive(Debug, Deserialize)]
pub struct AskedRequest {
    pub user_id: Option<String>,
    pub role_id: Option<String>,
    pub reason: Option<String>,
    /// RFC 3339; the end the grant will carry if granted.
    pub expires_at: Option<String>,
}

pub async fn lodge(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    body: web::Json<AskedRequest>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    let worded =
        |detail: &str| ApiError::with_detail(ErrorCode::ValidationError, detail.to_owned());
    let user = asked
        .user_id
        .as_deref()
        .map(str::trim)
        .filter(|held| !held.is_empty())
        .ok_or_else(|| worded("user_id names who would hold it"))?;
    let role_id = asked
        .role_id
        .as_deref()
        .map(str::trim)
        .filter(|held| !held.is_empty())
        .ok_or_else(|| worded("role_id names what is asked"))?;
    let expires_at = match asked.expires_at.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(spelled) => Some(
            chrono::DateTime::parse_from_rfc3339(spelled)
                .map(|end| end.with_timezone(&chrono::Utc))
                .map_err(|_| worded("expires_at is an RFC 3339 instant"))?,
        ),
    };

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let lodged = requests::lodge(
        &transaction,
        sealing.provider.as_ref(),
        admin.context.principal.id(),
        user,
        role_id,
        asked.reason.as_deref().unwrap_or_default(),
        expires_at,
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(shaped(&lodged)))
}

pub async fn approve(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, request_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let granted = requests::approve(&transaction, &request_id, admin.context.principal.id())
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(shaped(&granted)))
}

#[derive(Debug, Deserialize)]
pub struct AskedDenial {
    pub reason: Option<String>,
}

pub async fn deny(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<AskedDenial>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, request_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    requests::deny(
        &transaction,
        &request_id,
        admin.context.principal.id(),
        body.into_inner().reason.as_deref().unwrap_or_default(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

pub async fn withdraw(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, request_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    requests::withdraw(&transaction, &request_id, admin.context.principal.id())
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}
