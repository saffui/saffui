use crate::api::rest::endpoints::within;
use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use serde::Deserialize;
use services::admin::agents::{self, Refused};
use store::tenancy::Tenancy;

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

/// What a registration asks: the root out loud, nothing implied. No secret
/// rides in or out of this door; an agent's platform is its credential,
/// and an operator who wants one turns the client's secret rotation door,
/// eyes open.
#[derive(Debug, Deserialize)]
pub struct RegisterSpec {
    pub client_id: String,
    pub capabilities: Vec<String>,
    pub session_seconds: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct ReshapeSpec {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    pub session_seconds: Option<i32>,
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
    let held = agents::list(&transaction).await.map_err(refused)?;
    Ok(HttpResponse::Ok().json(held))
}

pub async fn register(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    body: web::Json<RegisterSpec>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let born = agents::register(
        &transaction,
        sealing.provider.as_ref(),
        &admin.context.tenant.tenant,
        &realm_id,
        admin.context.principal.id(),
        &asked.client_id,
        &asked.capabilities,
        asked.session_seconds,
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(born))
}

pub async fn get(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, client_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = agents::get(&transaction, &client_id)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(held))
}

pub async fn reshape(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<ReshapeSpec>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, client_id) = path.into_inner();
    let asked = body.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = agents::reshape(
        &transaction,
        &client_id,
        &asked.add,
        &asked.remove,
        asked.session_seconds,
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(held))
}

fn refused(why: Refused) -> ApiError {
    match why {
        Refused::AlreadyExists => ApiError::new(ErrorCode::ClientAlreadyExists),
        Refused::NotFound => ApiError::new(ErrorCode::ClientNotFound),
        Refused::Invalid(said) => ApiError::with_detail(ErrorCode::ValidationError, said),
        Refused::Unwritable => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
