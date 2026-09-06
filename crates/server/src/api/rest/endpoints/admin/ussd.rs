use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use services::admin::ussd::Unsettable;
use store::keyring;
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

/// What a caller may see: that a gateway is named. Never the secret, and
/// there is no shape of this endpoint that answers with one.
#[derive(Debug, Serialize)]
pub struct UssdBrief {
    pub has_secret: bool,
}

#[derive(Debug, Deserialize)]
pub struct UssdWrite {
    /// The secret the gateway will present. Always replaces: an inbound
    /// credential is rotated whole or not at all.
    pub secret: String,
}

pub async fn read(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.as_str();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, realm_id),
        )
        .await
        .map_err(|_| internal())?;
    let ring = keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        realm_id,
    )
    .await
    .map_err(|_| internal())?;
    let held = services::admin::ussd::held(&transaction, &ring, &sealing.envelope)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(UssdBrief { has_secret: held }))
}

pub async fn write(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    asked: web::Json<UssdWrite>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.as_str();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, realm_id),
        )
        .await
        .map_err(|_| internal())?;
    let ring = keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        realm_id,
    )
    .await
    .map_err(|_| internal())?;
    services::admin::ussd::write(
        &transaction,
        &ring,
        &sealing.envelope,
        asked.into_inner().secret,
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

pub async fn forget(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.as_str();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, realm_id),
        )
        .await
        .map_err(|_| internal())?;
    services::admin::ussd::forget(&transaction)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

fn refused(why: Unsettable) -> ApiError {
    match why {
        Unsettable::NotFound => ApiError::new(ErrorCode::UssdSettingsNotFound),
        Unsettable::TooShort => ApiError::with_detail(
            ErrorCode::ValidationError,
            "a gateway secret is at least sixteen characters".to_owned(),
        ),
        Unsettable::Unwritable => ApiError::new(ErrorCode::InternalError),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
