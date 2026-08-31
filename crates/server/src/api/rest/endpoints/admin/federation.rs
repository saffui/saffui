use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::entities::brokering::UserFederationMutationModel;
use services::admin::federation::{self, Unwritable};
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

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
    let held = federation::list(&transaction).await.map_err(refused)?;
    Ok(HttpResponse::Ok().json(held))
}

pub async fn get(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, alias) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = federation::get(&transaction, &alias)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(held))
}

pub async fn put(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<(String, String)>,
    body: web::Json<UserFederationMutationModel>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, alias) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        &realm_id,
    )
    .await
    .map_err(|_| internal())?;
    let kept = federation::put(
        &transaction,
        &ring,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        &realm_id,
        &alias,
        admin.context.principal.id(),
        body.into_inner(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(kept))
}

pub async fn delete(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, alias) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    federation::delete(&transaction, &alias)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Mirror everybody the directory holds, now, once. The same walk the sync
/// makes, asked by an operator instead of a clock.
pub async fn import(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, alias) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let context = within(&admin, &realm_id);
    let transaction = tenancy
        .transaction(&mut connection, &context)
        .await
        .map_err(|_| internal())?;
    let held = match store::providers::brokering::federation(&transaction, &alias)
        .await
        .map_err(|_| internal())?
    {
        Some(held) if held.enabled != Some(false) => held,
        Some(_) => {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                "the directory is disabled".to_owned(),
            ));
        }
        None => return Err(ApiError::new(ErrorCode::IdentityProviderNotFound)),
    };
    let settings = services::federation::LdapSettings::parse(&held)
        .map_err(|why| ApiError::with_detail(ErrorCode::ValidationError, why.to_string()))?;
    let directory =
        crate::federation::directory_for(&transaction, &sealing, &context, &held, settings).await;
    let told = crate::federation::import_everyone(&transaction, &context, &alias, &directory)
        .await
        .map_err(|_| {
            ApiError::with_detail(
                ErrorCode::ValidationError,
                "the directory could not be walked".to_owned(),
            )
        })?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "imported": told.imported,
        "refreshed": told.refreshed,
        "walked": told.walked,
    })))
}

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

fn refused(why: Unwritable) -> ApiError {
    match why {
        Unwritable::NotFound => ApiError::new(ErrorCode::IdentityProviderNotFound),
        Unwritable::Invalid(what) => ApiError::with_detail(ErrorCode::ValidationError, what),
        Unwritable::Backend => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
