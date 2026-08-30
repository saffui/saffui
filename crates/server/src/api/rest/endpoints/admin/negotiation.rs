use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::entities::brokering::RealmSpnegoMutationModel;
use services::admin::negotiation::{self, Unwritable};
use store::tenancy::{Tenancy, TenantContext};

use crate::middleware::admin_guard::Admin;

pub async fn get(
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
    let held = negotiation::get(&transaction).await.map_err(refused)?;
    Ok(HttpResponse::Ok().json(held))
}

pub async fn put(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    body: web::Json<RealmSpnegoMutationModel>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let kept = negotiation::put(
        &transaction,
        &admin.context.tenant.tenant,
        &realm_id,
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
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    negotiation::delete(&transaction).await.map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
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
