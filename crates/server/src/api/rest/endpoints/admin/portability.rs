use actix_web::{HttpResponse, web};
use chrono::Utc;
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::entities::export::ExportedRealm;
use serde::Deserialize;
use services::admin::portability::{self, Unportable};
use store::tenancy::{Tenancy, TenantContext};

use crate::middleware::admin_guard::Admin;

/// The realm as a document. Read whole inside one transaction, so no
/// section can come from a different state than another.
pub async fn export(
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
    let document = portability::export_realm(&transaction, &realm_id, Utc::now())
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(document))
}

/// Where the document lands: under its own name unless the caller says
/// another, which is how a realm is cloned beside its original.
#[derive(Deserialize)]
pub struct Landing {
    #[serde(rename = "as")]
    pub landed_as: Option<String>,
}

pub async fn import(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    landing: web::Query<Landing>,
    body: web::Json<ExportedRealm>,
) -> Result<HttpResponse, ApiError> {
    let document = body.into_inner();
    let realm_id = landing
        .into_inner()
        .landed_as
        .unwrap_or_else(|| document.realm.realm_id.clone());
    if realm_id.trim().is_empty() {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "a realm answers to a name",
        ));
    }
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    portability::import_realm(
        &transaction,
        &admin.context.tenant.tenant,
        &realm_id,
        document,
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(serde_json::json!({ "realm_id": realm_id })))
}

fn refused(why: Unportable) -> ApiError {
    match why {
        Unportable::NotFound => ApiError::new(ErrorCode::RealmNotFound),
        Unportable::AlreadyExists => ApiError::new(ErrorCode::RealmAlreadyExists),
        Unportable::Quarantined(what) => ApiError::with_detail(
            ErrorCode::ValidationError,
            format!("policy {what} cannot be read, so the document would be missing it"),
        ),
        Unportable::Tangled(server) => ApiError::with_detail(
            ErrorCode::ValidationError,
            format!("the policies of {server} do not resolve in document order"),
        ),
        Unportable::Invalid(what) => ApiError::with_detail(ErrorCode::ValidationError, what),
        Unportable::Backend => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
