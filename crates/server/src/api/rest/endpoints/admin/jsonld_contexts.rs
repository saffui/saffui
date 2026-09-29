use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use config::serving::Egress;
use models::entities::jsonld_contexts::JsonLdContext;
use serde::{Deserialize, Serialize};
use services::admin::jsonld_contexts::{Unpinnable, check_url};
use store::tenancy::{Tenancy, TenantContext};

use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;
use outbound::Sealing;

/// One pinned context, as a caller may see it: what was read and when, not the
/// document itself.
#[derive(Debug, Serialize)]
pub struct ContextBrief {
    pub id: String,
    pub url: String,
    pub digest: String,
    pub octets: i32,
    pub read_at: chrono::DateTime<chrono::Utc>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<JsonLdContext> for ContextBrief {
    fn from(pinned: JsonLdContext) -> Self {
        Self {
            id: pinned.context_id,
            url: pinned.url,
            digest: pinned.digest,
            octets: pinned.octets,
            read_at: pinned.read_at,
            created_by: pinned.created_by,
            created_at: pinned.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ContextWrite {
    /// The context as documents name it.
    pub url: String,
}

/// The contexts built in and those the realm pins, and whether the verifier
/// that reads them runs: experimental, they do nothing until the process runs
/// it.
pub async fn list(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let pinned = services::admin::jsonld_contexts::list(&transaction)
        .await
        .map_err(refused)?;
    let running = crate::api::feature::runs_for_realm(
        &transaction,
        commons::feature::Feature::WalletVerifier,
    )
    .await;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "running": running,
        "built_in": services::admin::jsonld_contexts::built_in_urls(),
        "items": pinned.into_iter().map(ContextBrief::from).collect::<Vec<_>>(),
    })))
}

/// Pin a context, reading it first: before any transaction opens, so no
/// database session waits on somebody else's server.
pub async fn pin(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    egress: web::Data<Egress>,
    path: web::Path<String>,
    asked: web::Json<ContextWrite>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let url = asked.into_inner().url;
    check_url(&url).map_err(refused)?;
    let document = fetched(&url, **egress).await?;
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let pinned = services::admin::jsonld_contexts::pin(
        &transaction,
        sealing.provider.as_ref(),
        &url,
        &document,
        admin.context.principal.id(),
        chrono::Utc::now(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(ContextBrief::from(pinned)))
}

/// Read a context again, where it was first read.
pub async fn read_again(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    egress: web::Data<Egress>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, context_id) = path.into_inner();
    let within = TenantContext::new(&admin.context.tenant.tenant, &realm_id);
    let url = {
        let transaction = tenancy.begin(&within).await.map_err(refuse_unopened_work)?;
        services::admin::jsonld_contexts::pinned(&transaction, &context_id)
            .await
            .map_err(refused)?
            .url
    };
    let document = fetched(&url, **egress).await?;
    let transaction = tenancy.begin(&within).await.map_err(refuse_unopened_work)?;
    let pinned = services::admin::jsonld_contexts::read_again(
        &transaction,
        sealing.provider.as_ref(),
        &context_id,
        &document,
        chrono::Utc::now(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(ContextBrief::from(pinned)))
}

pub async fn forget(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, context_id) = path.into_inner();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    services::admin::jsonld_contexts::forget(&transaction, &context_id)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

async fn fetched(address: &str, egress: Egress) -> Result<String, ApiError> {
    outbound::egress::fetch(address.to_owned(), egress)
        .await
        .ok_or_else(|| {
            ApiError::with_detail(
                ErrorCode::ValidationError,
                format!("nothing could be read at {address}"),
            )
        })
}

fn refused(why: Unpinnable) -> ApiError {
    match why {
        Unpinnable::NotFound => ApiError::new(ErrorCode::JsonLdContextNotFound),
        Unpinnable::AlreadyPinned => ApiError::new(ErrorCode::JsonLdContextAlreadyPinned),
        Unpinnable::Unwritable => internal(),
        spoken => ApiError::with_detail(ErrorCode::ValidationError, spoken.to_string()),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
