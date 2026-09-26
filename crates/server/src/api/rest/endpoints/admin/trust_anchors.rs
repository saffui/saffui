use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use models::entities::trust_anchors::{TrustAnchor, TrustAnchorRole};
use serde::{Deserialize, Serialize};
use services::admin::trust_anchors::Undepositable;
use store::tenancy::{Tenancy, TenantContext};

use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;
use outbound::Sealing;

/// One trusted authority, as a caller may see it. The certificate is public,
/// and handed back whole so it can be checked against the one meant.
#[derive(Debug, Serialize)]
pub struct AnchorBrief {
    pub id: String,
    pub role: TrustAnchorRole,
    pub subject: String,
    pub key_identifier: Option<String>,
    pub fingerprint: String,
    pub not_after: chrono::DateTime<chrono::Utc>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// The DER, base64.
    pub certificate: String,
}

impl From<TrustAnchor> for AnchorBrief {
    fn from(anchor: TrustAnchor) -> Self {
        Self {
            id: anchor.anchor_id,
            role: anchor.role,
            subject: anchor.subject,
            key_identifier: anchor.key_identifier,
            fingerprint: anchor.fingerprint,
            not_after: anchor.not_after,
            created_by: anchor.created_by,
            created_at: anchor.created_at,
            certificate: data_encoding::BASE64.encode(&anchor.certificate),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AnchorWrite {
    pub role: TrustAnchorRole,
    /// One certificate, PEM encoded.
    pub certificate: String,
}

/// The authorities the realm trusts, and whether the verifier that reads them
/// runs: experimental, they do nothing until the process runs it.
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
    let anchors = services::admin::trust_anchors::list(&transaction)
        .await
        .map_err(refused)?;
    let running = crate::api::feature::runs_for_realm(
        &transaction,
        commons::feature::Feature::WalletVerifier,
    )
    .await;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "running": running,
        "items": anchors.into_iter().map(AnchorBrief::from).collect::<Vec<_>>(),
    })))
}

pub async fn deposit(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    asked: web::Json<AnchorWrite>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = asked.into_inner();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let anchor = services::admin::trust_anchors::deposit(
        &transaction,
        sealing.provider.as_ref(),
        asked.role,
        &asked.certificate,
        admin.context.principal.id(),
        chrono::Utc::now(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(AnchorBrief::from(anchor)))
}

pub async fn withdraw(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, anchor_id) = path.into_inner();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    services::admin::trust_anchors::withdraw(&transaction, &anchor_id)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

fn refused(why: Undepositable) -> ApiError {
    match why {
        Undepositable::NotFound => ApiError::new(ErrorCode::TrustAnchorNotFound),
        Undepositable::AlreadyTrusted => ApiError::new(ErrorCode::TrustAnchorAlreadyDeposited),
        Undepositable::Unwritable => internal(),
        spoken => ApiError::with_detail(ErrorCode::ValidationError, spoken.to_string()),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
