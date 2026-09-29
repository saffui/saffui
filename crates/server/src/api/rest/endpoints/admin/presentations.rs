use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use config::serving::PublicOrigin;
use serde::Deserialize;
use services::verifier::presentation::{Unanswerable, Unaskable};
use store::tenancy::{Tenancy, TenantContext};

use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;
use outbound::Sealing;

#[derive(Debug, Deserialize)]
pub struct PresentationAsked {
    /// What to ask for, DCQL.
    pub dcql_query: serde_json::Value,
}

/// Ask a wallet for a presentation: the answer is a link a wallet opens, and
/// the same link drawn as a QR code for a wallet to scan, and the request waits
/// five minutes for it.
pub async fn ask(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<String>,
    asked: web::Json<PresentationAsked>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let tenant = admin.context.tenant.tenant.clone();
    let transaction = tenancy
        .begin(&TenantContext::new(&tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    // A request no wallet could fetch or answer is not one to hand out.
    if !crate::api::feature::runs_for_realm(&transaction, commons::feature::Feature::WalletVerifier)
        .await
    {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "this realm does not run the wallet verifier",
        ));
    }
    store::keyring::provision(&transaction, &sealing.envelope, &tenant, &realm_id)
        .await
        .map_err(|_| internal())?;
    let ring = store::keyring::load(&transaction, &sealing.envelope, &tenant, &realm_id)
        .await
        .map_err(|_| internal())?;
    let signing = store::keyring::Signing {
        provider: sealing.provider.as_ref(),
        ring: &ring,
        envelope: &sealing.envelope,
    };
    let made = services::verifier::presentation::ask(
        &transaction,
        &signing,
        &origin.issuer(&realm_id),
        &asked.into_inner().dcql_query,
        admin.context.principal.id(),
        chrono::Utc::now(),
    )
    .await
    .map_err(|why| match why {
        Unaskable::Unwritable => internal(),
        spoken => ApiError::with_detail(ErrorCode::ValidationError, spoken.to_string()),
    })?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": made.request_id,
        "qr": commons::qr::draw_qr_svg(&made.uri),
        "uri": made.uri,
        "expires_at": made.expires_at,
    })))
}

/// Where a request stands: pending, verified, refused by the wallet, or failed,
/// with what the answer came to. Never a claim's value: none is kept.
pub async fn read(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, request_id) = path.into_inner();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let standing = services::verifier::presentation::read_standing(&transaction, &request_id)
        .await
        .map_err(|_: Unanswerable| internal())?
        .ok_or_else(|| ApiError::new(ErrorCode::PresentationNotFound))?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": standing.request_id,
        "status": standing.status,
        "outcome": standing.outcome,
        "expires_at": standing.expires_at,
        "answered_at": standing.answered_at,
        "created_by": standing.created_by,
        "created_at": standing.created_at,
    })))
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
