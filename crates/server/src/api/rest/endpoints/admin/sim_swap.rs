use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use models::entities::sim_swap::WhenUnanswered;
use serde::{Deserialize, Serialize};
use services::admin::sim_swap::Unsettable;
use store::keyring;
use store::tenancy::{Tenancy, TenantContext};

use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;
use outbound::Sealing;

/// What a caller may see: the settings, the public half of the realm's key for
/// the carrier's onboarding, and whether the guard runs at all. The private
/// half is in no shape this endpoint answers with.
#[derive(Debug, Serialize)]
pub struct SimSwapBrief {
    pub client_id: String,
    pub authorize_url: String,
    pub token_url: String,
    pub check_url: String,
    pub max_age_hours: i32,
    pub when_unanswered: WhenUnanswered,
    pub kid: String,
    pub public_jwk: serde_json::Value,
    /// Experimental: stored settings do nothing until the process runs the
    /// guard.
    pub running: bool,
}

#[derive(Debug, Deserialize)]
pub struct SimSwapWrite {
    pub client_id: String,
    pub authorize_url: String,
    pub token_url: String,
    pub check_url: String,
    pub max_age_hours: Option<i32>,
    pub when_unanswered: Option<WhenUnanswered>,
}

pub async fn read(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.as_str();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let ring = keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        realm_id,
    )
    .await
    .map_err(|_| internal())?;

    let view = services::admin::sim_swap::read(&transaction, &ring, &sealing.envelope)
        .await
        .map_err(refused)?
        .as_view();
    let running =
        crate::api::feature::runs_for_realm(&transaction, commons::feature::Feature::SimSwapGuard)
            .await;
    Ok(HttpResponse::Ok().json(SimSwapBrief {
        client_id: view.client_id,
        authorize_url: view.authorize_url,
        token_url: view.token_url,
        check_url: view.check_url,
        max_age_hours: view.max_age_hours,
        when_unanswered: view.when_unanswered,
        kid: view.kid,
        public_jwk: view.public_jwk,
        running,
    }))
}

pub async fn write(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    egress: web::Data<config::serving::Egress>,
    path: web::Path<String>,
    asked: web::Json<SimSwapWrite>,
) -> Result<HttpResponse, ApiError> {
    let asked = asked.into_inner();
    // What the dial will always refuse is refused now, in words, as for a
    // realm's SMS gateway.
    if *egress.get_ref() == config::serving::Egress::Outward
        && ![&asked.authorize_url, &asked.token_url, &asked.check_url]
            .iter()
            .all(|held| held.trim().starts_with("https://"))
    {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "an outward deployment asks its carrier only over https".to_owned(),
        ));
    }
    let realm_id = path.as_str();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let ring = keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        realm_id,
    )
    .await
    .map_err(|_| internal())?;

    services::admin::sim_swap::write(
        &transaction,
        &ring,
        &sealing.envelope,
        sealing.provider.as_ref(),
        services::admin::sim_swap::Wanted {
            client_id: asked.client_id,
            authorize_url: asked.authorize_url,
            token_url: asked.token_url,
            check_url: asked.check_url,
            max_age_hours: asked.max_age_hours,
            when_unanswered: asked.when_unanswered,
        },
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

pub async fn forget(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.as_str();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    services::admin::sim_swap::forget(&transaction)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

fn refused(why: Unsettable) -> ApiError {
    match why {
        Unsettable::NotFound => ApiError::new(ErrorCode::SimSwapSettingsNotFound),
        Unsettable::Unwritable => ApiError::new(ErrorCode::InternalError),
        spoken => ApiError::with_detail(ErrorCode::ValidationError, spoken.to_string()),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
