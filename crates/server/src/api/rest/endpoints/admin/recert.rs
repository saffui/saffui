use crate::api::rest::endpoints::within;
use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use services::admin::recert::{self, Unreviewable};
use store::tenancy::Tenancy;

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

fn refused(why: Unreviewable) -> ApiError {
    match why {
        Unreviewable::NotFound | Unreviewable::NoSuchItem => ApiError::new(ErrorCode::RoleNotFound),
        Unreviewable::Backend => internal(),
        told => ApiError::with_detail(ErrorCode::ValidationError, told.to_string()),
    }
}

fn shaped(campaign: &store::providers::recert::Campaign) -> serde_json::Value {
    json!({
        "campaign_id": campaign.campaign_id,
        "name": campaign.name,
        "scope_kind": campaign.scope_kind,
        "scope_ref": campaign.scope_ref,
        "reviewer_id": campaign.reviewer_id,
        "state": campaign.state,
        "snapshot_at": campaign.snapshot_at.map(|at| at.to_rfc3339()),
        "closed_at": campaign.closed_at.map(|at| at.to_rfc3339()),
        "excluded": campaign.excluded,
        "report_seq": campaign.report_seq,
        "created_at": campaign.created_at.to_rfc3339(),
    })
}

pub async fn campaigns(
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
    let held = recert::campaigns(&transaction).await.map_err(refused)?;
    Ok(HttpResponse::Ok().json(held.iter().map(shaped).collect::<Vec<_>>()))
}

#[derive(Debug, Deserialize)]
pub struct AskedCampaign {
    pub name: Option<String>,
    /// realm, role or group.
    pub scope_kind: Option<String>,
    pub scope_ref: Option<String>,
    pub reviewer_id: Option<String>,
}

pub async fn open(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    body: web::Json<AskedCampaign>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    let worded =
        |detail: &str| ApiError::with_detail(ErrorCode::ValidationError, detail.to_owned());
    let reviewer = asked
        .reviewer_id
        .as_deref()
        .map(str::trim)
        .filter(|held| !held.is_empty())
        .ok_or_else(|| worded("reviewer_id names who reviews"))?;
    let scope_kind = asked.scope_kind.as_deref().unwrap_or(recert::SCOPE_REALM);

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let opened = recert::open(
        &transaction,
        sealing.provider.as_ref(),
        admin.context.principal.id(),
        asked.name.as_deref().unwrap_or_default(),
        scope_kind,
        asked
            .scope_ref
            .as_deref()
            .map(str::trim)
            .filter(|held| !held.is_empty()),
        reviewer,
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(shaped(&opened)))
}

pub async fn activate(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, campaign_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let (frozen, excluded) =
        recert::activate(&transaction, sealing.provider.as_ref(), &campaign_id)
            .await
            .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(json!({ "frozen": frozen, "excluded": excluded })))
}

pub async fn items(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, campaign_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = recert::items(&transaction, &campaign_id)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(
        held.iter()
            .map(|item| {
                json!({
                    "item_id": item.item_id,
                    "subject_id": item.subject_id,
                    "edge_kind": item.edge_kind,
                    "edge_ref": item.edge_ref,
                    "frozen": item.frozen,
                    "state": item.state,
                    "resolution": item.resolution,
                })
            })
            .collect::<Vec<_>>(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct AskedDecision {
    pub decision: Option<String>,
    pub justification: Option<String>,
}

pub async fn decide(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<(String, String, String)>,
    body: web::Json<AskedDecision>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, campaign_id, item_id) = path.into_inner();
    let asked = body.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    recert::decide(
        &transaction,
        sealing.provider.as_ref(),
        &campaign_id,
        &item_id,
        admin.context.principal.id(),
        asked.decision.as_deref().unwrap_or_default(),
        asked.justification.as_deref(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

pub async fn close(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, campaign_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let told = recert::close(
        &transaction,
        sealing.provider.as_ref(),
        &admin.context.tenant.tenant,
        &realm_id,
        &campaign_id,
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(json!({
        "certified": told.certified,
        "revoked": told.revoked,
        "drifted": told.drifted,
        "already_removed": told.already_gone,
        "report_digest": told.report_digest,
        "anchored_at": told.anchored_at,
    })))
}

/// The report as it was rendered and hashed, byte for byte: anything that
/// re-renders it is a second renderer, and two renderers is one digest that
/// does not match.
pub async fn report(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, campaign_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let rendered = recert::report(&transaction, &campaign_id)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(rendered))
}
