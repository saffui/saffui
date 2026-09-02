use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use data_encoding::HEXLOWER;
use deadpool_postgres::Pool;
use models::paging::PagingParams;
use store::tenancy::{Tenancy, TenantContext};

use crate::middleware::admin_guard::Admin;

/// The realm's audit journal, newest first: what the plane did, as the
/// chain recorded it. Read only; the chain's single writer is the store's
/// own append, and nothing here can rewrite what stands.
pub async fn list_entries(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    paging: web::Query<PagingParams>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let window = paging
        .window()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let (entries, total) = store::audit::list_entries(
        &transaction,
        window.first,
        window.max,
        paging.count.unwrap_or(false),
    )
    .await
    .map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": entries
            .iter()
            .map(|entry| serde_json::json!({
                "seq": entry.seq,
                "recorded_at": entry.recorded_at.timestamp(),
                "entry": entry.envelope,
            }))
            .collect::<Vec<_>>(),
        "first": window.first,
        "max": window.max,
        "total": total,
    })))
}

/// Recompute every link of the chain and say whether the record stands,
/// and where it first breaks when it does not.
pub async fn verify_chain(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<crate::api::config::Sealing>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let verified = match store::audit::verify(&transaction, sealing.provider.digest()).await {
        Ok(verified) => verified,
        Err(store::error::StoreError::NoChain) => {
            // Nothing has been written yet: an empty record is a whole one.
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "holds": true,
                "entries": 0,
                "broken_at": null,
            })));
        }
        Err(_) => return Err(internal()),
    };
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "holds": verified.holds(),
        "entries": verified.entries,
        "broken_at": verified.broken_at,
    })))
}

#[derive(serde::Deserialize)]
pub struct Anchoring {
    pub witness: Option<String>,
    pub receipt: Option<String>,
}

/// Publish the chain's current head against a witness the writer does not
/// control, and remember where and what came back.
pub async fn anchor_head(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    body: web::Json<Anchoring>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    let (Some(witness), Some(receipt)) = (
        asked.witness.filter(|held| !held.trim().is_empty()),
        asked.receipt.filter(|held| !held.trim().is_empty()),
    ) else {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "witness and receipt are required".to_owned(),
        ));
    };
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let anchored = match store::audit::anchor(&transaction, &witness, &receipt).await {
        Ok(anchored) => anchored,
        Err(store::error::StoreError::NoChain) => {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                "nothing has been journalled yet".to_owned(),
            ));
        }
        Err(_) => return Err(internal()),
    };
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(serde_json::json!({
        "seq": anchored.seq,
        "head_hash": HEXLOWER.encode(&anchored.hash),
    })))
}

/// Every head this realm has published, newest first.
pub async fn list_anchors(
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
    let held = store::audit::list_anchors(&transaction)
        .await
        .map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "anchors": held
            .iter()
            .map(|anchor| serde_json::json!({
                "seq": anchor.seq,
                "head_hash": HEXLOWER.encode(&anchor.head_hash),
                "witness": anchor.witness,
                "receipt": anchor.receipt,
                "anchored_at": anchor.anchored_at.timestamp(),
            }))
            .collect::<Vec<_>>(),
    })))
}

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
