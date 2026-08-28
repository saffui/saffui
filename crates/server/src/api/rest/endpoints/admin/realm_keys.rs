use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use crypto::provider::SignAlg;
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use services::admin::realm_keys::Unturnable;
use store::keyring;
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

/// Every key the realm holds, disabled ones included. The public JWKS shows
/// what verifies; this shows what the realm has.
pub async fn list(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.as_str();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, realm_id))
        .await
        .map_err(|_| internal())?;

    let held = services::admin::realm_keys::held(&transaction)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(json!({
        "signing": held.signing,
        "encryption": held.encryption
            .iter()
            .map(|key| json!({
                "kid": key.kid,
                "algorithm": key.algorithm,
                "status": key.status,
                "public_jwk": key.public_jwk,
            }))
            .collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
pub struct RotationBody {
    pub algorithm: SignAlg,
}

/// Mint a successor: the named algorithm's active key goes passive and a
/// fresh one signs in its place.
pub async fn rotate(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    body: web::Json<RotationBody>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.as_str();
    let tenant = admin.context.tenant.tenant.clone();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, realm_id))
        .await
        .map_err(|_| internal())?;
    let ring = keyring::load(&transaction, &sealing.envelope, &tenant, realm_id)
        .await
        .map_err(|_| internal())?;

    let minted = services::admin::realm_keys::rotate(
        &transaction,
        &ring,
        &sealing.envelope,
        sealing.provider.as_ref(),
        &tenant,
        realm_id,
        body.algorithm,
        chrono::Utc::now().timestamp(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(minted))
}

/// Take a retired key out of publication. An active one is refused: rotation
/// is the way out of service, because it keeps signed tokens verifiable.
pub async fn disable(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, kid) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;

    services::admin::realm_keys::disable(&transaction, &kid)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

fn refused(why: Unturnable) -> ApiError {
    match why {
        Unturnable::NotFound => ApiError::new(ErrorCode::KeyNotFound),
        Unturnable::StillActive => ApiError::new(ErrorCode::KeyStillActive),
        Unturnable::Backend => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
