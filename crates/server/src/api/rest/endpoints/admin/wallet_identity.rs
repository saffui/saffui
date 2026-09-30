use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use serde::Deserialize;
use services::admin::wallet_identity::{Unsettable, WalletIdentity, Wanted};
use store::keyring;
use store::tenancy::{Tenancy, TenantContext};

use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;
use outbound::Sealing;

#[derive(Debug, Deserialize)]
pub struct WalletIdentityWrite {
    /// The one credential a login asks for, as a DCQL credential query.
    pub credential_query: serde_json::Value,
    /// The issuer that vouches for identities, one the realm names.
    pub issuer: String,
    /// The claim that identifies, as a path of member names.
    pub identifier_path: Vec<String>,
}

/// How the realm knows people by a credential their wallet presents. Never
/// the key identities are digested under: nothing here answers with it.
pub async fn read(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let transaction = tenancy
        .begin(&TenantContext::new(
            &admin.context.tenant.tenant,
            path.as_str(),
        ))
        .await
        .map_err(refuse_unopened_work)?;
    let profile = services::admin::wallet_identity::read(&transaction)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(describe_profile(&profile)))
}

/// Say how the realm knows people. The first write draws the key identities
/// are digested under; a rewrite keeps it, so every identity linked still
/// answers.
pub async fn write(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    asked: web::Json<WalletIdentityWrite>,
) -> Result<HttpResponse, ApiError> {
    let asked = asked.into_inner();
    let realm_id = path.as_str();
    let tenant = admin.context.tenant.tenant.clone();
    let transaction = tenancy
        .begin(&TenantContext::new(&tenant, realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    keyring::provision(&transaction, &sealing.envelope, &tenant, realm_id)
        .await
        .map_err(|_| internal())?;
    let ring = keyring::load(&transaction, &sealing.envelope, &tenant, realm_id)
        .await
        .map_err(|_| internal())?;
    let profile = services::admin::wallet_identity::write(
        &transaction,
        &keyring::Signing {
            provider: sealing.provider.as_ref(),
            ring: &ring,
            envelope: &sealing.envelope,
        },
        Wanted {
            credential_query: asked.credential_query,
            issuer: asked.issuer,
            identifier_path: asked.identifier_path,
        },
        admin.context.principal.id(),
        chrono::Utc::now(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(describe_profile(&profile)))
}

fn describe_profile(profile: &WalletIdentity) -> serde_json::Value {
    serde_json::json!({
        "credential_query": profile.credential_query,
        "issuer": profile.issuer,
        "identifier_path": profile.identifier_path,
        "updated_by": profile.updated_by,
        "updated_at": profile.updated_at,
    })
}

/// A refusal in the words of what was wrong, since the operator is the one
/// who can fix it.
fn refused(why: Unsettable) -> ApiError {
    match why {
        Unsettable::NotFound => ApiError::new(ErrorCode::WalletIdentityNotFound),
        Unsettable::Unwritable => internal(),
        spoken => ApiError::with_detail(ErrorCode::ValidationError, spoken.to_string()),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
