//! How a realm sends mail, over the admin plane.

use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::entities::mail::{MailCredentials, MailSettings};
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use store::keyring;
use store::providers::mail;
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

/// What a caller may see. The password is not in it, and there is no shape of
/// this endpoint that answers with one.
#[derive(Debug, Serialize)]
pub struct MailBrief {
    pub host: String,
    pub port: u16,
    pub from_address: String,
    pub from_name: String,
    pub reply_to: Option<String>,
    pub implicit_tls: bool,
    pub username: Option<String>,
    /// Whether a password is held. Not which one, and not how long it is.
    pub has_password: bool,
}

#[derive(Debug, Deserialize)]
pub struct MailWrite {
    pub host: String,
    pub port: u16,
    pub from_address: String,
    #[serde(default)]
    pub from_name: String,
    pub reply_to: Option<String>,
    #[serde(default)]
    pub implicit_tls: bool,
    pub username: Option<String>,
    /// Absent keeps whatever is held, so an administrator editing the host does
    /// not have to retype a password to keep it. Present replaces it.
    pub password: Option<String>,
}

pub async fn read(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.as_str();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, realm_id),
        )
        .await
        .map_err(|_| internal())?;
    let ring = keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        realm_id,
    )
    .await
    .map_err(|_| internal())?;

    let held = mail::load(&transaction, &ring, &sealing.envelope)
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| ApiError::new(ErrorCode::MailSettingsNotFound))?;

    let view = held.as_view();
    Ok(HttpResponse::Ok().json(MailBrief {
        host: view.host,
        port: view.port,
        from_address: view.from_address,
        from_name: view.from_name,
        reply_to: view.reply_to,
        implicit_tls: view.implicit_tls,
        has_password: view.username.is_some(),
        username: view.username,
    }))
}

pub async fn write(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    asked: web::Json<MailWrite>,
) -> Result<HttpResponse, ApiError> {
    let asked = asked.into_inner();
    let realm_id = path.as_str();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, realm_id),
        )
        .await
        .map_err(|_| internal())?;
    let ring = keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        realm_id,
    )
    .await
    .map_err(|_| internal())?;

    // A password left out keeps the one held, and only for the same user: a
    // username changed without a password is a credential half replaced.
    let held = mail::load(&transaction, &ring, &sealing.envelope)
        .await
        .map_err(|_| internal())?;
    let credentials = match (asked.username, asked.password) {
        (Some(username), Some(password)) => Some(MailCredentials {
            username,
            password: SecretBox::new(Box::new(password)),
        }),
        (Some(username), None) => held
            .and_then(|held| held.credentials)
            .filter(|held| held.username == username)
            .ok_or_else(|| ApiError::new(ErrorCode::BadRequest))
            .map(Some)?,
        (None, _) => None,
    };

    mail::keep(
        &transaction,
        &ring,
        &sealing.envelope,
        &MailSettings {
            host: asked.host,
            port: asked.port,
            from_address: asked.from_address,
            from_name: asked.from_name,
            reply_to: asked.reply_to,
            implicit_tls: asked.implicit_tls,
            credentials,
        },
    )
    .await
    .map_err(|_| ApiError::new(ErrorCode::ValidationError))?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

pub async fn forget(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.as_str();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, realm_id),
        )
        .await
        .map_err(|_| internal())?;
    if !mail::forget(&transaction).await.map_err(|_| internal())? {
        return Err(ApiError::new(ErrorCode::MailSettingsNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
