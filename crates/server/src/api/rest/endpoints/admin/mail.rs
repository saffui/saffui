use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use services::admin::mail::Unsettable;
use store::keyring;
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

/// Prove the relay works while the operator is still looking at the form:
/// one test mail, sent with the held settings, the SMTP refusal spoken back
/// in words when it does not.
#[derive(serde::Deserialize)]
pub struct TestAsked {
    pub to: String,
}

pub async fn send_test(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<crate::api::config::Sealing>,
    path: web::Path<String>,
    body: web::Json<TestAsked>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let to = body.into_inner().to;
    if !to.contains('@') {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "the test wants an address to send to".to_owned(),
        ));
    }
    let mut connection = pool
        .get()
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    let ring = keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        &realm_id,
    )
    .await
    .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    let settings = services::admin::mail::read(&transaction, &ring, &sealing.envelope)
        .await
        .map_err(|_| ApiError::new(ErrorCode::MailSettingsNotFound))?;

    let message = auth::messaging::Message {
        to,
        subject: "saffui mail test".to_owned(),
        body: "This is the test mail. The settings that sent it are the ones \
               on the email screen; nothing else was used.\n"
            .to_owned(),
    };
    // Straight through the SMTP transport, never the deployment's sink: a
    // Logged sink would print the mail and prove nothing about the relay.
    // This drives the whole dialogue, connect, TLS, auth, delivery, so a
    // green answer means the settings on screen actually carry mail.
    use auth::messaging::Deliver;
    crate::messaging::Smtp
        .send(&settings, &message)
        .await
        .map_err(|_| {
            ApiError::with_detail(
                ErrorCode::ValidationError,
                "the relay refused: connection, TLS, authentication or delivery failed \
                 with these settings; the server log holds the exact refusal"
                    .to_owned(),
            )
        })?;
    Ok(HttpResponse::NoContent().finish())
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

    let view = services::admin::mail::read(&transaction, &ring, &sealing.envelope)
        .await
        .map_err(refused)?
        .as_view();
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

    services::admin::mail::write(
        &transaction,
        &ring,
        &sealing.envelope,
        services::admin::mail::Wanted {
            host: asked.host,
            port: asked.port,
            from_address: asked.from_address,
            from_name: asked.from_name,
            reply_to: asked.reply_to,
            implicit_tls: asked.implicit_tls,
            username: asked.username,
            password: asked.password,
        },
    )
    .await
    .map_err(refused)?;
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
    services::admin::mail::forget(&transaction)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

fn refused(why: Unsettable) -> ApiError {
    ApiError::new(match why {
        Unsettable::NotFound => ErrorCode::MailSettingsNotFound,
        Unsettable::HalfACredential => ErrorCode::BadRequest,
        Unsettable::Unwritable => ErrorCode::InternalError,
    })
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

/// Hold the relay in conversation and report what it said.
///
/// Told apart from the test send on purpose. The test proves a message
/// leaves; this proves nothing about delivery and answers the questions an
/// operator asks before there is a message to send: does it answer, how fast,
/// what did the handshake settle on, whose certificate is it, how large a
/// message will it take, and how does it want to be authenticated.
pub async fn look_at_relay(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool
        .get()
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    let ring = keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        &realm_id,
    )
    .await
    .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    let settings = services::admin::mail::read(&transaction, &ring, &sealing.envelope)
        .await
        .map_err(|_| ApiError::new(ErrorCode::MailSettingsNotFound))?;

    // Off the reactor: this holds a socket open for as long as the relay takes
    // to answer, and a slow one would otherwise hold every other request on
    // this worker.
    let report = tokio::task::spawn_blocking(move || crate::smtp_probe::look_at_relay(&settings))
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    Ok(HttpResponse::Ok().json(report))
}

/// What this realm tried to send lately and could not.
pub async fn list_refusals(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool
        .get()
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;

    let since = chrono::Utc::now() - chrono::Duration::hours(24);
    let held = store::providers::deliveries::read_refusals_since(&transaction, since, 50)
        .await
        .map_err(|_| ApiError::new(ErrorCode::InternalError))?;
    let items: Vec<_> = held
        .into_iter()
        .map(|refusal| {
            serde_json::json!({
                "recipient": refusal.recipient,
                "purpose": refusal.purpose,
                "attempted_at": refusal.attempted_at,
                "detail": refusal.detail,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({ "items": items, "hours": 24 })))
}
