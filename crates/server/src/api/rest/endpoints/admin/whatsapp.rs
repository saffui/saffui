use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use serde::{Deserialize, Serialize};
use services::admin::whatsapp::Unsettable;
use store::keyring;
use store::tenancy::{Tenancy, TenantContext};

use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;
use outbound::Sealing;

/// What a caller may see. The token is not in it, and there is no shape of
/// this endpoint that answers with one; there is always one held.
#[derive(Debug, Serialize)]
pub struct WhatsAppBrief {
    pub phone_number_id: String,
    pub template: String,
    pub languages: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct WhatsAppWrite {
    pub phone_number_id: String,
    pub template: String,
    pub languages: Vec<String>,
    /// Absent keeps whatever is held, so an administrator editing the
    /// template does not have to retype a token to keep it. Meta wants one
    /// on every call, so there is no way to forget it but to forget the
    /// settings.
    pub token: Option<String>,
}

/// Prove the business number works while the operator is still looking at the
/// form: one code, `000000`, sent with the held settings through Meta itself,
/// the refusal spoken back in words when it does not go.
#[derive(Deserialize)]
pub struct TestAsked {
    pub to: String,
    /// One of the languages the template was approved in; the first when
    /// absent.
    pub language: Option<String>,
}

pub async fn send_test(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    egress: web::Data<config::serving::Egress>,
    path: web::Path<String>,
    body: web::Json<TestAsked>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    if !asked.to.starts_with('+') || !asked.to[1..].chars().all(|held| held.is_ascii_digit()) {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "the test wants a number in international form, like +22890123456".to_owned(),
        ));
    }
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let ring = keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        &realm_id,
    )
    .await
    .map_err(|_| internal())?;
    let settings = services::admin::whatsapp::read(&transaction, &ring, &sealing.envelope)
        .await
        .map_err(|_| ApiError::new(ErrorCode::WhatsAppSettingsNotFound))?;
    // Given back before Meta is dialled, which lasts as long as Meta cares to
    // answer: held, it is a pooled connection nobody else can have.
    drop(transaction);

    let language = match asked.language {
        Some(language) if settings.languages.contains(&language) => language,
        Some(_) => {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                "the test speaks one of the languages the template was approved in".to_owned(),
            ));
        }
        None => settings.languages.first().cloned().unwrap_or_default(),
    };
    // Straight through Meta, never the deployment's sink: a logged sink would
    // print the code and prove nothing about the business number.
    use auth::messaging::WhatsAppSender;
    outbound::senders::MetaWhatsApp::new(**egress)
        .send_code(&settings, &asked.to, "000000", &language)
        .await
        .map_err(|_| {
            ApiError::with_detail(
                ErrorCode::ValidationError,
                "Meta refused: the number id, the token, the template or its language does \
                 not hold with these settings; the server log holds the exact refusal"
                    .to_owned(),
            )
        })?;
    Ok(HttpResponse::NoContent().finish())
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

    let view = services::admin::whatsapp::read(&transaction, &ring, &sealing.envelope)
        .await
        .map_err(refused)?
        .as_view();
    Ok(HttpResponse::Ok().json(WhatsAppBrief {
        phone_number_id: view.phone_number_id,
        template: view.template,
        languages: view.languages,
    }))
}

pub async fn write(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    asked: web::Json<WhatsAppWrite>,
) -> Result<HttpResponse, ApiError> {
    let asked = asked.into_inner();
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

    services::admin::whatsapp::write(
        &transaction,
        &ring,
        &sealing.envelope,
        services::admin::whatsapp::Wanted {
            phone_number_id: asked.phone_number_id,
            template: asked.template,
            languages: asked.languages,
            token: asked.token,
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
    services::admin::whatsapp::forget(&transaction)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// A refusal in the words of what was wrong, since the operator is the one
/// who can fix it.
fn refused(why: Unsettable) -> ApiError {
    match why {
        Unsettable::NotFound => ApiError::new(ErrorCode::WhatsAppSettingsNotFound),
        Unsettable::Unwritable => ApiError::new(ErrorCode::InternalError),
        spoken => ApiError::with_detail(ErrorCode::ValidationError, spoken.to_string()),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
