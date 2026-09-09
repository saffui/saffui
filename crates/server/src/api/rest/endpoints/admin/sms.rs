use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use services::admin::sms::Unsettable;
use store::keyring;
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

/// What a caller may see. The token is not in it, and there is no shape of
/// this endpoint that answers with one.
#[derive(Debug, Serialize)]
pub struct SmsBrief {
    pub url: String,
    pub sender: String,
    /// Whether a token is held. Not which one, and not how long it is.
    pub has_token: bool,
}

#[derive(Debug, Deserialize)]
pub struct SmsWrite {
    pub url: String,
    pub sender: String,
    /// Absent keeps whatever is held, so an administrator editing the URL
    /// does not have to retype a token to keep it. Present replaces it, and
    /// empty forgets it.
    pub token: Option<String>,
}

/// Prove the gateway works while the operator is still looking at the form:
/// one test text, sent with the held settings, the refusal spoken back in
/// words when it does not.
#[derive(serde::Deserialize)]
pub struct TestAsked {
    pub to: String,
}

pub async fn send_test(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    egress: web::Data<config::serving::Egress>,
    path: web::Path<String>,
    body: web::Json<TestAsked>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let to = body.into_inner().to;
    if !to.starts_with('+') || !to[1..].chars().all(|held| held.is_ascii_digit()) {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "the test wants a number in international form, like +22890123456".to_owned(),
        ));
    }
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    let ring = keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        &realm_id,
    )
    .await
    .map_err(|_| internal())?;
    let settings = services::admin::sms::read(&transaction, &ring, &sealing.envelope)
        .await
        .map_err(|_| ApiError::new(ErrorCode::SmsSettingsNotFound))?;

    let text = auth::messaging::Text {
        to,
        body: "This is the saffui SMS test. The settings that sent it are the \
               ones on the phone screen; nothing else was used."
            .to_owned(),
    };
    // Straight through the HTTP gateway, never the deployment's sink: a
    // logged sink would print the text and prove nothing about the gateway.
    // A green answer means the settings on screen actually carry texts.
    use auth::messaging::Texter;
    crate::messaging::HttpTexter::new(**egress)
        .text(&settings, &text)
        .await
        .map_err(|_| {
            ApiError::with_detail(
                ErrorCode::ValidationError,
                "the gateway refused: connection, TLS, authorization or delivery failed \
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

    let view = services::admin::sms::read(&transaction, &ring, &sealing.envelope)
        .await
        .map_err(refused)?
        .as_view();
    Ok(HttpResponse::Ok().json(SmsBrief {
        url: view.url,
        sender: view.sender,
        has_token: view.has_token,
    }))
}

pub async fn write(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    egress: web::Data<config::serving::Egress>,
    path: web::Path<String>,
    asked: web::Json<SmsWrite>,
) -> Result<HttpResponse, ApiError> {
    let asked = asked.into_inner();
    // What the dial will always refuse is refused now, in words. The
    // addresses behind the name are not judged here: names change after
    // they are written, so the resolver at each dial is what stands
    // between this URL and the deployment's own network.
    if *egress.get_ref() == config::serving::Egress::Outward && !asked.url.starts_with("https://") {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "an outward deployment posts to its gateway only over https".to_owned(),
        ));
    }
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

    services::admin::sms::write(
        &transaction,
        &ring,
        &sealing.envelope,
        services::admin::sms::Wanted {
            url: asked.url,
            sender: asked.sender,
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
    services::admin::sms::forget(&transaction)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

fn refused(why: Unsettable) -> ApiError {
    match why {
        Unsettable::NotFound => ApiError::new(ErrorCode::SmsSettingsNotFound),
        Unsettable::NotAGateway => ApiError::with_detail(
            ErrorCode::ValidationError,
            "the gateway wants an http or https URL".to_owned(),
        ),
        Unsettable::Unwritable => ApiError::new(ErrorCode::InternalError),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

/// What this realm has spent on texts today, and what its brakes held back.
///
/// Both numbers come off what the sending path already writes: the day
/// counter the daily cap reads, and the throttle log a brake writes when it
/// trips. Nothing is counted twice and nothing is counted here that the
/// engine does not count for itself, so the screen and the brake can never
/// disagree about the same day.
pub async fn spent_today(
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

    let now = chrono::Utc::now().timestamp();
    let sent = store::providers::sms::spent_today(&transaction, now)
        .await
        .map_err(|_| internal())?;
    let held = store::providers::sms::held_back_today(&transaction, now)
        .await
        .map_err(|_| internal())?;
    let realm = store::providers::realms::of_context(&transaction)
        .await
        .map_err(|_| internal())?;

    let counted = |named: &str| -> i64 {
        held.iter()
            .find(|(brake, _)| brake == named)
            .map_or(0, |(_, count)| *count)
    };
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "sent": sent,
        // Absent where the realm names no cap: the engine has its own, and
        // printing that one here would read as this realm's setting.
        "cap": realm.as_ref().and_then(|held| held.sms_daily_cap),
        "blocked_prefix": counted("blocked-prefix"),
        "number_velocity": counted("number-velocity"),
        "day_budget": counted("day-budget"),
    })))
}
