//! A draft of a realm's page wording, kept just long enough to look at.

use actix_web::{HttpResponse, web};
use chrono::{Duration, Utc};
use commons::error::ErrorCode;
use commons::http::ApiError;
use store::tenancy::Tenancy;

use crate::api::config::Sealing;
use crate::api::rest::endpoints::within;
use crate::middleware::admin_guard::Admin;

#[derive(serde::Deserialize)]
pub struct Drafting {
    pub overrides: serde_json::Value,
}

/// How long a draft is worth reading: long enough to open a tab and look,
/// short enough that a link left in a chat window is already dead.
const LOOKING: i64 = 600;

/// Keep what the console has not saved yet, so the page can be shown with it.
///
/// Weighed by the same guard that weighs saved wording, so nothing can be
/// previewed that saving would refuse. What makes the draft safe to open with
/// no bearer is not this door: it is that the page rendered from one cannot
/// submit anything.
pub async fn keep(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    body: web::Json<Drafting>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    crate::api::rest::endpoints::protocol::i18n::weigh_overrides(&asked.overrides)?;

    let mut drawn = [0_u8; 16];
    sealing
        .provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| internal())?;
    let preview_id = drawn
        .iter()
        .fold(String::with_capacity(32), |mut id, byte| {
            use std::fmt::Write as _;
            let _ = write!(id, "{byte:02x}");
            id
        });
    let expires_at = Utc::now() + Duration::seconds(LOOKING);

    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    store::providers::page_previews::keep(&transaction, &preview_id, &asked.overrides, expires_at)
        .await
        .map_err(|_| internal())?;
    transaction.commit().await.map_err(|_| internal())?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "preview_id": preview_id,
        "expires_at": expires_at,
    })))
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
