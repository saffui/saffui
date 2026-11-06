//! Whether a subject may take an action on a resource: a client that guards
//! the resource asks, with the token the subject presented to it.

use actix_web::http::header::{CACHE_CONTROL, PRAGMA};
use actix_web::{FromRequest, HttpRequest, HttpResponse, post, web};
use saffui_core::app::App as Product;
use saffui_core::authz::decide::{DecisionRequest, decide};
use saffui_core::error::ErrorCode;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::error::render_protocol_failure;
use crate::extract::client_credentials::{Presented, read_basic_header};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceQuestion {
    #[serde(rename = "type")]
    resource_type: String,
    id: Option<String>,
    #[serde(default)]
    attributes: Map<String, Value>,
}

// No `Debug`: the question carries a token.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionQuestion {
    subject_token: Option<String>,
    action: String,
    resource: ResourceQuestion,
}

/// Answers the question of a client that authenticates in the Basic scheme,
/// and in no other way: a secret is never read from a body. Nothing of the
/// body is read before the scheme is there, and a body that cannot be read
/// is refused in the dialect of the protocol.
#[post("/realms/{realm}/authz/decide")]
pub async fn ask_decision(
    product: web::Data<Product>,
    realm: web::Path<String>,
    request: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    let Presented::Credentials(credentials) = read_basic_header(&request) else {
        return render_protocol_failure(&ErrorCode::ClientAuthenticationFailed.into(), true);
    };
    let mut payload = payload.into_inner();
    let Ok(question) = web::Json::<DecisionQuestion>::from_request(&request, &mut payload).await
    else {
        return render_protocol_failure(&ErrorCode::RequestInvalid.into(), true);
    };
    let question = question.into_inner();
    let asked = DecisionRequest {
        subject_token: question.subject_token.as_deref(),
        action: &question.action,
        resource_type: &question.resource.resource_type,
        resource_id: question.resource.id.as_deref(),
        attributes: &question.resource.attributes,
    };
    match decide(
        &product,
        &realm,
        Some(&credentials.client_id),
        Some(credentials.secret),
        asked,
    )
    .await
    {
        Ok(decision) => HttpResponse::Ok()
            .insert_header((CACHE_CONTROL, "no-store"))
            .insert_header((PRAGMA, "no-cache"))
            .json(decision),
        Err(failure) => render_protocol_failure(&failure, true),
    }
}
