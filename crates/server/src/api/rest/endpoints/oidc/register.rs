//! Registration of a client through the protocol (RFC 7591), and the
//! management of what was registered (RFC 7592). Each answer is JSON that
//! no cache keeps. Metadata is read only from a body that says it is JSON.

use actix_web::http::StatusCode;
use actix_web::http::header::{CACHE_CONTROL, CONTENT_TYPE, PRAGMA};
use actix_web::web::Bytes;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, put, web};
use saffui_core::app::App as Product;
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::oidc::registration::{
    RegistrationAnswer, RegistrationRequest, check_metadata_media_type, delete_registered_client,
    read_registered_client, register_dynamic_client, update_registered_client,
};

use crate::error::render_registration_failure;
use crate::extract::bearer::read_bearer_token;
use crate::middleware::caller_address::read_caller_address;

/// The largest body a registration or a change of one reads, in bytes:
/// written here, since anyone may send one where the realm is open.
const REGISTRATION_BODY_LIMIT: usize = 32 * 1024;

fn render_registration(status: StatusCode, answer: RegistrationAnswer) -> HttpResponse {
    HttpResponse::build(status)
        .insert_header((CACHE_CONTROL, "no-store"))
        .insert_header((PRAGMA, "no-cache"))
        .json(answer.into_document())
}

/// Reads a body that says it is JSON, up to the limit, and no further. One
/// that says anything else is refused before a byte of it is read.
async fn read_body(request: &HttpRequest, payload: web::Payload) -> Result<Bytes, HttpResponse> {
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    check_metadata_media_type(content_type)
        .map_err(|failure| render_registration_failure(&failure))?;
    let unread = |why: &str| {
        render_registration_failure(
            &Failure::with_detail(ErrorCode::ClientMetadataInvalid, why.to_owned()).into(),
        )
    };
    match payload.to_bytes_limited(REGISTRATION_BODY_LIMIT).await {
        Ok(Ok(body)) => Ok(body),
        Ok(Err(_)) => Err(unread("a body cut short")),
        Err(_) => Err(unread("a body too large")),
    }
}

#[post("/realms/{realm}/oauth2/register")]
pub async fn create_registration(
    product: web::Data<Product>,
    realm: web::Path<String>,
    request: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    let body = match read_body(&request, payload).await {
        Ok(body) => body,
        Err(refusal) => return refusal,
    };
    let token = read_bearer_token(&request);
    let asked = RegistrationRequest {
        caller: read_caller_address(&product, &request),
        token: token.as_deref(),
        body: &body,
    };
    match register_dynamic_client(&product, &realm, asked).await {
        Ok(registered) => render_registration(StatusCode::CREATED, registered),
        Err(failure) => render_registration_failure(&failure),
    }
}

#[get("/realms/{realm}/oauth2/register/{client_id}")]
pub async fn read_registration(
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
    request: HttpRequest,
) -> HttpResponse {
    let (realm, client_id) = path.into_inner();
    let token = read_bearer_token(&request);
    match read_registered_client(&product, &realm, &client_id, token.as_deref()).await {
        Ok(read) => render_registration(StatusCode::OK, read),
        Err(failure) => render_registration_failure(&failure),
    }
}

#[put("/realms/{realm}/oauth2/register/{client_id}")]
pub async fn update_registration(
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
    request: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    let (realm, client_id) = path.into_inner();
    let body = match read_body(&request, payload).await {
        Ok(body) => body,
        Err(refusal) => return refusal,
    };
    let token = read_bearer_token(&request);
    let asked = RegistrationRequest {
        caller: read_caller_address(&product, &request),
        token: token.as_deref(),
        body: &body,
    };
    match update_registered_client(&product, &realm, &client_id, asked).await {
        Ok(updated) => render_registration(StatusCode::OK, updated),
        Err(failure) => render_registration_failure(&failure),
    }
}

#[delete("/realms/{realm}/oauth2/register/{client_id}")]
pub async fn delete_registration(
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
    request: HttpRequest,
) -> HttpResponse {
    let (realm, client_id) = path.into_inner();
    let token = read_bearer_token(&request);
    let caller = read_caller_address(&product, &request);
    match delete_registered_client(&product, &realm, &client_id, caller, token.as_deref()).await {
        Ok(()) => HttpResponse::NoContent()
            .insert_header((CACHE_CONTROL, "no-store"))
            .insert_header((PRAGMA, "no-cache"))
            .finish(),
        Err(failure) => render_registration_failure(&failure),
    }
}
