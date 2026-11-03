//! The one place a refusal of the core becomes a response. The code of the
//! catalog is the only source of the status and of the message: the detail
//! goes to the journal and never leaves.

use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use actix_web::http::header::{CACHE_CONTROL, PRAGMA, WWW_AUTHENTICATE};
use saffui_core::error::{ErrorKind, Failure};
use saffui_core::oidc::errors::{OAuthError, OAuthFailure};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    error_code: u32,
    message: &'static str,
}

fn choose_status(kind: ErrorKind) -> StatusCode {
    match kind {
        ErrorKind::Invalid => StatusCode::BAD_REQUEST,
        ErrorKind::Unauthenticated => StatusCode::UNAUTHORIZED,
        ErrorKind::Forbidden => StatusCode::FORBIDDEN,
        ErrorKind::NotFound => StatusCode::NOT_FOUND,
        ErrorKind::Conflict => StatusCode::CONFLICT,
        // A database that is down is never the caller's fault.
        ErrorKind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Renders a refusal as the data plane answers it today.
pub(crate) fn render_failure(failure: &Failure) -> HttpResponse {
    let kind = failure.code.kind();
    if matches!(kind, ErrorKind::Unavailable | ErrorKind::Internal) {
        tracing::error!(
            code = failure.code.slug(),
            detail = failure.detail.as_deref(),
            "a request failed"
        );
    }
    HttpResponse::build(choose_status(kind)).json(ErrorBody {
        code: failure.code.slug(),
        error_code: failure.code.number(),
        message: failure.code.message(),
    })
}

#[derive(Serialize)]
struct OAuthErrorBody {
    error: &'static str,
    error_description: &'static str,
}

/// Renders a refusal in the dialect of the protocol plane (RFC 6749). Nothing
/// a token endpoint answers may be kept by a cache, a refusal included.
pub(crate) fn render_protocol_failure(
    failure: &OAuthFailure,
    asked_with_basic: bool,
) -> HttpResponse {
    let status = match failure.error {
        OAuthError::InvalidClient => StatusCode::UNAUTHORIZED,
        OAuthError::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        OAuthError::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    if status.is_server_error() {
        tracing::error!(
            code = failure.cause.code.slug(),
            detail = failure.cause.detail.as_deref(),
            "a protocol request failed"
        );
    }
    let mut response = HttpResponse::build(status);
    response
        .insert_header((CACHE_CONTROL, "no-store"))
        .insert_header((PRAGMA, "no-cache"));
    // A client that tried the Basic scheme is told which scheme failed.
    if failure.error == OAuthError::InvalidClient && asked_with_basic {
        response.insert_header((WWW_AUTHENTICATE, "Basic"));
    }
    response.json(OAuthErrorBody {
        error: failure.error.name(),
        error_description: failure.error.describe(),
    })
}
