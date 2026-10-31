//! The one place a refusal of the core becomes a response. The code of the
//! catalog is the only source of the status and of the message: the detail
//! goes to the journal and never leaves.

use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use saffui_core::error::{ErrorKind, Failure};
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
