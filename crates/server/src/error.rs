//! The one place a refusal of the core becomes a response. The code of the
//! catalog is the only source of the status and of the message: the detail
//! goes to the journal and never leaves.

use actix_web::http::StatusCode;
use actix_web::http::header::{CACHE_CONTROL, PRAGMA, WWW_AUTHENTICATE};
use actix_web::{HttpRequest, HttpResponse};
use saffui_core::error::{ErrorCode, ErrorKind, Failure};
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

/// How the journal tells a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Journaled {
    /// The service failed.
    AsError,
    /// A client met a bound its own setting reaches: the detail names it.
    AsWarning,
    Not,
}

fn choose_journaling(code: ErrorCode) -> Journaled {
    match (code, code.kind()) {
        (_, ErrorKind::Unavailable | ErrorKind::Internal) => Journaled::AsError,
        (ErrorCode::ClaimsTooLarge | ErrorCode::HeldTooMany, _) => Journaled::AsWarning,
        _ => Journaled::Not,
    }
}

/// Writes a refusal to the journal, the detail included, when it is one to tell.
fn journal_failure(failure: &Failure) {
    let (code, detail) = (failure.code.slug(), failure.detail.as_deref());
    match choose_journaling(failure.code) {
        Journaled::AsError => tracing::error!(code, detail, "a request failed"),
        Journaled::AsWarning => tracing::warn!(code, detail, "a request met a bound"),
        Journaled::Not => {}
    }
}

/// Renders a refusal in the dialect of the administration plane.
pub(crate) fn render_failure(failure: &Failure) -> HttpResponse {
    let kind = failure.code.kind();
    journal_failure(failure);
    let mut response = HttpResponse::build(choose_status(kind));
    // A caller that was not authenticated is told which scheme to come back with.
    if kind == ErrorKind::Unauthenticated {
        response.insert_header((WWW_AUTHENTICATE, "Bearer"));
    }
    response.json(ErrorBody {
        code: failure.code.slug(),
        error_code: failure.code.number(),
        message: failure.code.message(),
    })
}

/// A JSON body that cannot be read, in the dialect of the administration plane.
pub(crate) fn refuse_unreadable_json(
    error: actix_web::error::JsonPayloadError,
    _request: &HttpRequest,
) -> actix_web::Error {
    let refusal = render_failure(&saffui_core::error::ErrorCode::RequestInvalid.into());
    actix_web::error::InternalError::from_response(error, refusal).into()
}

/// A query string that cannot be read, in the dialect of the administration plane.
pub(crate) fn refuse_unreadable_query(
    error: actix_web::error::QueryPayloadError,
    _request: &HttpRequest,
) -> actix_web::Error {
    let refusal = render_failure(&saffui_core::error::ErrorCode::RequestInvalid.into());
    actix_web::error::InternalError::from_response(error, refusal).into()
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
    journal_failure(&failure.cause);
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
        error_description: failure.describe(),
    })
}

#[cfg(test)]
mod tests {
    use saffui_core::error::ErrorCode;

    use super::{Journaled, choose_journaling};

    #[test]
    fn a_failure_of_the_service_is_an_error_a_bound_a_client_meets_a_warning() {
        assert_eq!(
            choose_journaling(ErrorCode::StorageUnavailable),
            Journaled::AsError
        );
        assert_eq!(choose_journaling(ErrorCode::Internal), Journaled::AsError);
        for bound in [ErrorCode::ClaimsTooLarge, ErrorCode::HeldTooMany] {
            assert_eq!(choose_journaling(bound), Journaled::AsWarning, "{bound:?}");
        }
        for refusal in [ErrorCode::RequestInvalid, ErrorCode::TokenInvalid] {
            assert_eq!(choose_journaling(refusal), Journaled::Not, "{refusal:?}");
        }
    }
}
