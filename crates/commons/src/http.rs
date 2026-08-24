use actix_web::body::BoxBody;
use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;

use crate::error::ErrorCode;

/// What a client sees.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ErrorBody {
    pub error_code: &'static str,
    pub message: String,
}

/// A catalogued error on its way out.
#[derive(Debug)]
pub struct ApiError {
    code: ErrorCode,
    message: String,
    /// Held server-side and logged, never serialised.
    detail: Option<String>,
}

impl ApiError {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            message: code.message().to_string(),
            detail: None,
        }
    }

    /// Attach a detail.
    ///
    /// For an internal error the detail stays server-side: the client reads the
    /// catalogue's generic message, and the specific string — usually a raw
    /// failure from something underneath — is logged when the response is
    /// built. For every other code the detail *is* the client-facing message,
    /// which is why a caller must not put a raw failure behind one.
    pub fn with_detail(code: ErrorCode, detail: impl Into<String>) -> Self {
        let detail = detail.into();

        if code == ErrorCode::InternalError {
            Self {
                code,
                message: code.message().to_string(),
                detail: Some(detail),
            }
        } else {
            Self {
                code,
                message: detail,
                detail: None,
            }
        }
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// The body, without the detail by construction.
    pub fn body(&self) -> ErrorBody {
        ErrorBody {
            error_code: self.code.slug(),
            message: self.message.clone(),
        }
    }
}

impl std::fmt::Display for ApiError {
    /// The catalogue's message, never the detail: this is what a `?` prints.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.slug(), self.message)
    }
}

impl std::error::Error for ApiError {}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        // The catalogue holds a `u16` so it stays free of this crate. A status
        // it could not represent is a catalogue bug, and 500 is the honest
        // answer to one.
        StatusCode::from_u16(self.code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        if let Some(detail) = &self.detail {
            log::error!("[{}] {}: {detail}", self.code.status(), self.code.slug());
        }

        HttpResponse::build(self.status_code()).json(self.body())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::body::MessageBody;

    fn rendered(error: &ApiError) -> (u16, serde_json::Value) {
        let response = error.error_response();
        let status = response.status().as_u16();
        let bytes = response.into_body().try_into_bytes().unwrap();

        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// A catalogued error renders its own slug, message and status.
    #[test]
    fn an_error_renders_what_the_catalogue_says() {
        for code in [
            ErrorCode::UserNotFound,
            ErrorCode::AccessDenied,
            ErrorCode::TooManyRequests,
        ] {
            let (status, body) = rendered(&ApiError::new(code));

            assert_eq!(status, code.status(), "{code:?}");
            assert_eq!(body["error_code"], code.slug(), "{code:?}");
            assert_eq!(body["message"], code.message(), "{code:?}");
        }
    }

    /// An internal error never carries its detail to the client.
    ///
    /// The detail is whatever failed underneath — a connection string, a file
    /// path, a driver message. It is logged and it stays there.
    #[test]
    fn an_internal_detail_does_not_reach_the_client() {
        let error = ApiError::with_detail(
            ErrorCode::InternalError,
            "connection to postgres://user:hunter2@db refused",
        );

        let (status, body) = rendered(&error);

        assert_eq!(status, 500);
        assert_eq!(body["message"], ErrorCode::InternalError.message());
        assert!(!body.to_string().contains("hunter2"));
        assert!(!body.to_string().contains("postgres"));
        // Nor through Display, which is what a `?` prints into a log line that
        // may itself be echoed.
        assert!(!error.to_string().contains("hunter2"));
    }

    /// A client-safe code carries its detail as the message, keeping the slug
    /// and the status the catalogue fixes.
    #[test]
    fn a_client_safe_detail_becomes_the_message() {
        let error = ApiError::with_detail(ErrorCode::ValidationError, "field 'email' is required");
        let (status, body) = rendered(&error);

        assert_eq!(status, ErrorCode::ValidationError.status());
        assert_eq!(body["error_code"], ErrorCode::ValidationError.slug());
        assert_eq!(body["message"], "field 'email' is required");
    }

    /// The body holds these two members and nothing else, so a detail cannot
    /// arrive through a field added later.
    #[test]
    fn the_body_holds_only_what_it_should() {
        let (_, body) = rendered(&ApiError::with_detail(ErrorCode::InternalError, "secret"));
        let members = body.as_object().unwrap();

        assert_eq!(members.len(), 2, "{body}");
        assert!(members.contains_key("error_code") && members.contains_key("message"));
    }

    /// Every code in the catalogue renders with a status actix accepts.
    ///
    /// The catalogue holds a `u16` to stay free of this crate, so nothing there
    /// stops a number actix would refuse — this is where that would show.
    #[test]
    fn every_code_renders_with_a_real_status() {
        for code in ErrorCode::ALL {
            let error = ApiError::new(*code);

            assert_eq!(
                error.status_code().as_u16(),
                code.status(),
                "{code:?} fell back to 500"
            );
        }
    }
}
