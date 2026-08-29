use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder};
use serde::{Deserialize, Serialize};

/// What a caller asks for. Form encoded per §4.1.3, every field optional here so
/// a missing one is `invalid_request` naming it rather than a 400 from the
/// parser.
#[derive(Debug, Default, Deserialize)]
pub struct Asked {
    /// RFC 7521 §4.2, when this is how the client authenticates.
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub code_verifier: Option<String>,
    /// RFC 8693 §2.1, when the grant is an exchange.
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub requested_token_type: Option<String>,
    pub audience: Option<String>,
}

/// A token, and what a client needs to use it.
#[derive(Debug, Serialize)]
pub struct Granted {
    pub access_token: String,
    /// Always `Bearer`, and stated: §5.1 requires it and a client switching on
    /// it finds nothing otherwise.
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// RFC 8693 §2.2.1, present only on an exchange.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<&'static str>,
}

/// Why nothing was granted. The codes are §5.2's, spelled exactly: one outside
/// that list has no branch in any client, so it reads as an unknown failure and
/// the caller retries what will never work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    /// RFC 9449 §5.2, and named by that RFC rather than folded into
    /// `invalid_request`: a client that sends a proof and gets told only that
    /// its request was invalid cannot tell the proof was the part refused.
    InvalidDpopProof,
}

impl Denied {
    pub fn code(self) -> &'static str {
        match self {
            Denied::InvalidRequest => "invalid_request",
            Denied::InvalidClient => "invalid_client",
            Denied::InvalidGrant => "invalid_grant",
            Denied::UnauthorizedClient => "unauthorized_client",
            Denied::UnsupportedGrantType => "unsupported_grant_type",
            Denied::InvalidScope => "invalid_scope",
            Denied::InvalidDpopProof => "invalid_dpop_proof",
        }
    }

    /// §5.2 singles out `invalid_client`: the failure is about who is asking
    /// rather than what was asked, and it is the one carrying
    /// `WWW-Authenticate`.
    fn status(self) -> StatusCode {
        match self {
            Denied::InvalidClient => StatusCode::UNAUTHORIZED,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    /// Rendered under §5.1's caching rules, refusals included: a cached token
    /// response is a token handed to whoever asks next.
    pub fn answer(self, description: &str) -> HttpResponse {
        let mut response = HttpResponseBuilder::new(self.status());
        if self == Denied::InvalidClient {
            response.insert_header(("WWW-Authenticate", "Basic realm=\"saffui\""));
        }
        uncached(&mut response).json(serde_json::json!({
            "error": self.code(),
            "error_description": description,
        }))
    }
}

/// Never store this, never serve it from a cache.
pub fn uncached(response: &mut HttpResponseBuilder) -> &mut HttpResponseBuilder {
    response
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Pragma", "no-cache"))
}
