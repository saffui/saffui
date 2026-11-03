//! The dialect of the protocol plane. A refusal there is told in the words
//! of RFC 6749, whatever the catalog calls it.

use crate::error::{ErrorCode, ErrorKind, Failure};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuthError {
    InvalidRequest,
    InvalidClient,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidGrant,
    InvalidScope,
    UnsupportedResponseType,
    LoginRequired,
    ConsentRequired,
    ServerError,
    TemporarilyUnavailable,
}

impl OAuthError {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidScope => "invalid_scope",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

impl OAuthError {
    /// What a client is told beside the name of the error. One sentence per
    /// error, whatever caused it: the cause stays in the journal, so that an
    /// answer never tells an unknown realm from an unknown client.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::InvalidRequest => "The request is missing a parameter or carries one twice.",
            Self::InvalidClient => "Client authentication failed.",
            Self::UnauthorizedClient => "The client is not allowed this grant.",
            Self::UnsupportedGrantType => "This grant type is not served.",
            Self::InvalidGrant => "The grant is invalid, expired, or was already used.",
            Self::InvalidScope => "A scope that was asked for is unknown or not allowed.",
            Self::UnsupportedResponseType => "Only the code response type is served.",
            Self::LoginRequired => "The person must sign in.",
            Self::ConsentRequired => "Consent cannot be asked here yet.",
            Self::ServerError => "The request could not be completed.",
            Self::TemporarilyUnavailable => "The service is busy. Try again in a moment.",
        }
    }
}

/// A refusal of the protocol plane, and the refusal of the catalog behind it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthFailure {
    pub error: OAuthError,
    pub cause: Failure,
}

impl From<Failure> for OAuthFailure {
    fn from(cause: Failure) -> Self {
        let error = match cause.code {
            // An unknown realm answers as an unknown client: the token
            // endpoint does not tell which realms exist.
            ErrorCode::ClientAuthenticationFailed | ErrorCode::RealmNotFound => {
                OAuthError::InvalidClient
            }
            ErrorCode::ScopeInvalid | ErrorCode::ScopeNotAllowed => OAuthError::InvalidScope,
            ErrorCode::GrantNotAllowed => OAuthError::UnauthorizedClient,
            ErrorCode::GrantInvalid => OAuthError::InvalidGrant,
            ErrorCode::GrantTypeUnsupported => OAuthError::UnsupportedGrantType,
            other => match other.kind() {
                ErrorKind::Unavailable => OAuthError::TemporarilyUnavailable,
                ErrorKind::Internal => OAuthError::ServerError,
                _ => OAuthError::InvalidRequest,
            },
        };
        Self { error, cause }
    }
}

impl From<ErrorCode> for OAuthFailure {
    fn from(code: ErrorCode) -> Self {
        Failure::new(code).into()
    }
}
