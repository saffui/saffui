//! The catalog of refusals. A number is a public contract: it is never
//! reused, and the code is the only source of the message. The detail goes
//! to the journal and never into a response.

use std::fmt;

use crate::ports::storage::StorageError;

/// What kind of refusal a code is. The HTTP surface maps a kind to a status:
/// the heart knows no status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Invalid,
    /// The caller did not prove who it is.
    Unauthenticated,
    /// The caller proved who it is, and is not allowed this.
    Forbidden,
    NotFound,
    Conflict,
    Unavailable,
    Internal,
}

/// Ranges by domain: platform under 100, realm 100, user 200, client 300,
/// authentication 400, token 500, tenant 600, organization 700, credential 800.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    Internal = 1,
    StorageUnavailable = 2,
    Conflict = 3,
    RandomUnavailable = 4,
    CryptoUnavailable = 5,
    RequestInvalid = 6,
    ListOffsetTooLarge = 7,
    RealmNotFound = 100,
    RealmNameInvalid = 101,
    RealmNameTaken = 102,
    UsernameInvalid = 200,
    UsernameTaken = 201,
    EmailInvalid = 202,
    EmailTaken = 203,
    DisplayNameInvalid = 204,
    PasswordUnacceptable = 205,
    PersonNotFound = 206,
    ClientAuthenticationFailed = 300,
    ClientIdentifierInvalid = 301,
    ClientIdentifierTaken = 302,
    ClientNameInvalid = 303,
    ScopeInvalid = 304,
    ScopeNotAllowed = 305,
    GrantNotAllowed = 306,
    GrantTypeUnsupported = 307,
    ClientNotFound = 308,
    CapabilityUnknown = 309,
    RedirectUriInvalid = 310,
    RedirectUriMismatch = 311,
    AdminAuthenticationFailed = 400,
    CapabilityMissing = 401,
    SignInFailed = 402,
    HashingBusy = 403,
    AuthorizationRequestExpired = 404,
    SignInRequestsTooFrequent = 405,
    TokenInvalid = 500,
    GrantInvalid = 501,
    TokenScopeInsufficient = 502,
    TokenTypeUnsupported = 503,
    TenantNameInvalid = 600,
}

impl ErrorCode {
    #[must_use]
    pub fn number(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub fn kind(self) -> ErrorKind {
        match self {
            Self::Internal | Self::RandomUnavailable | Self::CryptoUnavailable => {
                ErrorKind::Internal
            }
            Self::StorageUnavailable | Self::HashingBusy | Self::SignInRequestsTooFrequent => {
                ErrorKind::Unavailable
            }
            Self::Conflict
            | Self::RealmNameTaken
            | Self::ClientIdentifierTaken
            | Self::UsernameTaken
            | Self::EmailTaken => ErrorKind::Conflict,
            Self::RealmNotFound | Self::ClientNotFound | Self::PersonNotFound => {
                ErrorKind::NotFound
            }
            Self::ClientAuthenticationFailed
            | Self::TokenInvalid
            | Self::AdminAuthenticationFailed
            | Self::SignInFailed => ErrorKind::Unauthenticated,
            Self::GrantNotAllowed | Self::CapabilityMissing | Self::TokenScopeInsufficient => {
                ErrorKind::Forbidden
            }
            Self::RealmNameInvalid
            | Self::TenantNameInvalid
            | Self::ClientIdentifierInvalid
            | Self::ClientNameInvalid
            | Self::ScopeInvalid
            | Self::RequestInvalid
            | Self::ScopeNotAllowed
            | Self::GrantTypeUnsupported
            | Self::ListOffsetTooLarge
            | Self::CapabilityUnknown
            | Self::UsernameInvalid
            | Self::EmailInvalid
            | Self::DisplayNameInvalid
            | Self::PasswordUnacceptable
            | Self::RedirectUriInvalid
            | Self::RedirectUriMismatch
            | Self::AuthorizationRequestExpired
            | Self::GrantInvalid
            | Self::TokenTypeUnsupported => ErrorKind::Invalid,
        }
    }

    /// The stable name clients match on.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::Internal => "platform.internal",
            Self::StorageUnavailable => "platform.storage_unavailable",
            Self::Conflict => "platform.conflict",
            Self::RandomUnavailable => "platform.random_unavailable",
            Self::CryptoUnavailable => "platform.crypto_unavailable",
            Self::RequestInvalid => "platform.request_invalid",
            Self::ListOffsetTooLarge => "platform.list_offset_too_large",
            Self::RealmNotFound => "realm.not_found",
            Self::RealmNameInvalid => "realm.name_invalid",
            Self::RealmNameTaken => "realm.name_taken",
            Self::UsernameInvalid => "user.username_invalid",
            Self::UsernameTaken => "user.username_taken",
            Self::EmailInvalid => "user.email_invalid",
            Self::EmailTaken => "user.email_taken",
            Self::DisplayNameInvalid => "user.display_name_invalid",
            Self::PasswordUnacceptable => "user.password_unacceptable",
            Self::ClientAuthenticationFailed => "client.authentication_failed",
            Self::ClientIdentifierInvalid => "client.identifier_invalid",
            Self::ClientIdentifierTaken => "client.identifier_taken",
            Self::ClientNameInvalid => "client.name_invalid",
            Self::ScopeInvalid => "client.scope_invalid",
            Self::ScopeNotAllowed => "client.scope_not_allowed",
            Self::GrantNotAllowed => "client.grant_not_allowed",
            Self::GrantTypeUnsupported => "client.grant_type_unsupported",
            Self::ClientNotFound => "client.not_found",
            Self::PersonNotFound => "user.not_found",
            Self::CapabilityUnknown => "client.capability_unknown",
            Self::RedirectUriInvalid => "client.redirect_uri_invalid",
            Self::RedirectUriMismatch => "client.redirect_uri_mismatch",
            Self::TokenInvalid => "token.invalid",
            Self::GrantInvalid => "token.grant_invalid",
            Self::TokenScopeInsufficient => "token.scope_insufficient",
            Self::TokenTypeUnsupported => "token.type_unsupported",
            Self::AdminAuthenticationFailed => "auth.admin_authentication_failed",
            Self::CapabilityMissing => "auth.capability_missing",
            Self::SignInFailed => "auth.sign_in_failed",
            Self::HashingBusy => "auth.hashing_busy",
            Self::AuthorizationRequestExpired => "auth.request_expired",
            Self::SignInRequestsTooFrequent => "auth.sign_in_requests_too_frequent",
            Self::TenantNameInvalid => "tenant.name_invalid",
        }
    }

    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::Internal | Self::RandomUnavailable | Self::CryptoUnavailable => {
                "The request could not be completed."
            }
            Self::StorageUnavailable => "The service is temporarily unavailable.",
            Self::Conflict => "The request conflicts with what exists.",
            Self::RealmNotFound => "No such realm.",
            Self::RealmNameInvalid => {
                "A realm name is 1 to 63 lowercase letters, digits or hyphens, and neither starts nor ends with a hyphen."
            }
            Self::RealmNameTaken => "This realm name is already taken.",
            Self::UsernameInvalid => {
                "A username is 1 to 64 letters, digits, dots, hyphens or underscores, and starts and ends with a letter or a digit."
            }
            Self::UsernameTaken => "This username is already taken.",
            Self::EmailInvalid => "This is not an email address.",
            Self::EmailTaken => "This email address is already taken.",
            Self::DisplayNameInvalid => {
                "A display name is at most 120 characters, none of them a control or a format character."
            }
            Self::PasswordUnacceptable => "A password is 8 to 1024 bytes long.",
            Self::SignInFailed => "The name or the password is wrong.",
            Self::HashingBusy => "The service is busy. Try again in a moment.",
            Self::AuthorizationRequestExpired => {
                "This sign-in has expired. Start again from the application."
            }
            Self::SignInRequestsTooFrequent => {
                "Too many sign-ins were started from here. Try again in a few minutes."
            }
            Self::RedirectUriMismatch => "The redirect URI is not one the client registered.",
            Self::RequestInvalid => "The request is missing a parameter or carries one it cannot.",
            Self::ClientAuthenticationFailed => "Client authentication failed.",
            Self::ScopeNotAllowed => "The client is not allowed a scope it asked for.",
            Self::GrantNotAllowed => "The client is not allowed this grant.",
            Self::GrantTypeUnsupported => "This grant type is not supported.",
            Self::ListOffsetTooLarge => "A list starts at 100000 at the latest: narrow it instead.",
            Self::ClientNotFound => "No such client.",
            Self::PersonNotFound => "No such person.",
            Self::CapabilityUnknown => "A capability that was asked for does not exist.",
            Self::RedirectUriInvalid => {
                "A redirect URI is an https URL, or an http URL of this machine, without a fragment."
            }
            Self::TokenInvalid => "The token is not valid.",
            Self::GrantInvalid => "The grant is invalid, expired, or was already used.",
            Self::TokenScopeInsufficient => "The token was not granted what this asks.",
            Self::TokenTypeUnsupported => "A token of this type cannot be revoked.",
            Self::AdminAuthenticationFailed => "Authentication is required.",
            Self::CapabilityMissing => "The caller is not allowed to do this.",
            Self::ClientIdentifierInvalid => {
                "A client identifier is 1 to 64 letters, digits, hyphens, dots or underscores."
            }
            Self::ClientIdentifierTaken => "This client identifier is already taken.",
            Self::ClientNameInvalid => {
                "A client name is 1 to 120 characters, none of them a control or a format character."
            }
            Self::ScopeInvalid => {
                "A scope is 1 to 64 printable characters, without a space or a quote."
            }
            Self::TenantNameInvalid => {
                "A tenant name is 1 to 120 characters, none of them a control character."
            }
        }
    }
}

/// A refusal of a use case: the code, and what only the journal may read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub code: ErrorCode,
    pub detail: Option<String>,
}

impl Failure {
    #[must_use]
    pub fn new(code: ErrorCode) -> Self {
        Self { code, detail: None }
    }

    #[must_use]
    pub fn with_detail(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: Some(detail.into()),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.slug())?;
        if let Some(detail) = &self.detail {
            write!(formatter, ": {detail}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Failure {}

impl From<ErrorCode> for Failure {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

impl From<StorageError> for Failure {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::Unavailable(reason) => {
                Self::with_detail(ErrorCode::StorageUnavailable, reason.to_string())
            }
            StorageError::Taken(what) => Self::with_detail(ErrorCode::Conflict, what),
            StorageError::Failed => Self::new(ErrorCode::Internal),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::ErrorCode;

    const ALL: [ErrorCode; 40] = [
        ErrorCode::Internal,
        ErrorCode::StorageUnavailable,
        ErrorCode::Conflict,
        ErrorCode::RandomUnavailable,
        ErrorCode::CryptoUnavailable,
        ErrorCode::RequestInvalid,
        ErrorCode::ListOffsetTooLarge,
        ErrorCode::RealmNotFound,
        ErrorCode::RealmNameInvalid,
        ErrorCode::RealmNameTaken,
        ErrorCode::UsernameInvalid,
        ErrorCode::UsernameTaken,
        ErrorCode::EmailInvalid,
        ErrorCode::EmailTaken,
        ErrorCode::DisplayNameInvalid,
        ErrorCode::PasswordUnacceptable,
        ErrorCode::ClientAuthenticationFailed,
        ErrorCode::ClientIdentifierInvalid,
        ErrorCode::ClientIdentifierTaken,
        ErrorCode::ClientNameInvalid,
        ErrorCode::ScopeInvalid,
        ErrorCode::ScopeNotAllowed,
        ErrorCode::GrantNotAllowed,
        ErrorCode::GrantTypeUnsupported,
        ErrorCode::ClientNotFound,
        ErrorCode::PersonNotFound,
        ErrorCode::CapabilityUnknown,
        ErrorCode::RedirectUriInvalid,
        ErrorCode::RedirectUriMismatch,
        ErrorCode::TokenInvalid,
        ErrorCode::GrantInvalid,
        ErrorCode::TokenScopeInsufficient,
        ErrorCode::TokenTypeUnsupported,
        ErrorCode::AdminAuthenticationFailed,
        ErrorCode::CapabilityMissing,
        ErrorCode::SignInFailed,
        ErrorCode::HashingBusy,
        ErrorCode::AuthorizationRequestExpired,
        ErrorCode::SignInRequestsTooFrequent,
        ErrorCode::TenantNameInvalid,
    ];

    #[test]
    fn no_two_codes_share_a_number_or_a_slug() {
        let numbers: HashSet<u32> = ALL.iter().map(|code| code.number()).collect();
        let slugs: HashSet<&str> = ALL.iter().map(|code| code.slug()).collect();

        assert_eq!(numbers.len(), ALL.len());
        assert_eq!(slugs.len(), ALL.len());
    }

    #[test]
    fn a_slug_starts_with_the_domain_its_number_range_belongs_to() {
        for code in ALL {
            let domain = match code.number() {
                0..100 => "platform.",
                100..200 => "realm.",
                200..300 => "user.",
                300..400 => "client.",
                400..500 => "auth.",
                500..600 => "token.",
                600..700 => "tenant.",
                other => panic!("no domain is written for {other}"),
            };
            assert!(code.slug().starts_with(domain), "{}", code.slug());
        }
    }
}
