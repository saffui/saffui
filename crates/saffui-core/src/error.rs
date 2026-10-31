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
    RealmNotFound = 100,
    RealmNameInvalid = 101,
    RealmNameTaken = 102,
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
            Self::Internal | Self::RandomUnavailable => ErrorKind::Internal,
            Self::StorageUnavailable => ErrorKind::Unavailable,
            Self::Conflict | Self::RealmNameTaken => ErrorKind::Conflict,
            Self::RealmNotFound => ErrorKind::NotFound,
            Self::RealmNameInvalid | Self::TenantNameInvalid => ErrorKind::Invalid,
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
            Self::RealmNotFound => "realm.not_found",
            Self::RealmNameInvalid => "realm.name_invalid",
            Self::RealmNameTaken => "realm.name_taken",
            Self::TenantNameInvalid => "tenant.name_invalid",
        }
    }

    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::Internal | Self::RandomUnavailable => "The request could not be completed.",
            Self::StorageUnavailable => "The service is temporarily unavailable.",
            Self::Conflict => "The request conflicts with what exists.",
            Self::RealmNotFound => "No such realm.",
            Self::RealmNameInvalid => {
                "A realm name is 1 to 63 lowercase letters, digits or hyphens, and neither starts nor ends with a hyphen."
            }
            Self::RealmNameTaken => "This realm name is already taken.",
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

    const ALL: [ErrorCode; 8] = [
        ErrorCode::Internal,
        ErrorCode::StorageUnavailable,
        ErrorCode::Conflict,
        ErrorCode::RandomUnavailable,
        ErrorCode::RealmNotFound,
        ErrorCode::RealmNameInvalid,
        ErrorCode::RealmNameTaken,
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
                600..700 => "tenant.",
                other => panic!("no domain is written for {other}"),
            };
            assert!(code.slug().starts_with(domain), "{}", code.slug());
        }
    }
}
