//! Tenants and realms. A tenant is the account that hosts realms: residency
//! and isolation follow it. A realm is a security domain: its own keys, its
//! own issuer. The two are never merged.

pub mod realm;
pub mod resolve;
pub mod scope;
pub mod store;

use std::fmt;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{ErrorCode, Failure};

pub use scope::RealmScope;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TenantId(Uuid);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RealmId(Uuid);

impl TenantId {
    #[must_use]
    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    #[must_use]
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl RealmId {
    #[must_use]
    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    #[must_use]
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// The name of a realm, as it appears in every URL of the realm and in its
/// issuer. One label of a host name: nothing in it needs escaping anywhere.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RealmName(String);

impl RealmName {
    /// Reads a realm name.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::RealmNameInvalid`] for anything but 1 to 63
    /// lowercase letters, digits or hyphens, with no hyphen at either end.
    pub fn parse(text: &str) -> Result<Self, Failure> {
        let allowed = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-';
        let well_formed = (1..=63).contains(&text.len())
            && text.bytes().all(allowed)
            && !text.starts_with('-')
            && !text.ends_with('-');
        if well_formed {
            Ok(Self(text.to_owned()))
        } else {
            Err(Failure::new(ErrorCode::RealmNameInvalid))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RealmName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant {
    pub id: TenantId,
    pub name: String,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Realm {
    pub id: RealmId,
    pub tenant: TenantId,
    pub name: RealmName,
    /// A disabled realm answers as if it did not exist.
    pub enabled: bool,
    pub created_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::RealmName;
    use crate::error::ErrorCode;

    #[test]
    fn a_host_label_is_a_realm_name() {
        for text in ["a", "acme", "acme-prod", "7eleven", &"a".repeat(63)] {
            assert_eq!(
                RealmName::parse(text).map(|name| name.to_string()),
                Ok(text.to_owned())
            );
        }
    }

    #[test]
    fn anything_that_would_need_escaping_or_folding_is_refused() {
        for text in [
            "",
            "Acme",
            "acme prod",
            "acme/prod",
            "acme.prod",
            "-acme",
            "acme-",
            "acmé",
            "acme%2f",
            &"a".repeat(64),
        ] {
            let refused = RealmName::parse(text).map_err(|failure| failure.code);
            assert_eq!(refused, Err(ErrorCode::RealmNameInvalid), "{text:?}");
        }
    }
}
