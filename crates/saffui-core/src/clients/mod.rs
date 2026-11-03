//! The clients of a realm: the applications and services allowed to ask it
//! for tokens.

pub mod authenticate;
pub mod register;
pub mod store;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::authz::capability::Capability;
use crate::error::{ErrorCode, Failure};
use crate::ports::storage::{StorageError, UnitOfWork};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    pub id: Uuid,
    /// The public identifier, unique in its realm.
    pub client_id: String,
    pub name: String,
    /// The digest of the secret the realm generated. The secret itself is
    /// shown once, when it is made, and kept nowhere.
    pub secret_digest: Vec<u8>,
    /// A grant that is not written here is refused.
    pub allows_client_credentials: bool,
    /// The scopes the client may be given.
    pub scopes: Vec<String>,
    /// What the client may do on the administration plane of its realm.
    pub capabilities: Vec<Capability>,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
}

/// Checks a client identifier: 1 to 64 letters, digits, hyphens, dots or
/// underscores. No colon, so that it survives the Basic scheme unescaped.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientIdentifierInvalid`].
pub fn check_client_identifier(text: &str) -> Result<(), Failure> {
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || b"-._".contains(&byte);
    // A token issued to a service names it as its subject. An identifier in
    // the shape of a person's would let a service be taken for that person.
    let shaped_as_a_person = Uuid::parse_str(text).is_ok();
    if (1..=64).contains(&text.len()) && text.bytes().all(allowed) && !shaped_as_a_person {
        Ok(())
    } else {
        Err(Failure::new(ErrorCode::ClientIdentifierInvalid))
    }
}

/// Checks a scope token as RFC 6749 writes it: printable ASCII, no space, no
/// quote, no backslash.
///
/// # Errors
///
/// Returns [`ErrorCode::ScopeInvalid`].
pub fn check_scope_token(text: &str) -> Result<(), Failure> {
    let allowed = |byte: u8| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e);
    if (1..=64).contains(&text.len()) && text.bytes().all(allowed) {
        Ok(())
    } else {
        Err(Failure::new(ErrorCode::ScopeInvalid))
    }
}

/// Reads the client a caller names. What is not written as a client
/// identifier names no client, and is never sent to the storage.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn read_named_client(
    work: &mut dyn UnitOfWork,
    client_id: &str,
) -> Result<Option<Client>, StorageError> {
    if check_client_identifier(client_id).is_err() {
        return Ok(None);
    }
    work.read_client(client_id).await
}

#[cfg(test)]
mod tests {
    use super::{check_client_identifier, check_scope_token};

    #[test]
    fn an_identifier_in_the_shape_of_a_person_or_with_a_byte_no_client_writes_is_refused() {
        for refused in [
            "0198c2f4-7a3e-7c11-9b6e-2f1d3c4b5a69",
            "0198C2F47A3E7C119B6E2F1D3C4B5A69",
            "portal\0",
            "por tal",
            "billing:admin",
            "",
        ] {
            assert!(check_client_identifier(refused).is_err(), "{refused:?}");
        }
        assert!(check_client_identifier("portal-2.web_app").is_ok());
    }

    #[test]
    fn a_scope_is_printable_without_a_space_a_quote_or_a_backslash() {
        for refused in ["", "a b", "a\"b", "a\\b", "é"] {
            assert!(check_scope_token(refused).is_err(), "{refused:?}");
        }
        for accepted in ["invoices:read", "openid", "a!#[]~"] {
            assert!(check_scope_token(accepted).is_ok(), "{accepted:?}");
        }
    }
}
