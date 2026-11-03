//! The people of a realm.

pub mod create;
pub mod list;
pub mod store;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{ErrorCode, Failure};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Person {
    pub id: Uuid,
    /// What the person types to sign in. Lowercase: two spellings of one
    /// name are one person.
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
}

/// The shortest and the longest password, in bytes. The ceiling is not a
/// rule of strength: it bounds what one request can make the hasher chew.
pub const PASSWORD_MIN_BYTES: usize = 8;
pub const PASSWORD_MAX_BYTES: usize = 1024;

/// Reads a username as typed: trimmed and lowercased, then 1 to 64 letters,
/// digits, dots, hyphens or underscores that start and end with a letter or
/// a digit.
///
/// # Errors
///
/// Returns [`ErrorCode::UsernameInvalid`].
pub fn normalize_username(typed: &str) -> Result<String, Failure> {
    let username = typed.trim().to_ascii_lowercase();
    let inner =
        |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte);
    let edge = |byte: Option<u8>| {
        byte.is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    };
    let bytes = username.as_bytes();
    if (1..=64).contains(&bytes.len())
        && bytes.iter().copied().all(inner)
        && edge(bytes.first().copied())
        && edge(bytes.last().copied())
    {
        Ok(username)
    } else {
        Err(Failure::new(ErrorCode::UsernameInvalid))
    }
}

/// Reads an email address as typed: trimmed and lowercased. Only its shape
/// is checked: whether it exists is proven by writing to it.
///
/// # Errors
///
/// Returns [`ErrorCode::EmailInvalid`].
pub fn normalize_email(typed: &str) -> Result<String, Failure> {
    let email = typed.trim().to_lowercase();
    let well_formed = email.len() <= 254
        && !email
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.contains('@')
        });
    if well_formed {
        Ok(email)
    } else {
        Err(Failure::new(ErrorCode::EmailInvalid))
    }
}

/// Refuses a password before any work is spent on it.
///
/// # Errors
///
/// Returns [`ErrorCode::PasswordUnacceptable`].
pub fn check_password_bounds(password: &[u8]) -> Result<(), Failure> {
    if (PASSWORD_MIN_BYTES..=PASSWORD_MAX_BYTES).contains(&password.len()) {
        Ok(())
    } else {
        Err(Failure::new(ErrorCode::PasswordUnacceptable))
    }
}

#[cfg(test)]
mod tests {
    use super::{check_password_bounds, normalize_email, normalize_username};

    #[test]
    fn a_username_is_trimmed_and_lowercased_then_held_to_its_grammar() {
        assert_eq!(
            normalize_username("  Ada.Lovelace ").ok().as_deref(),
            Some("ada.lovelace")
        );
        assert_eq!(normalize_username("a").ok().as_deref(), Some("a"));
        for typed in [
            "",
            ".ada",
            "ada-",
            "ada lovelace",
            "ada@home",
            "adé",
            &"a".repeat(65),
        ] {
            assert!(normalize_username(typed).is_err(), "{typed:?}");
        }
    }

    #[test]
    fn an_email_is_lowercased_and_only_its_shape_is_checked() {
        assert_eq!(
            normalize_email(" Ada@Example.ORG ").ok().as_deref(),
            Some("ada@example.org")
        );
        for typed in [
            "",
            "ada",
            "@example.org",
            "ada@localhost",
            "a da@example.org",
            "a@b@c.org",
        ] {
            assert!(normalize_email(typed).is_err(), "{typed:?}");
        }
    }

    #[test]
    fn a_password_is_bounded_at_both_ends_before_anything_is_hashed() {
        assert!(check_password_bounds(b"1234567").is_err());
        assert!(check_password_bounds(b"12345678").is_ok());
        assert!(check_password_bounds(&[b'a'; 1024]).is_ok());
        assert!(check_password_bounds(&[b'a'; 1025]).is_err());
    }
}
