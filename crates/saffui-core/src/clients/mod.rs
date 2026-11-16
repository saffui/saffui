//! The clients of a realm: the applications and services allowed to ask it
//! for tokens.

pub mod assertion;
pub mod authenticate;
pub mod manage;
pub mod register;
pub mod store;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::authz::capability::Capability;
use crate::error::{ErrorCode, Failure};
use crate::ports::crypto::SignatureAlgorithm;
use crate::ports::storage::{StorageError, UnitOfWork};

/// How a client proves itself where it asks about tokens. The method it
/// registered is the only one it may prove itself with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuthMethod {
    /// Its secret, in the Basic scheme of the `Authorization` header.
    ClientSecretBasic,
    /// Its secret, in the body of the form.
    ClientSecretPost,
    /// An assertion signed with its secret (RFC 7523).
    ClientSecretJwt,
    /// An assertion signed with a key it registered (RFC 7523).
    PrivateKeyJwt,
    /// Nothing: a public client only names itself.
    None,
}

impl ClientAuthMethod {
    pub const ALL: [Self; 5] = [
        Self::ClientSecretBasic,
        Self::ClientSecretPost,
        Self::ClientSecretJwt,
        Self::PrivateKeyJwt,
        Self::None,
    ];

    /// The name RFC 7591 gives it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretJwt => "client_secret_jwt",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::None => "none",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|method| method.name() == name)
    }

    /// Whether a client of this method keeps a secret: the two that present
    /// it, and the one that signs with it. Only they are given one, or a new
    /// one. Named one by one: a method added later keeps none until it says.
    #[must_use]
    pub fn keeps_secret(self) -> bool {
        match self {
            Self::ClientSecretBasic | Self::ClientSecretPost | Self::ClientSecretJwt => true,
            Self::PrivateKeyJwt | Self::None => false,
        }
    }
}

/// What signs the assertion of a client: its secret, or one of its keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssertionAlgorithm {
    /// HMAC with SHA-256, keyed by the secret.
    Hs256,
    Signed(SignatureAlgorithm),
}

impl AssertionAlgorithm {
    /// The name it has in the header of an assertion.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Hs256 => "HS256",
            Self::Signed(algorithm) => algorithm.name(),
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        if name == Self::Hs256.name() {
            return Some(Self::Hs256);
        }
        SignatureAlgorithm::parse(name).map(Self::Signed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each is a column of its own: a grant refused, a consent not asked, unless written"
)]
pub struct Client {
    pub id: Uuid,
    /// The public identifier, unique in its realm.
    pub client_id: String,
    pub name: String,
    /// How it proves itself. What it proves itself with is kept apart.
    pub auth_method: ClientAuthMethod,
    /// The one algorithm its assertions may be signed in, when it named one.
    pub auth_signing_alg: Option<AssertionAlgorithm>,
    /// A grant that is not written here is refused.
    pub allows_client_credentials: bool,
    pub allows_authorization_code: bool,
    /// Where a person may be sent back. Compared by exact equality: an empty
    /// list sends nobody anywhere.
    pub redirect_uris: Vec<String>,
    /// Where a person may be sent after signing out, by exact equality too.
    pub post_logout_redirect_uris: Vec<String>,
    /// Each person is asked before the client gets a code in their name, and
    /// asked again for a scope they did not allow it.
    pub requires_consent: bool,
    /// The scopes the client may be given.
    pub scopes: Vec<String>,
    /// What the client may do on the administration plane of its realm.
    pub capabilities: Vec<Capability>,
    /// The algorithm of its identity tokens. None: the default of the realm.
    pub id_token_signed_response_alg: Option<SignatureAlgorithm>,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
}

impl Client {
    /// A public client keeps no secret and holds no key: it proves nothing.
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.auth_method == ClientAuthMethod::None
    }
}

/// What the realm keeps to check that a client is who it says, in the form
/// its method needs. It is read with the client by the one statement that
/// identifies it, and by no other: a client read for anything else carries
/// none of it.
// No `Debug` and no `Clone`: it is what a client proves itself with.
pub struct KeptProof {
    /// The digest of a secret the client presents. The secret itself is
    /// shown once, when it is made.
    pub secret_digest: Option<Vec<u8>>,
    /// A secret the client signs its assertions with, sealed for its row.
    pub sealed_secret: Option<Vec<u8>>,
    /// The public keys of a client that signs with a key, each written with
    /// the one algorithm it verifies in.
    pub jwks: Option<serde_json::Value>,
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

/// Checks a redirect URI at registration: an https URL, or an http URL of
/// this machine, with a host, without a fragment or credentials.
///
/// # Errors
///
/// Returns [`ErrorCode::RedirectUriInvalid`].
pub fn check_redirect_uri(text: &str) -> Result<(), Failure> {
    let invalid = || Failure::new(ErrorCode::RedirectUriInvalid);
    let plain = text.len() <= 2000
        && !text.contains('#')
        && !text
            .chars()
            .any(|character| character.is_whitespace() || character.is_control());
    let (secure, rest) = if let Some(rest) = text.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = text.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(invalid());
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    let host = match authority.rsplit_once(']') {
        Some((address, _port)) => address.trim_start_matches('['),
        None => authority.split(':').next().unwrap_or_default(),
    };
    let local = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if plain && !host.is_empty() && !authority.contains('@') && (secure || local) {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// Whether a page cannot show a character as it is: a control, a format
/// character of Unicode 16 and 17 (category Cf, which reorders or hides what
/// is around it), or a line or paragraph separator. A name that holds one
/// could be read as another.
#[must_use]
pub fn is_unshowable(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{ad}'
                | '\u{600}'..='\u{605}'
                | '\u{61c}'
                | '\u{6dd}'
                | '\u{70f}'
                | '\u{890}'..='\u{891}'
                | '\u{8e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
}

/// Writes a text a page shows with each character it cannot show as it is
/// replaced by U+FFFD: a name written by whoever registered a client never
/// reorders or hides what is around it.
#[must_use]
pub fn neutralize_unshowable(text: &str) -> String {
    text.chars()
        .map(|character| {
            if is_unshowable(character) {
                char::REPLACEMENT_CHARACTER
            } else {
                character
            }
        })
        .collect()
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
    use super::{
        check_client_identifier, check_redirect_uri, check_scope_token, is_unshowable,
        neutralize_unshowable,
    };

    #[test]
    fn an_https_url_and_an_http_url_of_this_machine_may_be_registered() {
        for uri in [
            "https://app.example.org/callback",
            "https://app.example.org/callback?tenant=a",
            "http://localhost:3000/callback",
            "http://127.0.0.1/callback",
            "http://[::1]:8080/cb",
        ] {
            assert!(check_redirect_uri(uri).is_ok(), "{uri}");
        }
    }

    #[test]
    fn a_fragment_a_clear_remote_host_another_scheme_or_credentials_are_refused() {
        for uri in [
            "https://app.example.org/callback#fragment",
            "http://app.example.org/callback",
            "myapp://callback",
            "https://user@app.example.org/callback",
            "https:///callback",
            "https://app.example.org/a b",
            "",
        ] {
            assert!(check_redirect_uri(uri).is_err(), "{uri:?}");
        }
    }

    #[test]
    fn a_name_that_holds_a_control_a_change_of_direction_or_an_invisible_character_is_unshowable() {
        for refused in [
            '\u{1b}',
            '\u{202e}',
            '\u{200b}',
            '\u{2028}',
            '\u{feff}',
            '\u{e0041}',
        ] {
            assert!(is_unshowable(refused), "{refused:?}");
        }
        for shown in ['a', '\u{e9}', ' ', '\u{2713}', '\u{4e2d}'] {
            assert!(!is_unshowable(shown), "{shown:?}");
        }
    }

    #[test]
    fn a_shown_name_keeps_what_it_can_show_and_replaces_each_character_it_cannot() {
        assert_eq!(
            neutralize_unshowable("Pay\u{202e}lap\u{2066}Inc\u{200b}."),
            "Pay\u{fffd}lap\u{fffd}Inc\u{fffd}."
        );
        assert_eq!(neutralize_unshowable("Caf\u{e9} <b>"), "Caf\u{e9} <b>");
    }

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
