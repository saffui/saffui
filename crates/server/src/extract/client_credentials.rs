//! The credentials of a client, as it presents them to the token endpoint:
//! in the Basic scheme, or in the form. Never both.

use actix_web::HttpRequest;
use actix_web::http::header::AUTHORIZATION;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use saffui_core::secret::Secret;

pub(crate) struct ClientCredentials {
    pub(crate) client_id: String,
    pub(crate) secret: Secret,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Presented<T> {
    Nothing,
    Credentials(T),
    /// A scheme that is not Basic, a header that cannot be read, or two
    /// methods at once.
    Unusable,
}

/// Reads the `Authorization` header of a request.
pub(crate) fn read_basic_header(request: &HttpRequest) -> Presented<ClientCredentials> {
    match request.headers().get(AUTHORIZATION) {
        None => Presented::Nothing,
        Some(value) => value.to_str().ok().and_then(decode_basic_scheme).map_or(
            Presented::Unusable,
            |(client_id, secret)| {
                Presented::Credentials(ClientCredentials {
                    client_id,
                    secret: Secret::new(secret.into_bytes()),
                })
            },
        ),
    }
}

/// Decodes `Basic base64(id:secret)`. Both halves are form-encoded before
/// they are joined (RFC 6749, section 2.3.1).
fn decode_basic_scheme(header: &str) -> Option<(String, String)> {
    let (scheme, encoded) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
    let (client_id, secret) = decoded.split_once(':')?;
    Some((
        decode_form_component(client_id)?,
        decode_form_component(secret)?,
    ))
}

/// Decodes one form-encoded component. An escape that is not two hexadecimal
/// digits, or bytes that are not UTF-8, refuse the whole value.
fn decode_form_component(encoded: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(encoded.len());
    let mut rest = encoded.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        rest = tail;
        match first {
            b'+' => bytes.push(b' '),
            b'%' => {
                let (digits, tail) = rest.split_at_checked(2)?;
                let digits = std::str::from_utf8(digits).ok()?;
                bytes.push(u8::from_str_radix(digits, 16).ok()?);
                rest = tail;
            }
            other => bytes.push(other),
        }
    }
    String::from_utf8(bytes).ok()
}

/// Who a client says it is, and the secret it presents, if any.
pub(crate) struct ClientIdentity {
    pub(crate) client_id: Option<String>,
    pub(crate) secret: Option<Secret>,
    /// The client tried the Basic scheme: a refusal names it.
    pub(crate) asked_with_basic: bool,
}

/// Why the credentials of a client cannot even be read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UnreadableIdentity {
    /// The header and the form both carry credentials.
    TwoMethods,
    /// A header that is not a readable Basic scheme.
    UnusableHeader,
}

/// Reads the credentials of a client from the header or from the form. One
/// method per request: the header, or the form, never the two.
pub(crate) fn read_client_identity(
    request: &HttpRequest,
    form_client_id: Option<String>,
    form_secret: Option<String>,
) -> Result<ClientIdentity, UnreadableIdentity> {
    match read_basic_header(request) {
        Presented::Credentials(_) | Presented::Unusable if form_secret.is_some() => {
            Err(UnreadableIdentity::TwoMethods)
        }
        Presented::Unusable => Err(UnreadableIdentity::UnusableHeader),
        Presented::Credentials(credentials) => Ok(ClientIdentity {
            client_id: Some(credentials.client_id),
            secret: Some(credentials.secret),
            asked_with_basic: true,
        }),
        Presented::Nothing => Ok(ClientIdentity {
            client_id: form_client_id,
            secret: form_secret.map(|secret| Secret::new(secret.into_bytes())),
            asked_with_basic: false,
        }),
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::{decode_basic_scheme, decode_form_component};

    fn encode(pair: &str) -> String {
        format!("Basic {}", STANDARD.encode(pair))
    }

    #[test]
    fn an_identifier_and_a_secret_are_read_from_the_basic_scheme() {
        assert_eq!(
            decode_basic_scheme(&encode("billing:s3cret")),
            Some(("billing".to_owned(), "s3cret".to_owned()))
        );
        assert_eq!(
            decode_basic_scheme(&encode("billing:")),
            Some(("billing".to_owned(), String::new()))
        );
    }

    #[test]
    fn the_secret_keeps_every_colon_after_the_first() {
        assert_eq!(
            decode_basic_scheme(&encode("billing:a:b:c")),
            Some(("billing".to_owned(), "a:b:c".to_owned()))
        );
    }

    #[test]
    fn both_halves_are_form_decoded() {
        assert_eq!(
            decode_basic_scheme(&encode("my%20app:p%3Ass+word")),
            Some(("my app".to_owned(), "p:ss word".to_owned()))
        );
    }

    #[test]
    fn another_scheme_a_missing_colon_and_bad_base64_are_not_credentials() {
        assert_eq!(decode_basic_scheme("Bearer abc"), None);
        assert_eq!(decode_basic_scheme(&encode("no-colon")), None);
        assert_eq!(decode_basic_scheme("Basic !!!"), None);
        assert_eq!(decode_basic_scheme("Basic"), None);
    }

    #[test]
    fn an_escape_that_is_cut_short_or_not_hexadecimal_refuses_the_value() {
        assert_eq!(decode_form_component("a%2"), None);
        assert_eq!(decode_form_component("a%zz"), None);
        assert_eq!(decode_form_component("%ff"), None, "not UTF-8");
        assert_eq!(decode_form_component("a%2Fb"), Some("a/b".to_owned()));
    }
}
