use actix_web::HttpRequest;
use data_encoding::BASE64;
use secrecy::SecretBox;

/// The bearer the `Authorization` header carries.
///
/// Here beside the Basic reader because both parse the one header, and two
/// readers of one header are two chances to disagree about what it says.
pub fn bearer(request: &HttpRequest) -> Option<String> {
    let header = request.headers().get("authorization")?.to_str().ok()?;
    // RFC 9110 §11.1: the scheme is case-insensitive, so `bearer` and
    // `BEARER` present the same way `Bearer` does.
    let (scheme, token) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

/// The pair the header carries, or nothing if it carries something else.
pub fn credentials(request: &HttpRequest) -> Option<(String, SecretBox<String>)> {
    let header = request.headers().get("authorization")?.to_str().ok()?;
    let encoded = header.strip_prefix("Basic ")?.trim();
    let decoded = BASE64.decode(encoded.as_bytes()).ok()?;
    let pair = String::from_utf8(decoded).ok()?;

    // The first colon, not the last: a secret may contain one, an id may not.
    let (client_id, secret) = pair.split_once(':')?;
    let client_id = form_decode(client_id)?;
    if client_id.is_empty() {
        return None;
    }
    Some((client_id, SecretBox::new(Box::new(form_decode(secret)?))))
}

/// Undo the form encoding §2.3.1 puts on each half.
fn form_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                let hex = value.get(index + 1..index + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use secrecy::ExposeSecret;

    fn header(value: &str) -> HttpRequest {
        TestRequest::default()
            .insert_header(("authorization", value))
            .to_http_request()
    }

    fn encoded(pair: &str) -> String {
        format!("Basic {}", BASE64.encode(pair.as_bytes()))
    }

    #[test]
    fn a_secret_with_a_colon_survives_the_header() {
        let (client_id, secret) = credentials(&header(&encoded("app:s3c%3Aret"))).unwrap();
        assert_eq!(client_id, "app");
        assert_eq!(
            secret.expose_secret(),
            "s3c:ret",
            "the encoding §2.3.1 puts on each half was not undone"
        );
    }

    #[test]
    fn a_plus_is_a_space_and_not_a_plus() {
        let (_, secret) = credentials(&header(&encoded("app:a+b"))).unwrap();
        assert_eq!(secret.expose_secret(), "a b");
    }

    #[test]
    fn anything_that_is_not_this_scheme_carries_no_credentials() {
        for refused in [
            "Bearer abc",
            "Basic",
            "Basic !!!not-base64!!!",
            // No colon at all, so nothing separates the two halves.
            &encoded("appsecret"),
            // An empty id names no client.
            &encoded(":s3cr3t"),
            // A truncated escape.
            &encoded("app:%A"),
        ] {
            assert!(credentials(&header(refused)).is_none(), "{refused}");
        }
    }

    /// An empty secret is a secret. Refusing it here would turn a
    /// misconfiguration into a request that looks anonymous.
    #[test]
    fn an_empty_secret_is_still_presented() {
        let (client_id, secret) = credentials(&header(&encoded("app:"))).unwrap();
        assert_eq!(client_id, "app");
        assert_eq!(secret.expose_secret(), "");
    }
}
