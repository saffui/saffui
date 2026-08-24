//! What a relying party's iframe compares a login against, OIDC Session
//! Management 1.0 §4.2.

use crypto::provider::{CryptoProvider, HashAlg};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use url::Url;

/// How many bytes the per-login value and the salt are drawn from.
const DRAWN_BYTES: usize = 16;

/// Draw the value this login is known by in the browser.
///
/// Not the session identifier. It is handed to script in a page the relying
/// party loads, and an identifier that reaches script is one that page can use.
pub fn draw_browser_state(provider: &dyn CryptoProvider) -> Option<String> {
    let mut drawn = [0u8; DRAWN_BYTES];
    provider.rand().fill(&mut drawn).ok()?;
    Some(BASE64URL_NOPAD.encode(&drawn))
}

/// §4.2: the salted digest a client is handed, and the salt beside it.
///
/// Salted because the digest travels to the client and back through script:
/// without one, the same login and client would always produce the same value
/// and anything that saw it once could recognise the login again.
pub fn state_for(
    provider: &dyn CryptoProvider,
    client_id: &str,
    redirect_uri: &str,
    browser_state: &str,
) -> Option<String> {
    let mut salt = [0u8; DRAWN_BYTES];
    provider.rand().fill(&mut salt).ok()?;
    let salt = BASE64URL_NOPAD.encode(&salt);
    computed(
        provider,
        client_id,
        &origin_of(redirect_uri)?,
        browser_state,
        &salt,
    )
}

/// The same computation the iframe performs, so the two agree or the answer is
/// that the login changed.
pub fn computed(
    provider: &dyn CryptoProvider,
    client_id: &str,
    origin: &str,
    browser_state: &str,
    salt: &str,
) -> Option<String> {
    let over = format!("{client_id} {origin} {browser_state} {salt}");
    let digest = provider
        .digest()
        .hash(HashAlg::Sha256, over.as_bytes())
        .ok()?;
    Some(format!("{}.{salt}", HEXLOWER.encode(&digest)))
}

/// §4.2 names the scheme, host and port of where the response is sent, and
/// nothing else of it.
pub fn origin_of(redirect_uri: &str) -> Option<String> {
    let parsed = Url::parse(redirect_uri).ok()?;
    // What the frame compares against is a browser's own `event.origin`, and
    // that is only ever http or https. A client reached by a scheme of its own
    // has no origin to be one, and no browser to load the frame in either.
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
        None => format!("{}://{host}", parsed.scheme()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::provider::CryptoConfig;
    use crypto::provider::openssl::OpenSslProvider;

    fn provider() -> OpenSslProvider {
        OpenSslProvider::new(&CryptoConfig::default()).expect("a provider")
    }

    #[test]
    fn an_origin_is_the_scheme_the_host_and_the_port() {
        assert_eq!(
            origin_of("https://app.example/cb?x=1#f").as_deref(),
            Some("https://app.example")
        );
        assert_eq!(
            origin_of("https://app.example:8443/cb").as_deref(),
            Some("https://app.example:8443")
        );
        assert_eq!(origin_of("app://callback").as_deref(), None);
        assert_eq!(origin_of("/cb").as_deref(), None);
    }

    /// The value is the digest and the salt, and the digest is over both of the
    /// things that make this login this client's.
    #[test]
    fn the_state_names_the_client_the_origin_and_the_login() {
        let held = provider();
        let one = computed(&held, "app", "https://app.example", "opbs", "salt").unwrap();
        assert!(one.ends_with(".salt"));
        assert_eq!(one.len(), 64 + 1 + 4);

        for (client, origin, opbs) in [
            ("other", "https://app.example", "opbs"),
            ("app", "https://elsewhere.example", "opbs"),
            ("app", "https://app.example", "another"),
        ] {
            assert_ne!(
                computed(&held, client, origin, opbs, "salt").unwrap(),
                one,
                "{client} {origin} {opbs}"
            );
        }
        // The same four things give the same answer, or the iframe could never
        // agree with what the client was handed.
        assert_eq!(
            computed(&held, "app", "https://app.example", "opbs", "salt").unwrap(),
            one
        );
    }

    /// Two logins are two values, and two responses for one login are two
    /// salts.
    #[test]
    fn nothing_drawn_repeats() {
        let held = provider();
        let first = draw_browser_state(&held).unwrap();
        assert_ne!(first, draw_browser_state(&held).unwrap());
        assert_ne!(
            state_for(&held, "app", "https://app.example/cb", &first).unwrap(),
            state_for(&held, "app", "https://app.example/cb", &first).unwrap()
        );
    }
}
