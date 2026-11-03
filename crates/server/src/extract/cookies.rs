//! Cookies, read and written by hand.
//!
//! Under an origin served over TLS a name starts with `__Host-`: a browser
//! then takes the cookie only from this very host, with the path `/` and no
//! domain, so a neighbouring host cannot plant one. The realm is part of the
//! name, since the path no longer tells realms apart.

use actix_web::HttpRequest;
use actix_web::http::header::COOKIE;
use saffui_core::app::App as Product;

/// Tells whether the public origin is served over TLS: cookies are then
/// marked `Secure` and named under the host prefix.
pub(crate) fn is_served_over_tls(product: &Product) -> bool {
    product
        .settings
        .public_origin
        .as_str()
        .starts_with("https://")
}

fn choose_prefix(secure: bool) -> &'static str {
    if secure { "__Host-" } else { "" }
}

/// The name of the cookie that carries the session of a person in a realm.
pub(crate) fn name_session_cookie(realm: &str, secure: bool) -> String {
    format!("{}saffui_session_{realm}", choose_prefix(secure))
}

/// The name of the cookie that binds a pending sign-in to the browser that
/// started it. One per pending request: two tabs do not undo each other.
pub(crate) fn name_flow_cookie(request: uuid::Uuid, secure: bool) -> String {
    format!("{}saffui_flow_{request}", choose_prefix(secure))
}

/// The name of the cookie that marks a browser where a person signed in to
/// a realm: it is counted apart at its next sign-in.
pub(crate) fn name_device_cookie(realm: &str, secure: bool) -> String {
    format!("{}saffui_mark_{realm}", choose_prefix(secure))
}

/// Reads the value of one cookie of a request. A name sent twice is a name
/// someone else also wrote: neither value is believed.
pub(crate) fn read_cookie(request: &HttpRequest, name: &str) -> Option<String> {
    let mut values = request
        .headers()
        .get_all(COOKIE)
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| find_cookies(header, name));
    let only = values.next()?;
    values.next().is_none().then_some(only)
}

fn find_cookies<'a>(header: &'a str, name: &'a str) -> impl Iterator<Item = String> + 'a {
    header.split(';').filter_map(move |pair| {
        let (key, value) = pair.trim().split_once('=')?;
        (key == name).then(|| value.to_owned())
    })
}

/// Writes a `Set-Cookie` value. Never readable by a script, never sent on a
/// request another site makes on its own, and only over TLS when the public
/// origin is. Without an age, the cookie lives as long as the browser: the
/// next person at a shared machine does not find the session.
pub(crate) fn write_cookie(
    name: &str,
    value: &str,
    max_age_seconds: Option<i64>,
    secure: bool,
) -> String {
    let max_age =
        max_age_seconds.map_or_else(String::new, |seconds| format!("; Max-Age={seconds}"));
    let secure = if secure { "; Secure" } else { "" };
    format!("{name}={value}; Path=/{max_age}; HttpOnly; SameSite=Lax{secure}")
}

#[cfg(test)]
mod tests {
    use actix_web::http::header::COOKIE;
    use actix_web::test::TestRequest;

    use super::{name_flow_cookie, name_session_cookie, read_cookie, write_cookie};

    fn read_from(headers: &[&str], name: &str) -> Option<String> {
        let mut request = TestRequest::default();
        for header in headers {
            request = request.append_header((COOKIE, *header));
        }
        read_cookie(&request.to_http_request(), name)
    }

    #[test]
    fn a_cookie_is_found_by_its_whole_name_among_others() {
        let header = "theme=dark; saffui_session_acme=abc.def; other=1";

        assert_eq!(
            read_from(&[header], "saffui_session_acme").as_deref(),
            Some("abc.def")
        );
        assert_eq!(read_from(&[header], "saffui_session_acm"), None);
        assert_eq!(read_from(&[header], "saffui_session_acme2"), None);
    }

    #[test]
    fn a_name_sent_twice_is_believed_for_neither_value() {
        let twice_in_one = "saffui_session_acme=planted; saffui_session_acme=real";

        assert_eq!(read_from(&[twice_in_one], "saffui_session_acme"), None);
        assert_eq!(
            read_from(
                &["saffui_session_acme=planted", "saffui_session_acme=real"],
                "saffui_session_acme"
            ),
            None
        );
    }

    #[test]
    fn under_tls_a_cookie_is_bound_to_this_host_and_out_of_reach_of_scripts() {
        let request = uuid::Uuid::from_u128(7);

        assert_eq!(
            name_session_cookie("acme", true),
            "__Host-saffui_session_acme"
        );
        assert_eq!(name_session_cookie("acme", false), "saffui_session_acme");
        assert_eq!(
            name_flow_cookie(request, true),
            format!("__Host-saffui_flow_{request}")
        );
        assert_eq!(
            write_cookie("__Host-saffui_flow_7", "v", Some(60), true),
            "__Host-saffui_flow_7=v; Path=/; Max-Age=60; HttpOnly; SameSite=Lax; Secure"
        );
        assert_eq!(
            write_cookie("__Host-saffui_session_acme", "v", None, true),
            "__Host-saffui_session_acme=v; Path=/; HttpOnly; SameSite=Lax; Secure",
            "a session lives as long as the browser"
        );
        assert!(!write_cookie("saffui_session_acme", "v", None, false).contains("Secure"));
    }
}
