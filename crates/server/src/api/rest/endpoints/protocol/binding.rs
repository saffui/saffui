//! What ties a browser to the login it is answering.
//!
//! A cookie and not a URL. A URL reaches the server logs of whatever it points
//! at, the `Referer` of every asset that page loads, and the history of the
//! machine it was typed on; an identifier that leaks there is one somebody else
//! can answer with. The cookie is unreadable to script and is not attached to a
//! cross-site request, so neither of those is a way to it.

use actix_web::cookie::time::Duration;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpRequest, HttpResponseBuilder};

/// The login in progress.
pub const AUTH_SESSION: &str = "saffui_auth_session";

/// The login that finished, which is what makes a second client's `/authorize`
/// something other than a fresh sign-in.
pub const SSO_SESSION: &str = "saffui_session";

/// Set one, scoped to the realm it belongs to.
///
/// `Lax` rather than `Strict`: the browser arrives here from the client's site,
/// and `Strict` would drop the cookie on exactly that navigation. `Lax` still
/// withholds it from a cross-site POST, which is the request being defended
/// against.
///
/// The path is the realm's, so one realm's cookie is never offered to another.
pub fn set(
    response: &mut HttpResponseBuilder,
    named: &'static str,
    value: &str,
    realm_id: &str,
    seconds: i64,
) {
    let cookie = Cookie::build(named, value.to_owned())
        .path(format!("/realms/{realm_id}"))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(seconds))
        .finish();
    response.cookie(cookie);
}

/// Take one away, which is what ending a login means to a browser.
pub fn clear(response: &mut HttpResponseBuilder, named: &'static str, realm_id: &str) {
    let cookie = Cookie::build(named, "")
        .path(format!("/realms/{realm_id}"))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(0))
        .finish();
    response.cookie(cookie);
}

/// Read one, or nothing.
pub fn read(request: &HttpRequest, named: &str) -> Option<String> {
    request
        .cookie(named)
        .map(|cookie| cookie.value().to_owned())
        .filter(|value| !value.is_empty())
}
