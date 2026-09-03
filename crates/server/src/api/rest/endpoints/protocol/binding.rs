use actix_web::cookie::time::Duration;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpRequest, HttpResponseBuilder};

/// The login in progress.
pub const AUTH_SESSION: &str = "saffui_auth_session";

/// The login that finished, which is what makes a second client's `/authorize`
/// something other than a fresh sign-in.
pub const SSO_SESSION: &str = "saffui_session";

/// The ticket that fetches a response waiting to be posted to a client.
///
/// A browser reading JSON is told where to go rather than handed the response,
/// because the page it is on may only post to this server. The ticket rides in
/// a cookie rather than the URL it names: it stands for an authorization code,
/// and a URL is read by history, referrers and proxy logs.
pub const LANDING: &str = "saffui_landing";

/// What a relying party's iframe reads to see whether this login changed.
///
/// Unlike the others: script must read it, and it must arrive inside a frame
/// the relying party's page loaded, so it is neither http-only nor same-site.
/// What that costs is bounded by what it is: an opaque value drawn per login,
/// which names nothing and authorises nothing. Knowing it says a login exists
/// here, which is what the mechanism is for.
pub const BROWSER_STATE: &str = "saffui_op_state";

/// Set the value the iframe reads, on the terms it has to be readable on.
pub fn set_browser_state(response: &mut HttpResponseBuilder, value: &str, realm_id: &str) {
    let cookie = Cookie::build(BROWSER_STATE, value.to_owned())
        .path(format!("/realms/{realm_id}"))
        .http_only(false)
        .secure(true)
        .same_site(SameSite::None)
        .finish();
    response.cookie(cookie);
}

/// Take it away, which is what a login ending looks like to an iframe.
pub fn clear_browser_state(response: &mut HttpResponseBuilder, realm_id: &str) {
    let cookie = Cookie::build(BROWSER_STATE, "")
        .path(format!("/realms/{realm_id}"))
        .http_only(false)
        .secure(true)
        .same_site(SameSite::None)
        .max_age(Duration::seconds(0))
        .finish();
    response.cookie(cookie);
}

/// Set one, scoped to the realm it belongs to.
///
/// `Lax` rather than `Strict`: the browser arrives here from the client's site,
/// and `Strict` would drop the cookie on exactly that navigation. `Lax` still
/// withholds it from a cross-site POST, which is the request being defended
/// against.
///
/// The path is the realm's, so one realm's cookie is never offered to another.
/// `seconds: None` sets a browser-session cookie, gone when the window is:
/// the shape of a login nobody asked to be remembered past it.
pub fn set(
    response: &mut HttpResponseBuilder,
    named: &'static str,
    value: &str,
    realm_id: &str,
    seconds: Option<i64>,
) {
    let mut cookie = Cookie::build(named, value.to_owned())
        .path(format!("/realms/{realm_id}"))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax);
    if let Some(seconds) = seconds {
        cookie = cookie.max_age(Duration::seconds(seconds));
    }
    response.cookie(cookie.finish());
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
