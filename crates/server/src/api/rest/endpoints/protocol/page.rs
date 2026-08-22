//! The login page this server renders when no other is configured.
//!
//! Static, and deliberately so: the page carries no data, so there is nothing
//! to template and nothing a response could leak. Which login it is answering
//! rides in the cookie, and the script posts to the very URL that served it.
//! Its policy allows nothing inline, which is what lets the policy be short.

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder};
use config::serving::PublicOrigin;

use crate::api::rest::endpoints::protocol::dto::uncached;

const PAGE: &str = include_str!("ui/login.html");
const SCRIPT: &str = include_str!("ui/login.js");
const STYLE: &str = include_str!("ui/login.css");

/// What the browser may do on this page: load this server's script and style,
/// call this server back or post the form to it, and nothing else. No inline
/// code, no frames, no submission to anywhere but here.
const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                      connect-src 'self'; form-action 'self'; frame-ancestors 'none'; \
                      base-uri 'none'";

/// Where `/auth` sends a browser when the deployment names no other page.
pub fn location(origin: &PublicOrigin, realm: &str) -> String {
    format!(
        "{}/realms/{realm}/protocol/openid-connect/login",
        origin.as_str()
    )
}

/// Whether the caller is a browser, which is told in a page, or anything
/// else, which is told in JSON.
pub fn wants_page(request: &actix_web::HttpRequest) -> bool {
    request
        .headers()
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}

/// A notice with nothing to run: a title and the body's inner HTML, which the
/// caller has already escaped, under the same style as the login page.
pub fn notice(status: StatusCode, title: &str, inner: &str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header((
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'",
        ))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>{title}</title><link rel=\"stylesheet\" href=\"login.css\"></head>\
             <body><main><h1>{title}</h1>{inner}</main></body></html>",
            title = escaped(title),
        ))
}

/// The five characters HTML reads as markup, spelled so it does not.
pub fn escaped(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#39;".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

pub async fn login() -> HttpResponse {
    serve("text/html; charset=utf-8", PAGE)
}

pub async fn script() -> HttpResponse {
    serve("text/javascript; charset=utf-8", SCRIPT)
}

pub async fn style() -> HttpResponse {
    serve("text/css; charset=utf-8", STYLE)
}

fn serve(content_type: &'static str, body: &'static str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", content_type))
        .insert_header(("Content-Security-Policy", POLICY))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(body)
}
