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
/// call this server back, and nothing else. No inline code, no frames, no
/// form submission that bypasses the script.
const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                      connect-src 'self'; form-action 'none'; frame-ancestors 'none'; \
                      base-uri 'none'";

/// Where `/auth` sends a browser when the deployment names no other page.
pub fn location(origin: &PublicOrigin, realm: &str) -> String {
    format!(
        "{}/realms/{realm}/protocol/openid-connect/login",
        origin.as_str()
    )
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
