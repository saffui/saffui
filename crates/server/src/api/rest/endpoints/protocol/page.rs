//! The login page this server renders when no other is configured.
//!
//! Static, and deliberately so: the page carries no data, so there is nothing
//! to template and nothing a response could leak. Which login it is answering
//! rides in the cookie, and the script posts to the very URL that served it.
//! Its policy allows nothing inline, which is what lets the policy be short.

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
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
    told(status, title, inner, false, None)
}

/// The same, allowing the frames a front-channel logout puts in the page and
/// leaving for `landing` once they have had a moment to load.
pub fn notice_with_frames(
    status: StatusCode,
    title: &str,
    inner: &str,
    landing: Option<&str>,
) -> HttpResponse {
    told(status, title, inner, true, landing)
}

fn told(
    status: StatusCode,
    title: &str,
    inner: &str,
    frames: bool,
    landing: Option<&str>,
) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header((
            "Content-Security-Policy",
            if frames {
                "default-src 'none'; style-src 'self'; form-action 'self'; \
                 frame-ancestors 'none'; frame-src https:"
            } else {
                "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"
            },
        ))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             {leaving}<title>{title}</title>\
             <link rel=\"stylesheet\" href=\"login.css\"></head>\
             <body><main><h1>{title}</h1>{inner}</main></body></html>",
            title = escaped(title),
            // Markup rather than a script, because this page runs none. Two
            // seconds is what the frames get before the browser leaves.
            leaving = landing.map_or_else(String::new, |landing| format!(
                "<meta http-equiv=\"refresh\" content=\"2;url={}\">",
                escaped(landing)
            )),
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

/// The page a mailed sign-in link lands on.
///
/// It spends nothing. A link in a mailbox is followed by more than the person
/// it was sent to: scanners and previewers fetch every URL they see, and a link
/// that signed somebody in on being fetched would be spent before they read the
/// message. What lands here is a button, and a button is not fetched.
///
/// The value is written into the form and nowhere else. Rendered into a page
/// this server serves, so nothing else on it can read it, and the page carries
/// no script and no referrer.
pub async fn magic_link(realm: web::Path<String>, asked: web::Query<Followed>) -> HttpResponse {
    let Some(token) = asked
        .into_inner()
        .magic_link
        .filter(|held| !held.is_empty())
    else {
        return serve("text/html; charset=utf-8", PAGE);
    };
    let body = LINK_PAGE
        .replace(
            "{action}",
            &escaped(&format!("/realms/{realm}/protocol/openid-connect/login")),
        )
        .replace("{token}", &escaped(&token));
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header(("Content-Security-Policy", POLICY))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(body)
}

#[derive(serde::Deserialize)]
pub struct Followed {
    pub magic_link: Option<String>,
}

const LINK_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Sign in</title>
<link rel="stylesheet" href="login.css"></head>
<body><main><h1>Sign in</h1>
<p>Follow through to finish signing in on this browser.</p>
<form method="post" action="{action}">
<input type="hidden" name="magic_link" value="{token}">
<button type="submit">Continue</button>
</form></main></body></html>
"#;
