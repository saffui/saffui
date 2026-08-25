use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use config::serving::PublicOrigin;

use crate::api::rest::endpoints::protocol::dto::uncached;

const PAGE: &str = include_str!("ui/login.html");
const CHECK_SESSION: &str = include_str!("ui/check-session.html");
const CHECK_SESSION_SCRIPT: &str = include_str!("ui/check-session.js");
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

/// What sends the form-post page on. Served rather than written into it: a
/// page that allows inline script allows every inline script.
pub async fn form_post_script() -> HttpResponse {
    serve(
        "text/javascript; charset=utf-8",
        crate::api::rest::endpoints::protocol::answering::SCRIPT,
    )
}

/// Session Management 1.0 §4.1, the frame a relying party loads.
///
/// Framed on purpose, which is why this one page does not refuse framing as
/// every other does. It holds nothing and does nothing: it reads a cookie,
/// digests four strings and answers the frame that asked. Whoever loads it
/// learns only what they already sent plus whether it matched.
pub async fn check_session() -> HttpResponse {
    framed("text/html; charset=utf-8", CHECK_SESSION)
}

pub async fn check_session_script() -> HttpResponse {
    framed("text/javascript; charset=utf-8", CHECK_SESSION_SCRIPT)
}

pub async fn script() -> HttpResponse {
    serve("text/javascript; charset=utf-8", SCRIPT)
}

pub async fn style() -> HttpResponse {
    serve("text/css; charset=utf-8", STYLE)
}

/// The same, for the one page whose job is to be inside somebody else's.
fn framed(content_type: &'static str, body: &'static str) -> HttpResponse {
    HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(("Content-Type", content_type))
        .insert_header((
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; base-uri 'none'",
        ))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        // Read on every navigation of a page that never changes, so it is
        // allowed to be kept rather than fetched each time.
        .insert_header(("Cache-Control", "public, max-age=300"))
        .body(body)
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
    let asked = asked.into_inner();
    // Which link was followed decides which field the page posts back. A page
    // that always posted the same one would spend a sign-in token where an
    // address was being confirmed.
    let followed = asked
        .magic_link
        .filter(|held| !held.is_empty())
        .map(|token| ("magic_link", token))
        .or_else(|| {
            asked
                .verify_email
                .filter(|held| !held.is_empty())
                .map(|token| ("verify_email", token))
        });
    let Some((named, token)) = followed else {
        return serve("text/html; charset=utf-8", PAGE);
    };
    let body = LINK_PAGE
        .replace(
            "{action}",
            &escaped(&format!("/realms/{realm}/protocol/openid-connect/login")),
        )
        .replace("{field}", &escaped(named))
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
    pub verify_email: Option<String>,
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
<input type="hidden" name="{field}" value="{token}">
<button type="submit">Continue</button>
</form></main></body></html>
"#;

#[derive(serde::Deserialize)]
pub struct Resetting {
    pub token: Option<String>,
    pub user: Option<String>,
}

/// Where a mailed reset link lands: two fields and the token, and nothing that
/// says whether the link is any good. Telling that here would answer it to
/// whoever holds the link rather than to whoever can set a password.
pub async fn reset_password(
    realm: web::Path<String>,
    asked: web::Query<Resetting>,
) -> HttpResponse {
    let asked = asked.into_inner();
    let (Some(token), Some(user)) = (
        asked.token.filter(|held| !held.is_empty()),
        asked.user.filter(|held| !held.is_empty()),
    ) else {
        return serve("text/html; charset=utf-8", PAGE);
    };
    let body = RESET_PAGE
        .replace(
            "{action}",
            &escaped(&format!(
                "/realms/{realm}/protocol/openid-connect/reset-password"
            )),
        )
        .replace("{token}", &escaped(&token))
        .replace("{user}", &escaped(&user));
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header(("Content-Security-Policy", POLICY))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(body)
}

const RESET_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Set a new password</title>
<link rel="stylesheet" href="login.css"></head>
<body><main><h1>Set a new password</h1>
<form method="post" action="{action}">
<input type="hidden" name="token" value="{token}">
<input type="hidden" name="user" value="{user}">
<label for="password">New password</label>
<input id="password" name="password" type="password" autocomplete="new-password" required>
<button type="submit">Set password</button>
</form>
<p id="refused" class="flash" role="alert">That password was refused. Try another.</p>
<p id="no-such-link" class="flash" role="alert">This link has been used, or has expired. Ask for another.</p>
</main></body></html>
"#;

#[cfg(test)]
mod tests {
    use super::{PAGE, SCRIPT};

    /// The script reaches for the page by identifier, and a page that lost one
    /// hands it `null`. Every name it asks for has to be on the page.
    #[test]
    fn every_element_the_script_reaches_for_is_on_the_page() {
        let mut asked = Vec::new();
        let mut rest = SCRIPT;
        while let Some(at) = rest.find("getElementById(\"") {
            rest = &rest[at + "getElementById(\"".len()..];
            let end = rest.find('"').expect("an unterminated identifier");
            asked.push(&rest[..end]);
            rest = &rest[end..];
        }
        assert!(asked.len() >= 8, "the identifiers were not read: {asked:?}");
        for named in asked {
            assert!(
                PAGE.contains(&format!("id=\"{named}\"")),
                "the script asks for `{named}`, which the page does not carry"
            );
        }
    }

    /// A round the script cannot name lands on its own last branch, which says
    /// only that something went wrong. Every outcome the endpoint speaks has to
    /// be one the script answers.
    #[test]
    fn every_outcome_the_endpoint_speaks_is_one_the_script_answers() {
        for named in [
            "challenge",
            "consent",
            "locked-out",
            "refused",
            "admitted",
            "sent_back",
        ] {
            assert!(
                SCRIPT.contains(&format!("\"{named}\"")),
                "the endpoint answers `{named}`, which the script never names"
            );
        }
    }
}
