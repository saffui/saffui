use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use deadpool_postgres::Pool;
use services::form_post;
use services::landing::{Landing, ResponseMode};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::api::rest::endpoints::protocol::{binding, page};

/// The response, rendered the way the request named, to a request that was a
/// `GET`.
pub fn answer(landing: &Landing) -> HttpResponse {
    onto(&mut HttpResponseBuilder::new(StatusCode::FOUND), landing)
}

/// The same, onto a response somebody else has already begun: a login carries
/// cookies out with its answer, and they belong to the same response.
///
/// The caller's status stands for a redirect, because only the caller knows
/// what its own request was: after a `POST` the answer is a `303`, which tells
/// the browser to fetch the redirect with a `GET` rather than repeat the post.
/// A form is a `200` whatever asked for it: nothing is being redirected to.
pub fn onto(response: &mut HttpResponseBuilder, landing: &Landing) -> HttpResponse {
    match landing.mode {
        ResponseMode::Query | ResponseMode::Fragment => uncached(response)
            .insert_header(("Location", landing.as_url()))
            .finish(),
        ResponseMode::FormPost => posted_page(response, &landing.redirect_uri, &named(landing)),
    }
}

/// The parameters with their names owned, which is what they are once they have
/// been through the store and back.
fn named(landing: &Landing) -> Vec<(String, String)> {
    landing
        .parameters
        .iter()
        .map(|(named, value)| ((*named).to_owned(), value.clone()))
        .collect()
}

/// A page whose only content is the response, as a form the browser sends on.
///
/// The parameters never touch the URL, so nothing of the answer reaches a URL
/// bar, a history, a referrer or a proxy log. That is what the mode is for.
pub fn posted_page(
    response: &mut HttpResponseBuilder,
    redirect_uri: &str,
    fields: &[(String, String)],
) -> HttpResponse {
    uncached(response)
        .status(StatusCode::OK)
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        // Its own, and narrower than this server's other pages. `form-action`
        // names the one place this page may post to, which is where it was
        // going: a page that could post anywhere is one an injected form uses
        // to send the response somewhere else. The script is served from here
        // rather than written inline, so nothing on the page may be inline.
        .insert_header((
            "Content-Security-Policy",
            format!(
                "default-src 'none'; script-src 'self'; form-action {redirect_uri}; \
                 frame-ancestors 'none'; base-uri 'none'"
            ),
        ))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(page(redirect_uri, fields))
}

/// The page itself. Every value on it came from a caller or from a redirect a
/// caller registered, so every one of them is escaped.
fn page(redirect_uri: &str, fields: &[(String, String)]) -> String {
    let written: String = fields
        .iter()
        .map(|(named, value)| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">\n",
                escaped(named),
                escaped(value)
            )
        })
        .collect();
    PAGE.replace("{action}", &escaped(redirect_uri))
        .replace("{fields}", &written)
}

const PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<title>Signing in</title></head>
<body>
<form method="post" action="{action}">
{fields}<noscript><button type="submit">Continue</button></noscript>
</form>
<script src="form-post.js"></script>
</body></html>
"#;

/// What the browser runs to send it on. Served rather than written into the
/// page, because a page that allows inline script allows every inline script.
pub const SCRIPT: &str = "document.forms[0].submit();\n";

/// The five characters that end an attribute or open a tag. Everything on this
/// page came from a caller or from a redirect the caller registered.
fn escaped(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#x27;".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

/// Post to the client the response a browser was handed a ticket for.
///
/// The sign-in page cannot do this itself: it may only post to this server,
/// which is what its `form-action` says, and widening that would let anything
/// injected there post a password to a client's address. The page served here
/// is the server's own, under the narrow policy that mode needs.
pub async fn deliver_response(
    request: HttpRequest,
    realm: web::Path<String>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
) -> HttpResponse {
    let missing = || {
        page::notice(
            StatusCode::NOT_FOUND,
            "Nothing to send",
            "This sign-in has already been sent on, or it expired. Go back to \
             the application and try again.",
        )
    };
    let Some(ticket) = binding::read(&request, binding::LANDING) else {
        return missing();
    };
    let Ok(mut connection) = pool.get().await else {
        return missing();
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return missing();
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return missing();
    };
    let taken = form_post::take(&transaction, sealing.provider.as_ref(), &ticket).await;
    // Committed whatever came back: the row is spent by being read, and a
    // rollback would leave it there for whoever presents the ticket next.
    if transaction.commit().await.is_err() {
        return missing();
    }
    let Ok(Some(posted)) = taken else {
        return missing();
    };
    let mut response = HttpResponseBuilder::new(StatusCode::OK);
    binding::clear(&mut response, binding::LANDING, &context.realm_id);
    posted_page(&mut response, &posted.redirect_uri, &posted.fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_cannot_end_the_attribute_it_sits_in() {
        let asked = Landing::new("https://app.example/cb", ResponseMode::FormPost)
            .carrying("state", r#""><script>alert(1)</script>"#);
        let built = page(&asked.redirect_uri, &named(&asked));
        assert!(
            !built.contains("<script>alert"),
            "a value opened a tag: {built}"
        );
        assert!(built.contains("&quot;&gt;&lt;script&gt;"), "{built}");
    }

    /// The redirect is an attribute too, and it is the one that decides where
    /// the browser posts.
    #[test]
    fn a_redirect_cannot_end_its_own_attribute() {
        let asked = Landing::new(
            r#"https://app.example/cb" onload="evil()"#,
            ResponseMode::FormPost,
        );
        let built = page(&asked.redirect_uri, &named(&asked));
        assert!(!built.contains("onload=\"evil"), "{built}");
    }

    #[test]
    fn every_parameter_becomes_a_field() {
        let asked = Landing::new("https://app.example/cb", ResponseMode::FormPost)
            .carrying("code", "abc")
            .carrying_any("state", Some("s"));
        let built = page(&asked.redirect_uri, &named(&asked));
        assert!(
            built.contains(r#"<input type="hidden" name="code" value="abc">"#),
            "{built}"
        );
        assert!(
            built.contains(r#"<input type="hidden" name="state" value="s">"#),
            "{built}"
        );
        assert!(
            built.contains(r#"action="https://app.example/cb""#),
            "{built}"
        );
    }
}
