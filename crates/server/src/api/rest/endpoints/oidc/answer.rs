//! How an answer of the authorization endpoint reaches the client: a
//! redirection for a query or a fragment, a page that posts it for a form.

use actix_web::http::StatusCode;
use actix_web::http::header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION};
use actix_web::{HttpResponse, HttpResponseBuilder};
use askama::Template;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use saffui_core::app::App as Product;
use saffui_core::oidc::response::{AuthorizationResponse, ResponseMode};

/// What sends the form of an answer on, as `templates/oidc/form_post.html`
/// writes it. The policy of the page names it by its hash: no other script,
/// inline or fetched, runs there.
const FORM_POST_SCRIPT: &str = "document.forms[0].submit();";

/// The page of an answer posted as a form, `templates/oidc/form_post.html`.
#[derive(Template)]
#[template(path = "oidc/form_post.html")]
struct FormPostPage<'a> {
    action: &'a str,
    parameters: &'a [(&'static str, String)],
}

/// Sends `answer` to the client on `response`, which may carry cookies
/// already. A redirection keeps the status of the caller, who alone knows
/// what its request was: after a post, a `303` has the browser fetch the
/// redirect URI rather than post again. A form is a `200` whoever asks.
pub(crate) fn send_answer_to_client(
    product: &Product,
    mut response: HttpResponseBuilder,
    answer: &AuthorizationResponse,
) -> HttpResponse {
    response.insert_header((CACHE_CONTROL, "no-store"));
    match answer.mode() {
        ResponseMode::Query | ResponseMode::Fragment => match answer.write_location() {
            Some(location) => response.insert_header((LOCATION, location)).finish(),
            None => refuse_unsent_answer(),
        },
        ResponseMode::FormPost => post_answer(product, response, answer),
    }
}

/// The page that posts an answer, under a policy of its own: narrower than
/// that of the other pages, and the one that lets a form leave this origin.
/// `form-action` names the address the answer goes to and nothing else: a
/// page that could post anywhere is one an injected form would use to send
/// the answer elsewhere. Its post names this origin to the client: under the
/// referrer policy of the other pages it would carry `Origin: null`.
fn post_answer(
    product: &Product,
    mut response: HttpResponseBuilder,
    answer: &AuthorizationResponse,
) -> HttpResponse {
    let Some(source) = answer.write_form_action(&product.settings.public_origin) else {
        return refuse_unsent_answer();
    };
    let page = FormPostPage {
        action: answer.redirect_uri(),
        parameters: answer.parameters(),
    };
    let script_hash = STANDARD.encode(product.digester.sha256(FORM_POST_SCRIPT.as_bytes()));
    let policy = format!(
        "default-src 'none'; script-src 'sha256-{script_hash}'; form-action {source}; \
         frame-ancestors 'none'; base-uri 'none'"
    );
    match page.render() {
        Ok(page) => response
            .status(StatusCode::OK)
            .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
            .insert_header(("Content-Security-Policy", policy))
            .insert_header(("Referrer-Policy", "strict-origin"))
            .body(page),
        Err(error) => {
            tracing::error!(%error, "the page of an answer could not be rendered");
            refuse_unsent_answer()
        }
    }
}

/// What is sent instead of an answer that cannot be sent as it was asked:
/// nothing of it, and no cookie the caller meant to go with it.
fn refuse_unsent_answer() -> HttpResponse {
    HttpResponse::InternalServerError()
        .insert_header((CACHE_CONTROL, "no-store"))
        .finish()
}

#[cfg(test)]
mod tests {
    use actix_web::HttpResponse;
    use actix_web::body::MessageBody;
    use actix_web::http::StatusCode;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use saffui_core::oidc::response::{AuthorizationResponse, ResponseMode};
    use saffui_core::testkit::memory::MemoryStorage;

    use super::{FORM_POST_SCRIPT, send_answer_to_client};

    const CALLBACK: &str = "https://app.example.org/callback";
    const ISSUER: &str = "https://id.example.test/realms/acme";

    fn send(redirect_uri: &str, mode: ResponseMode, state: &str) -> HttpResponse {
        let (product, _storage) = MemoryStorage::wire();
        let answer = AuthorizationResponse::write(
            redirect_uri,
            mode,
            ISSUER,
            Some(state),
            vec![("code", "a-code".to_owned())],
        );
        send_answer_to_client(&product, HttpResponse::SeeOther(), &answer)
    }

    fn read_header(answer: &HttpResponse, name: &str) -> String {
        answer
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    }

    fn read_body(answer: HttpResponse) -> String {
        let body = answer.into_body().try_into_bytes().expect("a body");
        String::from_utf8(body.to_vec()).expect("text")
    }

    #[test]
    fn a_query_or_a_fragment_answer_is_a_redirection_with_the_status_of_the_caller() {
        let queried = send(CALLBACK, ResponseMode::Query, "s");
        let fragment = send(CALLBACK, ResponseMode::Fragment, "s");

        assert_eq!(queried.status(), StatusCode::SEE_OTHER);
        assert!(
            read_header(&queried, "location").starts_with(&format!("{CALLBACK}?code=a-code&")),
            "{}",
            read_header(&queried, "location")
        );
        assert_eq!(fragment.status(), StatusCode::SEE_OTHER);
        assert!(
            read_header(&fragment, "location").starts_with(&format!("{CALLBACK}#code=a-code&")),
            "{}",
            read_header(&fragment, "location")
        );
        for answer in [&queried, &fragment] {
            assert_eq!(read_header(answer, "cache-control"), "no-store");
            assert!(read_header(answer, "content-security-policy").is_empty());
        }
    }

    #[test]
    fn a_posted_answer_is_a_page_whose_policy_names_its_script_and_its_one_address() {
        let (product, _storage) = MemoryStorage::wire();
        let answer = AuthorizationResponse::write(
            "https://app.example.org/callback?tenant=a",
            ResponseMode::FormPost,
            ISSUER,
            Some("s"),
            vec![("code", "a-code".to_owned())],
        );

        let page = send_answer_to_client(&product, HttpResponse::SeeOther(), &answer);

        assert_eq!(page.status(), StatusCode::OK, "a form is not a redirection");
        assert!(read_header(&page, "location").is_empty());
        assert_eq!(read_header(&page, "cache-control"), "no-store");
        assert_eq!(
            read_header(&page, "referrer-policy"),
            "strict-origin",
            "the post tells the client where it comes from"
        );
        assert_eq!(
            read_header(&page, "content-type"),
            "text/html; charset=utf-8"
        );
        let hash = STANDARD.encode(product.digester.sha256(FORM_POST_SCRIPT.as_bytes()));
        assert_eq!(
            read_header(&page, "content-security-policy"),
            format!(
                "default-src 'none'; script-src 'sha256-{hash}'; \
                 form-action https://app.example.org/callback; \
                 frame-ancestors 'none'; base-uri 'none'"
            )
        );
        let body = read_body(page);
        assert!(
            body.contains(
                r#"<form method="post" action="https://app.example.org/callback?tenant=a">"#
            ),
            "{body}"
        );
        for (name, value) in [("code", "a-code"), ("state", "s"), ("iss", ISSUER)] {
            assert!(
                body.contains(&format!(
                    r#"<input type="hidden" name="{name}" value="{value}">"#
                )),
                "{name}: {body}"
            );
        }
        assert!(
            body.contains(&format!("<script>{FORM_POST_SCRIPT}</script>")),
            "the script is the one the policy names: {body}"
        );
        assert!(
            body.contains("<noscript><button type=\"submit\">Continue</button></noscript>"),
            "a browser without the script posts the form by hand: {body}"
        );
        assert_eq!(body.matches("<script").count(), 1, "{body}");
    }

    #[test]
    fn a_value_of_a_posted_answer_is_written_as_text() {
        let hostile = r#""><script>alert(1)</script><x a='"#;

        let body = read_body(send(CALLBACK, ResponseMode::FormPost, hostile));

        assert_eq!(body.matches("<script").count(), 1, "{body}");
        assert!(!body.contains("<x a="), "{body}");
        assert!(
            body.contains("&#34;&#62;&#60;script&#62;alert(1)&#60;/script&#62;&#60;x a=&#39;"),
            "{body}"
        );
    }

    #[test]
    fn an_answer_whose_address_a_policy_cannot_name_is_not_posted() {
        let refused = send("http://[::1]:8080/cb", ResponseMode::FormPost, "s");

        assert_eq!(refused.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(read_body(refused).is_empty());
    }

    #[test]
    fn an_answer_to_an_address_of_this_deployment_is_never_a_page_that_posts() {
        for redirect_uri in [
            "https://id.example.test/portal/callback",
            "https://id.example.test:8443/realms/acme/oauth2/logout",
        ] {
            let refused = send(redirect_uri, ResponseMode::FormPost, "s");

            assert_eq!(
                refused.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "{redirect_uri}"
            );
            assert!(read_header(&refused, "content-security-policy").is_empty());
            assert!(read_body(refused).is_empty(), "{redirect_uri}");
        }
    }
}
