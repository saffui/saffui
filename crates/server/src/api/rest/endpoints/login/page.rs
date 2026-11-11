//! The sign-in page of a pending authorization request, and its submission.

use actix_web::http::StatusCode;
use actix_web::http::header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION, ORIGIN, SET_COOKIE};
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use askama::Template;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use saffui_core::app::App as Product;
use saffui_core::error::{ErrorCode, ErrorKind, Failure};
use saffui_core::login::device::DeviceMark;
use saffui_core::login::device::{
    DEVICE_MARK_LIFETIME, keep_device_marks, read_device_marks, write_device_marks,
};
use saffui_core::oidc::authorize::{
    OwedSecondFactor, SignInAnswer, SignInStep, SignedInForConsent, SignedInForRequest,
    TypedSignIn, describe_owed_second_factor, finish_sign_in,
};
use saffui_core::secret::Secret;
use serde::Deserialize;
use uuid::Uuid;

use super::key_form::{KEY_SILENT, KeyCeremonyKind, KeyPrompt};
use crate::extract::cookies::{
    is_served_over_tls, name_device_cookie, name_flow_cookie, name_session_cookie, read_cookie,
    write_cookie,
};
use crate::extract::form::read_posted_form;
use crate::middleware::caller_address::read_caller_address;

#[derive(Deserialize)]
pub struct PageQuery {
    request: Option<String>,
}

/// One page, two steps: a name and a password first, then a code or the
/// answer of a security key when the person owes one.
// No `Debug`: the form carries a password.
#[derive(Deserialize)]
pub struct SignInForm {
    request: String,
    username: Option<String>,
    password: Option<String>,
    code: Option<String>,
    /// What the browser handed back from a security key, as JSON.
    key: Option<String>,
}

/// The frame every hosted page is drawn in, `templates/base.html`: the value
/// its style and its script are named by, drawn for this answer, and the
/// script it runs.
pub(crate) struct Frame {
    /// None when the draw failed: the page then has no style and no script.
    nonce: Option<String>,
    script: PageScript,
}

impl Frame {
    /// The value the style of the page is named by.
    pub(crate) fn style_nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// The value the script of the page is named by, when it runs one.
    pub(crate) fn script_nonce(&self) -> Option<&str> {
        match self.script {
            PageScript::SecurityKey => self.nonce.as_deref(),
            PageScript::Nothing => None,
        }
    }
}

/// The script a page runs.
#[derive(Clone, Copy)]
enum PageScript {
    Nothing,
    /// The one that hands the ceremony of a security key to the browser.
    SecurityKey,
}

/// The sign-in page: why the last answer was refused, if one was, and what
/// the page asks next.
#[derive(Template)]
#[template(path = "login/sign_in.html")]
struct SignInPage<'a> {
    frame: Frame,
    /// Empty when nothing was refused.
    message: &'a str,
    asked: Asked<'a>,
}

/// What the sign-in page asks under its message.
enum Asked<'a> {
    /// Nothing: the page says why it refuses, and no more.
    Nothing,
    /// A name and a password.
    Password { realm: &'a str, request: Uuid },
    /// What the person owes after their password: a code, the answer of a
    /// security key, or either when they set up both.
    SecondFactor {
        realm: &'a str,
        request: Uuid,
        code: bool,
        key: Option<KeyPrompt<'a>>,
    },
}

/// Renders a hosted page, which `page` makes in the frame drawn for this answer.
pub(crate) fn render_page<P: Template>(
    product: &Product,
    status: StatusCode,
    page: impl FnOnce(Frame) -> P,
) -> HttpResponse {
    write_page(product, status, PageScript::Nothing, page)
}

/// Renders a page that runs the script of a security key, and nothing else:
/// the policy of the page names the script by a value drawn for this answer.
pub(crate) fn render_scripted_page<P: Template>(
    product: &Product,
    status: StatusCode,
    page: impl FnOnce(Frame) -> P,
) -> HttpResponse {
    write_page(product, status, PageScript::SecurityKey, page)
}

fn write_page<P: Template>(
    product: &Product,
    status: StatusCode,
    script: PageScript,
    page: impl FnOnce(Frame) -> P,
) -> HttpResponse {
    let mut nonce = [0_u8; 16];
    // A page without its style is still a page: a failed draw loses the
    // style and the script, and names no value anybody could guess.
    let drawn = product.random.fill(&mut nonce).is_ok();
    let frame = Frame {
        nonce: drawn.then(|| URL_SAFE_NO_PAD.encode(nonce)),
        script,
    };
    let policy = write_policy(&frame);
    answer_rendered(status, &policy, page(frame).render())
}

/// The policy of a page: nothing styles it or runs on it but what its
/// nonces name.
fn write_policy(frame: &Frame) -> String {
    let style = frame
        .style_nonce()
        .map_or_else(String::new, |nonce| format!(" style-src 'nonce-{nonce}';"));
    let script = frame
        .script_nonce()
        .map_or_else(String::new, |nonce| format!(" script-src 'nonce-{nonce}';"));
    format!("default-src 'none';{style}{script} frame-ancestors 'none'; base-uri 'none'")
}

/// The answer that carries a rendered page. A page that could not be
/// rendered sends nothing of itself.
fn answer_rendered(
    status: StatusCode,
    policy: &str,
    rendered: askama::Result<String>,
) -> HttpResponse {
    match rendered {
        Ok(page) => HttpResponse::build(status)
            .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
            .insert_header((CACHE_CONTROL, "no-store"))
            .insert_header(("Content-Security-Policy", policy))
            .body(page),
        Err(error) => {
            tracing::error!(%error, "a hosted page could not be rendered");
            HttpResponse::InternalServerError()
                .insert_header((CACHE_CONTROL, "no-store"))
                .finish()
        }
    }
}

pub(crate) fn render_refusal(product: &Product, failure: &Failure) -> HttpResponse {
    let status = match failure.code.kind() {
        ErrorKind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        ErrorKind::NotFound => StatusCode::NOT_FOUND,
        _ => StatusCode::BAD_REQUEST,
    };
    if status.is_server_error() {
        tracing::error!(
            code = failure.code.slug(),
            detail = failure.detail.as_deref(),
            "a sign-in page failed"
        );
    }
    let message = failure.code.message();
    render_page(product, status, |frame| SignInPage {
        frame,
        message,
        asked: Asked::Nothing,
    })
}

fn render_form(
    product: &Product,
    realm: &str,
    request: Uuid,
    status: StatusCode,
    message: &str,
) -> HttpResponse {
    let asked = Asked::Password { realm, request };
    render_page(product, status, |frame| SignInPage {
        frame,
        message,
        asked,
    })
}

/// The second step of the page: what the person owes after their password.
/// A code, the answer of a security key, or either when they set up both.
fn render_second_factor(
    product: &Product,
    realm: &str,
    request: Uuid,
    owed: &OwedSecondFactor,
    status: StatusCode,
    message: &str,
) -> HttpResponse {
    let key = owed.key.as_ref().map(|options| KeyPrompt {
        action: format!("/realms/{realm}/login"),
        request: Some(request),
        kind: KeyCeremonyKind::Proof,
        options,
        label: "Use a security key",
    });
    let script = match key {
        Some(_) => PageScript::SecurityKey,
        None => PageScript::Nothing,
    };
    let asked = Asked::SecondFactor {
        realm,
        request,
        code: owed.code,
        key,
    };
    write_page(product, status, script, |frame| SignInPage {
        frame,
        message,
        asked,
    })
}

/// Shows the second step again, with what the request still asks.
async fn show_second_factor_again(
    product: &Product,
    realm: &str,
    request: Uuid,
    browser_secret: &Secret,
    status: StatusCode,
    message: &str,
) -> HttpResponse {
    match describe_owed_second_factor(product, realm, request, browser_secret).await {
        Ok(Some(owed)) if is_realm_label(realm) && (owed.code || owed.key.is_some()) => {
            render_second_factor(product, realm, request, &owed, status, message)
        }
        Ok(_) => render_refusal(
            product,
            &Failure::new(ErrorCode::AuthorizationRequestExpired),
        ),
        Err(failure) => render_refusal(product, &failure),
    }
}

/// A request that still waits, and the browser that started it.
struct WaitingRequest<'a> {
    realm: &'a str,
    request: Uuid,
    browser_secret: &'a Secret,
}

/// The step of the page an answer was given at.
#[derive(Clone, Copy)]
enum AnsweredStep {
    /// The name and the password.
    Password,
    /// A code or the answer of a key, after the password.
    SecondFactor,
}

/// Shows a refused answer on the step it was given at: the first form
/// again, or what the request still asks after the password.
async fn show_refused_answer(
    product: &Product,
    waiting: &WaitingRequest<'_>,
    failure: &Failure,
    step: AnsweredStep,
) -> HttpResponse {
    let status = if failure.code == ErrorCode::HashingBusy {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::UNAUTHORIZED
    };
    let message = failure.code.message();
    match step {
        AnsweredStep::SecondFactor => {
            show_second_factor_again(
                product,
                waiting.realm,
                waiting.request,
                waiting.browser_secret,
                status,
                message,
            )
            .await
        }
        AnsweredStep::Password => {
            render_form(product, waiting.realm, waiting.request, status, message)
        }
    }
}

/// Where a browser goes once its person signed in: back to the client, with
/// its session, the mark of this sign-in beside the others it keeps, and the
/// flow over.
fn send_back_to_client(
    product: &Product,
    realm: &str,
    secure: bool,
    flow_cookie: &str,
    signed_in: SignedInForRequest,
    known_browsers: &[DeviceMark],
) -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header((LOCATION, signed_in.location))
        .insert_header((CACHE_CONTROL, "no-store"))
        .append_header((
            SET_COOKIE,
            write_cookie(
                &name_session_cookie(realm, secure),
                &signed_in.ticket.write(),
                // The session ends with the browser; the server ends it
                // at its lifetime whatever the cookie says.
                None,
                secure,
            ),
        ))
        // Kept past the session: it only lets this browser be counted
        // apart at its next sign-in, beside the marks of the others who
        // sign in on it.
        .append_header((
            SET_COOKIE,
            write_cookie(
                &name_device_cookie(realm, secure),
                &write_device_marks(&keep_device_marks(
                    signed_in.device_mark,
                    known_browsers,
                    product.now(),
                )),
                Some(DEVICE_MARK_LIFETIME.whole_seconds()),
                secure,
            ),
        ))
        // The flow is over: its cookie goes with it.
        .append_header((SET_COOKIE, write_cookie(flow_cookie, "", Some(0), secure)))
        .finish()
}

/// Where a browser goes once its person signed in for a client they must
/// allow first: on to the consent page, with its session and the mark of
/// this sign-in. The flow goes on, and keeps its cookie.
fn send_on_to_consent(
    product: &Product,
    realm: &str,
    secure: bool,
    signed_in: SignedInForConsent,
    known_browsers: &[DeviceMark],
) -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header((
            LOCATION,
            format!("/realms/{realm}/consent?request={}", signed_in.request),
        ))
        .insert_header((CACHE_CONTROL, "no-store"))
        .append_header((
            SET_COOKIE,
            write_cookie(
                &name_session_cookie(realm, secure),
                &signed_in.ticket.write(),
                None,
                secure,
            ),
        ))
        .append_header((
            SET_COOKIE,
            write_cookie(
                &name_device_cookie(realm, secure),
                &write_device_marks(&keep_device_marks(
                    signed_in.device_mark,
                    known_browsers,
                    product.now(),
                )),
                Some(DEVICE_MARK_LIFETIME.whole_seconds()),
                secure,
            ),
        ))
        .finish()
}

/// Tells whether a browser says the form was posted from another origin.
/// The cookie is already withheld from such a post: this refuses it by name.
pub(crate) fn is_posted_from_elsewhere(product: &Product, http: &HttpRequest) -> bool {
    http.headers().get(ORIGIN).is_some_and(|origin| {
        origin.as_bytes() != product.settings.public_origin.as_str().as_bytes()
    })
}

/// A realm name is used in a path and an attribute: only its own grammar is let through.
pub(crate) fn is_realm_label(realm: &str) -> bool {
    !realm.is_empty()
        && realm
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[get("/realms/{realm}/login")]
pub async fn show_sign_in(
    product: web::Data<Product>,
    realm: web::Path<String>,
    query: web::Query<PageQuery>,
) -> HttpResponse {
    let request = query
        .request
        .as_deref()
        .and_then(|text| Uuid::parse_str(text).ok());
    match request {
        Some(request) if is_realm_label(&realm) => {
            render_form(&product, &realm, request, StatusCode::OK, "")
        }
        _ => render_refusal(
            &product,
            &Failure::new(ErrorCode::AuthorizationRequestExpired),
        ),
    }
}

#[post("/realms/{realm}/login")]
pub async fn submit_sign_in(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    let expired = || {
        render_refusal(
            &product,
            &Failure::new(ErrorCode::AuthorizationRequestExpired),
        )
    };
    if is_posted_from_elsewhere(&product, &http) {
        return expired();
    }
    let Some(form) = read_posted_form::<SignInForm>(&http, payload).await else {
        return expired();
    };
    let Ok(request) = Uuid::parse_str(&form.request) else {
        return expired();
    };
    let secure = is_served_over_tls(&product);
    let flow_cookie = name_flow_cookie(request, secure);
    // Without the cookie the page was not started by this browser.
    let Some(browser_secret) = read_cookie(&http, &flow_cookie)
        .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
        .map(Secret::new)
    else {
        return expired();
    };

    let device_cookie = name_device_cookie(&realm, secure);
    let known_browsers = read_cookie(&http, &device_cookie)
        .map(|value| read_device_marks(&value))
        .unwrap_or_default();
    // A code and the answer of a key are the two answers to the second
    // step. Anything else must be the whole of the first one.
    let key_answer;
    let (answer, answered) = match (&form.key, &form.code, &form.username, form.password) {
        (Some(written), ..) => {
            // A key that did not answer is no guess: nothing is counted.
            let Ok(read) = serde_json::from_str::<serde_json::Value>(written) else {
                return show_second_factor_again(
                    &product,
                    &realm,
                    request,
                    &browser_secret,
                    StatusCode::BAD_REQUEST,
                    KEY_SILENT,
                )
                .await;
            };
            key_answer = read;
            (SignInAnswer::Key(&key_answer), AnsweredStep::SecondFactor)
        }
        (None, Some(code), ..) => (SignInAnswer::Code(code), AnsweredStep::SecondFactor),
        (None, None, Some(name), Some(password)) => (
            SignInAnswer::Password {
                name,
                password: Secret::new(password.into_bytes()),
            },
            AnsweredStep::Password,
        ),
        _ => return expired(),
    };
    let typed = TypedSignIn {
        answer,
        caller: read_caller_address(&product, &http),
        known_browsers: &known_browsers,
    };
    let step = finish_sign_in(&product, &realm, request, &browser_secret, typed).await;
    match step {
        Ok(SignInStep::Finished(signed_in)) => send_back_to_client(
            &product,
            &realm,
            secure,
            &flow_cookie,
            signed_in,
            &known_browsers,
        ),
        Ok(SignInStep::SecondFactorRequired(owed)) if is_realm_label(&realm) => {
            render_second_factor(&product, &realm, request, &owed, StatusCode::OK, "")
        }
        Ok(SignInStep::ConsentRequired(signed_in)) if is_realm_label(&realm) => {
            send_on_to_consent(&product, &realm, secure, signed_in, &known_browsers)
        }
        // The request still waits: the person tries again on the same step.
        Err(failure)
            if matches!(
                failure.code,
                ErrorCode::SignInFailed
                    | ErrorCode::CodeRejected
                    | ErrorCode::KeyRejected
                    | ErrorCode::HashingBusy
            ) && is_realm_label(&realm) =>
        {
            let waiting = WaitingRequest {
                realm: &realm,
                request,
                browser_secret: &browser_secret,
            };
            show_refused_answer(&product, &waiting, &failure, answered).await
        }
        Ok(SignInStep::SecondFactorRequired(_) | SignInStep::ConsentRequired(_)) => expired(),
        Err(failure) => render_refusal(&product, &failure),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use actix_web::HttpResponse;
    use actix_web::body::MessageBody;
    use actix_web::http::StatusCode;
    use actix_web::http::header::CACHE_CONTROL;
    use askama::Template;
    use saffui_core::ports::random::{Random, RandomUnavailable};
    use saffui_core::testkit::memory::MemoryStorage;
    use serde_json::json;
    use uuid::Uuid;

    use super::{
        Asked, Frame, PageScript, SignInPage, answer_rendered, render_page, render_scripted_page,
    };
    use crate::api::rest::endpoints::login::key_form::{KeyCeremonyKind, KeyPrompt};

    /// A value with each character HTML reads as markup, for a field of a page.
    pub(crate) const HOSTILE: &str = "<x'\"&";

    /// Checks that a page holds `held` hostile values, each written as text.
    pub(crate) fn assert_written_as_text(page: HttpResponse, held: usize) {
        let body = page.into_body().try_into_bytes().expect("a body");
        let body = String::from_utf8_lossy(&body);
        assert!(
            !body.contains("<x"),
            "a value reached the page as markup: {body}"
        );
        assert_eq!(
            body.matches("&#60;x").count(),
            held,
            "each value reached the page: {body}"
        );
    }

    /// A source that never answers.
    struct SilentRandom;

    impl Random for SilentRandom {
        fn fill(&self, _buffer: &mut [u8]) -> Result<(), RandomUnavailable> {
            Err(RandomUnavailable)
        }
    }

    /// The frame of a page drawn without a nonce: no style, no script.
    fn build_frame_without_nonce() -> Frame {
        Frame {
            nonce: None,
            script: PageScript::Nothing,
        }
    }

    /// The step of a sign-in that asks a security key for `options`.
    fn ask_key(options: &serde_json::Value) -> Asked<'_> {
        Asked::SecondFactor {
            realm: "acme",
            request: Uuid::nil(),
            code: false,
            key: Some(KeyPrompt {
                action: "/realms/acme/login".to_owned(),
                request: Some(Uuid::nil()),
                kind: KeyCeremonyKind::Proof,
                options,
                label: "Use a security key",
            }),
        }
    }

    #[test]
    fn a_page_whose_nonce_could_not_be_drawn_runs_no_script_and_names_no_value() {
        let (mut product, _storage) = MemoryStorage::wire();
        product.random = Arc::new(SilentRandom);
        let options = json!({ "publicKey": {} });

        let page = render_scripted_page(&product, StatusCode::OK, |frame| SignInPage {
            frame,
            message: "",
            asked: ask_key(&options),
        });

        let policy = page
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(!policy.contains("nonce-"), "{policy}");
        assert!(policy.starts_with("default-src 'none';"), "{policy}");
        let body = page.into_body().try_into_bytes().expect("a body");
        let body = String::from_utf8_lossy(&body);
        assert!(!body.contains("<script"), "{body}");
        assert!(!body.contains("<style"), "{body}");
    }

    #[test]
    fn text_is_written_as_text_whatever_it_holds() {
        let page = SignInPage {
            frame: build_frame_without_nonce(),
            message: "otpauth://totp/a:b?secret=X&issuer=\"<i>'",
            asked: Asked::Nothing,
        };

        let written = page.render().expect("a page");

        assert!(
            written.contains(
                "<p class=\"error\">otpauth://totp/a:b?secret=X&#38;issuer=&#34;&#60;i&#62;&#39;</p>"
            ),
            "{written}"
        );
    }

    #[test]
    fn the_options_of_a_key_cannot_leave_their_attribute() {
        let options =
            json!({ "publicKey": { "user": { "name": "\"><script>alert(1)</script>" } } });
        let page = SignInPage {
            frame: build_frame_without_nonce(),
            message: "",
            asked: ask_key(&options),
        };

        let form = page.render().expect("a page");

        assert!(!form.contains("<script>"), "{form}");
        assert!(form.contains("data-ceremony=\"get\""));
        assert!(form.contains("&#34;publicKey&#34;"));
        assert!(form.contains("name=\"request\" value=\"00000000-0000-0000-0000-000000000000\""));
    }

    #[test]
    fn every_text_the_sign_in_page_shows_is_written_as_text() {
        let (product, _storage) = MemoryStorage::wire();
        let options = json!({ "user": HOSTILE });
        let key = KeyPrompt {
            action: HOSTILE.to_owned(),
            request: Some(Uuid::nil()),
            kind: KeyCeremonyKind::Proof,
            options: &options,
            label: HOSTILE,
        };
        let pages = [
            (Asked::Nothing, 1),
            (
                Asked::Password {
                    realm: HOSTILE,
                    request: Uuid::nil(),
                },
                2,
            ),
            (
                Asked::SecondFactor {
                    realm: HOSTILE,
                    request: Uuid::nil(),
                    code: true,
                    key: Some(key),
                },
                5,
            ),
        ];

        for (asked, held) in pages {
            let page = render_page(&product, StatusCode::OK, |frame| SignInPage {
                frame,
                message: HOSTILE,
                asked,
            });
            assert_written_as_text(page, held);
        }
    }

    #[test]
    fn a_page_that_could_not_be_rendered_sends_nothing_of_itself() {
        let answer = answer_rendered(
            StatusCode::OK,
            "default-src 'none'",
            Err(askama::Error::Fmt),
        );

        assert_eq!(answer.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            answer
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let body = answer.into_body().try_into_bytes().expect("a body");
        assert!(body.is_empty(), "{body:?}");
    }
}
