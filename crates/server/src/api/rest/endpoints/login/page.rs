//! The sign-in page of a pending authorization request, and its submission.

use actix_web::http::StatusCode;
use actix_web::http::header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION, ORIGIN, SET_COOKIE};
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use saffui_core::app::App as Product;
use saffui_core::error::{ErrorCode, ErrorKind, Failure};
use saffui_core::login::device::DeviceMark;
use saffui_core::login::device::{
    DEVICE_MARK_LIFETIME, keep_device_marks, read_device_marks, write_device_marks,
};
use saffui_core::oidc::authorize::{
    OwedSecondFactor, SignInAnswer, SignInStep, SignedInForRequest, TypedSignIn,
    describe_owed_second_factor, finish_sign_in,
};
use saffui_core::secret::Secret;
use serde::Deserialize;
use uuid::Uuid;

use super::key_form::{KEY_SCRIPT, KEY_SILENT, KeyCeremonyKind, write_key_form};
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

/// Renders a page of the sign-in flow. Nothing on it comes from the client:
/// the realm is a host label, the request an identifier, the message ours.
pub(crate) fn render_page(product: &Product, status: StatusCode, body: &str) -> HttpResponse {
    write_page(product, status, body, None)
}

/// Renders a page that runs `script`, and nothing else: the policy of the
/// page names the script by a value drawn for this answer.
pub(crate) fn render_scripted_page(
    product: &Product,
    status: StatusCode,
    body: &str,
    script: &'static str,
) -> HttpResponse {
    write_page(product, status, body, Some(script))
}

fn write_page(
    product: &Product,
    status: StatusCode,
    body: &str,
    script: Option<&'static str>,
) -> HttpResponse {
    let mut nonce = [0_u8; 16];
    // A page without its style is still a page: a failed draw loses the
    // style and the script, and names no value anybody could guess.
    let drawn = product.random.fill(&mut nonce).is_ok();
    let nonce = URL_SAFE_NO_PAD.encode(nonce);
    let (script, script_policy) = match script {
        Some(script) if drawn => (
            format!("<script nonce=\"{nonce}\">{script}</script>"),
            format!(" script-src 'nonce-{nonce}';"),
        ),
        _ => (String::new(), String::new()),
    };
    let (style, style_policy) = if drawn {
        (
            format!(
                "<style nonce=\"{nonce}\">\
                 body{{font-family:system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem}}\
                 label{{display:block;margin-top:1rem}}input{{width:100%;padding:.5rem;box-sizing:border-box}}\
                 button{{margin-top:1.5rem;padding:.6rem 1rem}}.error{{color:#a3341f}}</style>"
            ),
            format!(" style-src 'nonce-{nonce}';"),
        )
    } else {
        (String::new(), String::new())
    };
    let page = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>Account</title>{style}</head><body>{body}{script}</body></html>"
    );
    HttpResponse::build(status)
        .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header((CACHE_CONTROL, "no-store"))
        .insert_header((
            "Content-Security-Policy",
            format!(
                "default-src 'none';{style_policy}{script_policy} \
                 frame-ancestors 'none'; base-uri 'none'"
            ),
        ))
        .body(page)
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
    let body = format!(
        "<h1>Sign in</h1><p class=\"error\">{}</p>",
        failure.code.message()
    );
    render_page(product, status, &body)
}

fn write_message(message: &str) -> String {
    if message.is_empty() {
        String::new()
    } else {
        format!("<p class=\"error\">{message}</p>")
    }
}

fn render_form(
    product: &Product,
    realm: &str,
    request: Uuid,
    status: StatusCode,
    message: &str,
) -> HttpResponse {
    let message = write_message(message);
    let body = format!(
        "<h1>Sign in</h1>{message}<form method=\"post\" action=\"/realms/{realm}/login\">\
         <input type=\"hidden\" name=\"request\" value=\"{request}\">\
         <label>Username<input name=\"username\" autocomplete=\"username\" required autofocus></label>\
         <label>Password<input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label>\
         <button type=\"submit\">Sign in</button></form>"
    );
    render_page(product, status, &body)
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
    let message = write_message(message);
    let action = format!("/realms/{realm}/login");
    let code_form = if owed.code {
        format!(
            "<p>Enter the code your authenticator application shows.</p>\
             <form method=\"post\" action=\"{action}\">\
             <input type=\"hidden\" name=\"request\" value=\"{request}\">\
             <label>Code<input name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" \
             maxlength=\"6\" required autofocus></label>\
             <button type=\"submit\">Continue</button></form>"
        )
    } else {
        String::new()
    };
    let Some(options) = &owed.key else {
        let body = format!("<h1>Sign in</h1>{message}{code_form}");
        return render_page(product, status, &body);
    };
    let key_form = write_key_form(
        &action,
        Some(request),
        KeyCeremonyKind::Proof,
        options,
        "Use a security key",
    );
    let body = format!(
        "<h1>Sign in</h1>{message}{code_form}<p>Have your security key at hand.</p>{key_form}"
    );
    render_scripted_page(product, status, &body, KEY_SCRIPT)
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
        Ok(SignInStep::SecondFactorRequired(_)) => expired(),
        Err(failure) => render_refusal(&product, &failure),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::body::MessageBody;
    use actix_web::http::StatusCode;
    use saffui_core::ports::random::{Random, RandomUnavailable};
    use saffui_core::testkit::memory::MemoryStorage;

    use super::render_scripted_page;
    use crate::api::rest::endpoints::login::key_form::KEY_SCRIPT;

    /// A source that never answers.
    struct SilentRandom;

    impl Random for SilentRandom {
        fn fill(&self, _buffer: &mut [u8]) -> Result<(), RandomUnavailable> {
            Err(RandomUnavailable)
        }
    }

    #[test]
    fn a_page_whose_nonce_could_not_be_drawn_runs_no_script_and_names_no_value() {
        let (mut product, _storage) = MemoryStorage::wire();
        product.random = Arc::new(SilentRandom);

        let page = render_scripted_page(&product, StatusCode::OK, "<p>Key</p>", KEY_SCRIPT);

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
}
