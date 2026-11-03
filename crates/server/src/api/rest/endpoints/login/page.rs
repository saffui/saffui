//! The sign-in page of a pending authorization request, and its submission.

use actix_web::http::StatusCode;
use actix_web::http::header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION, ORIGIN, SET_COOKIE};
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use saffui_core::app::App as Product;
use saffui_core::error::{ErrorCode, ErrorKind, Failure};
use saffui_core::oidc::authorize::finish_sign_in;
use saffui_core::secret::Secret;
use serde::Deserialize;
use uuid::Uuid;

use crate::extract::cookies::{
    is_served_over_tls, name_flow_cookie, name_session_cookie, read_cookie, write_cookie,
};
use crate::middleware::caller_address::read_caller_address;

#[derive(Deserialize)]
pub struct PageQuery {
    request: Option<String>,
}

// No `Debug`: the form carries a password.
#[derive(Deserialize)]
pub struct SignInForm {
    request: String,
    username: String,
    password: String,
}

/// Renders a page of the sign-in flow. Nothing on it comes from the client:
/// the realm is a host label, the request an identifier, the message ours.
pub(crate) fn render_page(product: &Product, status: StatusCode, body: &str) -> HttpResponse {
    let mut nonce = [0_u8; 16];
    // A page without its style is still a page: a failed draw only loses the style.
    let _ = product.random.fill(&mut nonce);
    let nonce = URL_SAFE_NO_PAD.encode(nonce);
    let page = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>Account</title><style nonce=\"{nonce}\">\
         body{{font-family:system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem}}\
         label{{display:block;margin-top:1rem}}input{{width:100%;padding:.5rem;box-sizing:border-box}}\
         button{{margin-top:1.5rem;padding:.6rem 1rem}}.error{{color:#a3341f}}</style></head>\
         <body>{body}</body></html>"
    );
    HttpResponse::build(status)
        .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header((CACHE_CONTROL, "no-store"))
        .insert_header((
            "Content-Security-Policy",
            format!("default-src 'none'; style-src 'nonce-{nonce}'; frame-ancestors 'none'; base-uri 'none'"),
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

fn render_form(
    product: &Product,
    realm: &str,
    request: Uuid,
    status: StatusCode,
    message: &str,
) -> HttpResponse {
    let message = if message.is_empty() {
        String::new()
    } else {
        format!("<p class=\"error\">{message}</p>")
    };
    let body = format!(
        "<h1>Sign in</h1>{message}<form method=\"post\" action=\"/realms/{realm}/login\">\
         <input type=\"hidden\" name=\"request\" value=\"{request}\">\
         <label>Username<input name=\"username\" autocomplete=\"username\" required autofocus></label>\
         <label>Password<input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label>\
         <button type=\"submit\">Sign in</button></form>"
    );
    render_page(product, status, &body)
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
    form: web::Form<SignInForm>,
) -> HttpResponse {
    let form = form.into_inner();
    let expired = || {
        render_refusal(
            &product,
            &Failure::new(ErrorCode::AuthorizationRequestExpired),
        )
    };
    let Ok(request) = Uuid::parse_str(&form.request) else {
        return expired();
    };
    if is_posted_from_elsewhere(&product, &http) {
        return expired();
    }
    let secure = is_served_over_tls(&product);
    let flow_cookie = name_flow_cookie(request, secure);
    // Without the cookie the page was not started by this browser.
    let Some(browser_secret) = read_cookie(&http, &flow_cookie)
        .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
        .map(Secret::new)
    else {
        return expired();
    };

    let signed_in = finish_sign_in(
        &product,
        &realm,
        request,
        &browser_secret,
        &form.username,
        Secret::new(form.password.into_bytes()),
        read_caller_address(&product, &http),
    )
    .await;
    match signed_in {
        Ok(signed_in) => HttpResponse::SeeOther()
            .insert_header((LOCATION, signed_in.location))
            .insert_header((CACHE_CONTROL, "no-store"))
            .append_header((
                SET_COOKIE,
                write_cookie(
                    &name_session_cookie(&realm, secure),
                    &signed_in.ticket.write(),
                    // The session ends with the browser; the server ends it
                    // at its lifetime whatever the cookie says.
                    None,
                    secure,
                ),
            ))
            // The flow is over: its cookie goes with it.
            .append_header((SET_COOKIE, write_cookie(&flow_cookie, "", Some(0), secure)))
            .finish(),
        // The request still waits: the person tries again on the same page.
        Err(failure)
            if matches!(
                failure.code,
                ErrorCode::SignInFailed | ErrorCode::HashingBusy
            ) && is_realm_label(&realm) =>
        {
            let status = if failure.code == ErrorCode::SignInFailed {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            render_form(&product, &realm, request, status, failure.code.message())
        }
        Err(failure) => render_refusal(&product, &failure),
    }
}
