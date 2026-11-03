//! The pages on which a signed-in person sets up their authenticator
//! application: a secret is shown once, then confirmed by the password of
//! the person and a first code.

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use saffui_core::app::App as Product;
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::login::device::{DeviceMark, read_device_marks};
use saffui_core::login::enroll::{
    EnrollmentState, begin_totp_enrollment, confirm_totp_enrollment, describe_enrollment,
};
use saffui_core::login::session::SessionTicket;
use saffui_core::secret::Secret;
use serde::Deserialize;

use crate::api::rest::endpoints::login::key_form::escape_text;
use crate::api::rest::endpoints::login::page::{
    is_posted_from_elsewhere, is_realm_label, render_page, render_refusal,
};
use crate::extract::cookies::{
    is_served_over_tls, name_device_cookie, name_session_cookie, read_cookie,
};
use crate::extract::form::read_posted_form;
use crate::middleware::caller_address::read_caller_address;

// No `Debug`: the form carries a password.
#[derive(Deserialize)]
pub struct ConfirmationForm {
    password: String,
    code: String,
}

/// The marks of earlier sign-ins the browser brings: the password typed
/// again here is counted as at sign-in.
pub(super) fn read_marks(product: &Product, realm: &str, http: &HttpRequest) -> Vec<DeviceMark> {
    let name = name_device_cookie(realm, is_served_over_tls(product));
    read_cookie(http, &name)
        .map(|value| read_device_marks(&value))
        .unwrap_or_default()
}

pub(super) fn read_ticket(
    product: &Product,
    realm: &str,
    http: &HttpRequest,
) -> Option<SessionTicket> {
    let name = name_session_cookie(realm, is_served_over_tls(product));
    read_cookie(http, &name).and_then(|value| SessionTicket::parse(&value))
}

fn write_confirmation_form(realm: &str, message: &str) -> String {
    let message = if message.is_empty() {
        String::new()
    } else {
        format!("<p class=\"error\">{message}</p>")
    };
    format!(
        "{message}<form method=\"post\" action=\"/realms/{realm}/account/authenticator/confirm\">\
         <label>Your password<input name=\"password\" type=\"password\" \
         autocomplete=\"current-password\" required></label>\
         <label>The code your application shows<input name=\"code\" inputmode=\"numeric\" \
         autocomplete=\"one-time-code\" maxlength=\"6\" required></label>\
         <button type=\"submit\">Confirm</button></form>"
    )
}

/// A refusal of these pages: the status of its kind, its message, no form.
fn refuse_request(product: &Product, failure: &Failure) -> HttpResponse {
    let status = match failure.code {
        ErrorCode::SessionRequired => StatusCode::UNAUTHORIZED,
        ErrorCode::SecondFactorProofRequired => StatusCode::FORBIDDEN,
        _ => return render_refusal(product, failure),
    };
    let body = format!(
        "<h1>Authenticator application</h1><p class=\"error\">{}</p>",
        failure.code.message()
    );
    render_page(product, status, &body)
}

#[get("/realms/{realm}/account/authenticator")]
pub async fn show_authenticator(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
) -> HttpResponse {
    let ticket = read_ticket(&product, &realm, &http);
    match describe_enrollment(&product, &realm, ticket.as_ref()).await {
        Ok(EnrollmentState::Enrolled) => render_page(
            &product,
            StatusCode::OK,
            "<h1>Authenticator application</h1><p>An authenticator application is set up \
             for this account. An administrator can remove it if you lost it.</p>",
        ),
        Ok(EnrollmentState::NotEnrolled | EnrollmentState::Pending) if is_realm_label(&realm) => {
            let body = format!(
                "<h1>Authenticator application</h1><p>A code from an application on your \
                 phone will be asked each time you sign in.</p>\
                 <form method=\"post\" action=\"/realms/{realm}/account/authenticator\">\
                 <button type=\"submit\">Set up an authenticator application</button></form>"
            );
            render_page(&product, StatusCode::OK, &body)
        }
        Ok(_) => refuse_request(&product, &Failure::new(ErrorCode::RealmNotFound)),
        Err(failure) => refuse_request(&product, &failure),
    }
}

#[post("/realms/{realm}/account/authenticator")]
pub async fn begin_enrollment(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
) -> HttpResponse {
    // The session cookie is withheld from a form another site posts: this
    // refuses such a post by name, before a secret is made.
    if is_posted_from_elsewhere(&product, &http) || !is_realm_label(&realm) {
        return refuse_request(&product, &Failure::new(ErrorCode::SessionRequired));
    }
    let ticket = read_ticket(&product, &realm, &http);
    match begin_totp_enrollment(&product, &realm, ticket.as_ref()).await {
        Ok(offered) => {
            // Shown once, on a page no cache keeps. The secret serves for
            // nothing until the form below confirms it.
            let body = format!(
                "<h1>Authenticator application</h1>\
                 <p>Add this account to your application, with this address or this key.</p>\
                 <p><code id=\"uri\">{}</code></p><p>Key: <code id=\"secret\">{}</code></p>{}",
                escape_text(&offered.uri),
                escape_text(&offered.typed_secret),
                write_confirmation_form(&realm, "")
            );
            render_page(&product, StatusCode::OK, &body)
        }
        Err(failure) if failure.code == ErrorCode::AuthenticatorAlreadyEnrolled => {
            let body = format!(
                "<h1>Authenticator application</h1><p class=\"error\">{}</p>",
                failure.code.message()
            );
            render_page(&product, StatusCode::CONFLICT, &body)
        }
        Err(failure) => refuse_request(&product, &failure),
    }
}

#[post("/realms/{realm}/account/authenticator/confirm")]
pub async fn confirm_enrollment(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    if is_posted_from_elsewhere(&product, &http) || !is_realm_label(&realm) {
        return refuse_request(&product, &Failure::new(ErrorCode::SessionRequired));
    }
    let ticket = read_ticket(&product, &realm, &http);
    if ticket.is_none() {
        return refuse_request(&product, &Failure::new(ErrorCode::SessionRequired));
    }
    let Some(form) = read_posted_form::<ConfirmationForm>(&http, payload).await else {
        let body = format!(
            "<h1>Authenticator application</h1>{}",
            write_confirmation_form(&realm, ErrorCode::RequestInvalid.message())
        );
        return render_page(&product, StatusCode::BAD_REQUEST, &body);
    };
    let confirmed = confirm_totp_enrollment(
        &product,
        &realm,
        ticket.as_ref(),
        Secret::new(form.password.into_bytes()),
        &form.code,
        read_caller_address(&product, &http),
        &read_marks(&product, &realm, &http),
    )
    .await;
    match confirmed {
        Ok(()) => render_page(
            &product,
            StatusCode::OK,
            "<h1>Authenticator application</h1><p>Your authenticator application is set up. \
             A code will be asked the next time you sign in.</p>",
        ),
        // The secret still waits: the person tries again, without seeing it again.
        Err(failure)
            if matches!(
                failure.code,
                ErrorCode::SignInFailed | ErrorCode::CodeRejected | ErrorCode::HashingBusy
            ) =>
        {
            let status = if failure.code == ErrorCode::HashingBusy {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::UNAUTHORIZED
            };
            let body = format!(
                "<h1>Authenticator application</h1>{}",
                write_confirmation_form(&realm, failure.code.message())
            );
            render_page(&product, status, &body)
        }
        Err(failure) if failure.code == ErrorCode::AuthenticatorAlreadyEnrolled => {
            let body = format!(
                "<h1>Authenticator application</h1><p class=\"error\">{}</p>",
                failure.code.message()
            );
            render_page(&product, StatusCode::CONFLICT, &body)
        }
        Err(failure) => refuse_request(&product, &failure),
    }
}
