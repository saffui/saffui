//! The pages on which a signed-in person sets up their authenticator
//! application: a secret is shown once, then confirmed by the password of
//! the person and a first code.

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use askama::Template;
use saffui_core::app::App as Product;
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::login::device::{DeviceMark, read_device_marks};
use saffui_core::login::enroll::{
    EnrollmentState, begin_totp_enrollment, confirm_totp_enrollment, describe_enrollment,
};
use saffui_core::login::session::SessionTicket;
use saffui_core::secret::Secret;
use serde::Deserialize;

use crate::api::rest::endpoints::login::page::{
    Frame, is_posted_from_elsewhere, is_realm_label, render_page, render_refusal,
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

pub(crate) fn read_ticket(
    product: &Product,
    realm: &str,
    http: &HttpRequest,
) -> Option<SessionTicket> {
    let name = name_session_cookie(realm, is_served_over_tls(product));
    read_cookie(http, &name).and_then(|value| SessionTicket::parse(&value))
}

/// The page of the authenticator application.
#[derive(Template)]
#[template(path = "account/authenticator.html")]
struct AuthenticatorPage<'a> {
    frame: Frame,
    shown: Shown<'a>,
}

/// What the page shows under its heading.
enum Shown<'a> {
    /// Why the page refuses, and no form.
    Refusal {
        message: &'a str,
    },
    Enrolled,
    /// The offer to set one up.
    Offer {
        realm: &'a str,
    },
    /// The secret, shown once, and the form that confirms it.
    Secret {
        realm: &'a str,
        uri: &'a str,
        typed_secret: &'a str,
    },
    /// The form again, with why the last confirmation was refused.
    Confirmation {
        realm: &'a str,
        message: &'a str,
    },
    Confirmed,
}

fn render_shown(product: &Product, status: StatusCode, shown: Shown<'_>) -> HttpResponse {
    render_page(product, status, |frame| AuthenticatorPage { frame, shown })
}

/// A refusal of these pages: the status of its kind, its message, no form.
fn refuse_request(product: &Product, failure: &Failure) -> HttpResponse {
    let status = match failure.code {
        ErrorCode::SessionRequired => StatusCode::UNAUTHORIZED,
        ErrorCode::SecondFactorProofRequired => StatusCode::FORBIDDEN,
        _ => return render_refusal(product, failure),
    };
    let message = failure.code.message();
    render_shown(product, status, Shown::Refusal { message })
}

#[get("/realms/{realm}/account/authenticator")]
pub async fn show_authenticator(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
) -> HttpResponse {
    let ticket = read_ticket(&product, &realm, &http);
    match describe_enrollment(&product, &realm, ticket.as_ref()).await {
        Ok(EnrollmentState::Enrolled) => render_shown(&product, StatusCode::OK, Shown::Enrolled),
        Ok(EnrollmentState::NotEnrolled | EnrollmentState::Pending) if is_realm_label(&realm) => {
            render_shown(&product, StatusCode::OK, Shown::Offer { realm: &realm })
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
            let shown = Shown::Secret {
                realm: &realm,
                uri: &offered.uri,
                typed_secret: &offered.typed_secret,
            };
            render_shown(&product, StatusCode::OK, shown)
        }
        Err(failure) if failure.code == ErrorCode::AuthenticatorAlreadyEnrolled => {
            let message = failure.code.message();
            render_shown(&product, StatusCode::CONFLICT, Shown::Refusal { message })
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
        let shown = Shown::Confirmation {
            realm: &realm,
            message: ErrorCode::RequestInvalid.message(),
        };
        return render_shown(&product, StatusCode::BAD_REQUEST, shown);
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
        Ok(()) => render_shown(&product, StatusCode::OK, Shown::Confirmed),
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
            let shown = Shown::Confirmation {
                realm: &realm,
                message: failure.code.message(),
            };
            render_shown(&product, status, shown)
        }
        Err(failure) if failure.code == ErrorCode::AuthenticatorAlreadyEnrolled => {
            let message = failure.code.message();
            render_shown(&product, StatusCode::CONFLICT, Shown::Refusal { message })
        }
        Err(failure) => refuse_request(&product, &failure),
    }
}
