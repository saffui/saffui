//! The pages on which a signed-in person adds a security key: their
//! password first, then the key answers the browser.

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use askama::Template;
use saffui_core::app::App as Product;
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::login::enroll::{
    begin_key_enrollment, count_security_keys, finish_key_enrollment,
};
use saffui_core::secret::Secret;
use serde::Deserialize;

use super::authenticator::{read_marks, read_ticket};
use crate::api::rest::endpoints::login::key_form::{KEY_SILENT, KeyCeremonyKind, KeyPrompt};
use crate::api::rest::endpoints::login::page::{
    Frame, is_posted_from_elsewhere, is_realm_label, render_page, render_refusal,
    render_scripted_page,
};
use crate::extract::form::read_posted_form;
use crate::middleware::caller_address::read_caller_address;

const KEYS_NOT_SERVED: &str = "This service cannot use security keys: none can be added here.";

// No `Debug`: the form carries a password.
#[derive(Deserialize)]
pub struct PasswordForm {
    password: String,
}

#[derive(Deserialize)]
pub struct KeyForm {
    /// What the browser handed back from the key, as JSON.
    key: String,
}

/// The page of the security keys.
#[derive(Template)]
#[template(path = "account/security_key.html")]
struct SecurityKeyPage<'a> {
    frame: Frame,
    shown: Shown<'a>,
}

/// What the page shows under its heading.
enum Shown<'a> {
    /// How many keys the account holds, and the form that adds one where
    /// this service can use them.
    Held {
        realm: &'a str,
        held: usize,
        served: bool,
    },
    /// The form of the password again, with why it was refused.
    PasswordForm { realm: &'a str, message: &'a str },
    /// The form the key answers.
    Key(KeyPrompt<'a>),
    /// One thing said, as a refusal unless `status` is a success.
    Note {
        realm: &'a str,
        status: StatusCode,
        note: &'a str,
        start_again: StartAgain,
    },
    /// Why the page refuses, and no form.
    Refusal { message: &'a str },
}

fn render_shown(product: &Product, status: StatusCode, shown: Shown<'_>) -> HttpResponse {
    render_page(product, status, |frame| SecurityKeyPage { frame, shown })
}

/// Whether a note offers to start the enrollment again.
#[derive(Clone, Copy)]
enum StartAgain {
    Offered,
    /// The key is set up, or the account holds as many as it may.
    NotOffered,
}

/// A page that says one thing, and offers to start again when it can.
fn render_note(
    product: &Product,
    realm: &str,
    status: StatusCode,
    note: &str,
    start_again: StartAgain,
) -> HttpResponse {
    let shown = Shown::Note {
        realm,
        status,
        note,
        start_again,
    };
    render_shown(product, status, shown)
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

#[get("/realms/{realm}/account/security-key")]
pub async fn show_security_keys(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
) -> HttpResponse {
    let ticket = read_ticket(&product, &realm, &http);
    match count_security_keys(&product, &realm, ticket.as_ref()).await {
        Ok(held) if is_realm_label(&realm) => {
            let shown = Shown::Held {
                realm: &realm,
                held,
                served: product.security_keys.are_served(),
            };
            render_shown(&product, StatusCode::OK, shown)
        }
        Ok(_) => refuse_request(&product, &Failure::new(ErrorCode::RealmNotFound)),
        Err(failure) => refuse_request(&product, &failure),
    }
}

#[post("/realms/{realm}/account/security-key")]
pub async fn begin_enrollment(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    // The session cookie is withheld from a form another site posts: this
    // refuses such a post by name, before its form is read.
    if is_posted_from_elsewhere(&product, &http) || !is_realm_label(&realm) {
        return refuse_request(&product, &Failure::new(ErrorCode::SessionRequired));
    }
    let ticket = read_ticket(&product, &realm, &http);
    if ticket.is_none() {
        return refuse_request(&product, &Failure::new(ErrorCode::SessionRequired));
    }
    let Some(form) = read_posted_form::<PasswordForm>(&http, payload).await else {
        let shown = Shown::PasswordForm {
            realm: &realm,
            message: ErrorCode::RequestInvalid.message(),
        };
        return render_shown(&product, StatusCode::BAD_REQUEST, shown);
    };
    let begun = begin_key_enrollment(
        &product,
        &realm,
        ticket.as_ref(),
        Secret::new(form.password.into_bytes()),
        read_caller_address(&product, &http),
        &read_marks(&product, &realm, &http),
    )
    .await;
    match begun {
        Ok(options) => {
            let shown = Shown::Key(KeyPrompt {
                action: format!("/realms/{realm}/account/security-key/confirm"),
                request: None,
                kind: KeyCeremonyKind::Enrollment,
                options: &options,
                label: "Add this security key",
            });
            render_scripted_page(&product, StatusCode::OK, |frame| SecurityKeyPage {
                frame,
                shown,
            })
        }
        Err(failure)
            if matches!(
                failure.code,
                ErrorCode::SignInFailed | ErrorCode::HashingBusy
            ) =>
        {
            let status = if failure.code == ErrorCode::HashingBusy {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::UNAUTHORIZED
            };
            let shown = Shown::PasswordForm {
                realm: &realm,
                message: failure.code.message(),
            };
            render_shown(&product, status, shown)
        }
        // The one refusal of a key before any key answered: no room is left.
        Err(failure) if failure.code == ErrorCode::KeyRejected => render_note(
            &product,
            &realm,
            StatusCode::CONFLICT,
            "This account holds as many security keys as it may.",
            StartAgain::NotOffered,
        ),
        Err(failure) if failure.code == ErrorCode::SecurityKeysNotServed => render_note(
            &product,
            &realm,
            StatusCode::FORBIDDEN,
            KEYS_NOT_SERVED,
            StartAgain::NotOffered,
        ),
        Err(failure) => refuse_request(&product, &failure),
    }
}

#[post("/realms/{realm}/account/security-key/confirm")]
pub async fn finish_enrollment(
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
    let Some(form) = read_posted_form::<KeyForm>(&http, payload).await else {
        return render_note(
            &product,
            &realm,
            StatusCode::BAD_REQUEST,
            KEY_SILENT,
            StartAgain::Offered,
        );
    };
    let Ok(answer) = serde_json::from_str::<serde_json::Value>(&form.key) else {
        return render_note(
            &product,
            &realm,
            StatusCode::BAD_REQUEST,
            KEY_SILENT,
            StartAgain::Offered,
        );
    };
    match finish_key_enrollment(&product, &realm, ticket.as_ref(), &answer).await {
        Ok(()) => render_note(
            &product,
            &realm,
            StatusCode::OK,
            "Your security key is set up. It will be asked the next time you sign in.",
            StartAgain::NotOffered,
        ),
        // What was started is spent: the person starts again from their password.
        Err(failure) if failure.code == ErrorCode::KeyRejected => render_note(
            &product,
            &realm,
            StatusCode::BAD_REQUEST,
            failure.code.message(),
            StartAgain::Offered,
        ),
        Err(failure) => refuse_request(&product, &failure),
    }
}
