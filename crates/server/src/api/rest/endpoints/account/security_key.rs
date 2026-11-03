//! The pages on which a signed-in person adds a security key: their
//! password first, then the key answers the browser.

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use saffui_core::app::App as Product;
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::login::enroll::{
    begin_key_enrollment, count_security_keys, finish_key_enrollment,
};
use saffui_core::secret::Secret;
use serde::Deserialize;

use super::authenticator::{read_marks, read_ticket};
use crate::api::rest::endpoints::login::key_form::{
    KEY_SCRIPT, KEY_SILENT, KeyCeremonyKind, write_key_form,
};
use crate::api::rest::endpoints::login::page::{
    is_posted_from_elsewhere, is_realm_label, render_page, render_refusal, render_scripted_page,
};
use crate::extract::form::read_posted_form;
use crate::middleware::caller_address::read_caller_address;

const HEADING: &str = "<h1>Security key</h1>";

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

fn write_password_form(realm: &str, message: &str) -> String {
    let message = if message.is_empty() {
        String::new()
    } else {
        format!("<p class=\"error\">{message}</p>")
    };
    format!(
        "{message}<form method=\"post\" action=\"/realms/{realm}/account/security-key\">\
         <label>Your password<input name=\"password\" type=\"password\" \
         autocomplete=\"current-password\" required></label>\
         <button type=\"submit\">Add a security key</button></form>"
    )
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
    let class = if status.is_success() {
        ""
    } else {
        " class=\"error\""
    };
    let link = match start_again {
        StartAgain::Offered => {
            format!("<p><a href=\"/realms/{realm}/account/security-key\">Start again</a></p>")
        }
        StartAgain::NotOffered => String::new(),
    };
    render_page(
        product,
        status,
        &format!("{HEADING}<p{class}>{note}</p>{link}"),
    )
}

/// A refusal of these pages: the status of its kind, its message, no form.
fn refuse_request(product: &Product, failure: &Failure) -> HttpResponse {
    let status = match failure.code {
        ErrorCode::SessionRequired => StatusCode::UNAUTHORIZED,
        ErrorCode::SecondFactorProofRequired => StatusCode::FORBIDDEN,
        _ => return render_refusal(product, failure),
    };
    let body = format!("{HEADING}<p class=\"error\">{}</p>", failure.code.message());
    render_page(product, status, &body)
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
            let held = match held {
                0 => "No security key is set up for this account.".to_owned(),
                1 => "1 security key is set up for this account.".to_owned(),
                many => format!("{many} security keys are set up for this account."),
            };
            let body = format!(
                "{HEADING}<p>{held}</p><p>A security key you add will be asked each time \
                 you sign in.</p>{}",
                write_password_form(&realm, "")
            );
            render_page(&product, StatusCode::OK, &body)
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
        let body = format!(
            "{HEADING}{}",
            write_password_form(&realm, ErrorCode::RequestInvalid.message())
        );
        return render_page(&product, StatusCode::BAD_REQUEST, &body);
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
            let key_form = write_key_form(
                &format!("/realms/{realm}/account/security-key/confirm"),
                None,
                KeyCeremonyKind::Enrollment,
                &options,
                "Add this security key",
            );
            let body = format!("{HEADING}<p>Have your security key at hand.</p>{key_form}");
            render_scripted_page(&product, StatusCode::OK, &body, KEY_SCRIPT)
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
            let body = format!(
                "{HEADING}{}",
                write_password_form(&realm, failure.code.message())
            );
            render_page(&product, status, &body)
        }
        // The one refusal of a key before any key answered: no room is left.
        Err(failure) if failure.code == ErrorCode::KeyRejected => render_note(
            &product,
            &realm,
            StatusCode::CONFLICT,
            "This account holds as many security keys as it may.",
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
