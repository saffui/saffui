//! The page on which a signed-in person sees what they allowed clients, and
//! withdraws it.

use std::fmt::Write as _;

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use saffui_core::app::App as Product;
use saffui_core::consent::manage::{list_my_consents, withdraw_my_consent};
use saffui_core::error::{ErrorCode, Failure};
use serde::Deserialize;

use super::authenticator::read_ticket;
use crate::api::rest::endpoints::login::key_form::escape_text;
use crate::api::rest::endpoints::login::page::{
    is_posted_from_elsewhere, is_realm_label, render_page, render_refusal,
};
use crate::extract::form::read_posted_form;

const HEADING: &str = "<h1>Your consents</h1>";

#[derive(Deserialize)]
pub struct WithdrawalForm {
    client_id: String,
}

/// A refusal of these pages: a person who is not signed in is told so.
fn refuse_request(product: &Product, failure: &Failure) -> HttpResponse {
    if failure.code == ErrorCode::SessionRequired {
        let body = format!("{HEADING}<p class=\"error\">{}</p>", failure.code.message());
        return render_page(product, StatusCode::UNAUTHORIZED, &body);
    }
    render_refusal(product, failure)
}

#[get("/realms/{realm}/account/consents")]
pub async fn show_consents(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
) -> HttpResponse {
    if !is_realm_label(&realm) {
        return refuse_request(&product, &Failure::new(ErrorCode::RealmNotFound));
    }
    let ticket = read_ticket(&product, &realm, &http);
    let listed = match list_my_consents(&product, &realm, ticket.as_ref()).await {
        Ok(listed) => listed,
        Err(failure) => return refuse_request(&product, &failure),
    };
    if listed.is_empty() {
        let body = format!("{HEADING}<p>You allowed no application anything.</p>");
        return render_page(&product, StatusCode::OK, &body);
    }
    // Names, identifiers and scopes were written by whoever registered the
    // client: text on this page, never markup.
    let items = listed.iter().fold(String::new(), |mut items, held| {
        let scopes: Vec<String> = held
            .consent
            .scopes
            .iter()
            .map(|scope| escape_text(scope))
            .collect();
        let _ = write!(
            items,
            "<li><strong>{}</strong>: {}\
             <form method=\"post\" action=\"/realms/{realm}/account/consents/withdraw\">\
             <input type=\"hidden\" name=\"client_id\" value=\"{}\">\
             <button type=\"submit\">Withdraw</button></form></li>",
            escape_text(&held.client_name),
            scopes.join(", "),
            escape_text(&held.consent.client_id),
        );
        items
    });
    let body = format!("{HEADING}<ul>{items}</ul>");
    render_page(&product, StatusCode::OK, &body)
}

#[post("/realms/{realm}/account/consents/withdraw")]
pub async fn withdraw_consent(
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
    let Some(form) = read_posted_form::<WithdrawalForm>(&http, payload).await else {
        return refuse_request(&product, &Failure::new(ErrorCode::RequestInvalid));
    };
    match withdraw_my_consent(&product, &realm, ticket.as_ref(), &form.client_id).await {
        Ok(()) => {
            let body = format!("{HEADING}<p>The application no longer acts in your name.</p>");
            render_page(&product, StatusCode::OK, &body)
        }
        Err(failure) => refuse_request(&product, &failure),
    }
}
