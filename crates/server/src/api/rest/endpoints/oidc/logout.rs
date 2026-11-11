//! The end-session endpoint of a realm, and the page that asks a person
//! whether they sign out.

use actix_web::http::StatusCode;
use actix_web::http::header::{CACHE_CONTROL, LOCATION, SET_COOKIE};
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use askama::Template;
use saffui_core::app::App as Product;
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::login::session::SessionTicket;
use saffui_core::oidc::logout::{Logout, LogoutParameters, begin_logout, confirm_logout};
use serde::Deserialize;

use crate::api::rest::endpoints::login::page::{
    Frame, is_posted_from_elsewhere, is_realm_label, render_page, render_refusal,
};
use crate::extract::cookies::{is_served_over_tls, name_session_cookie, read_cookie, write_cookie};

#[derive(Deserialize)]
pub struct LogoutQuery {
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
}

/// The page that signs a person out, or asks them first.
#[derive(Template)]
#[template(path = "oidc/logout.html")]
struct LogoutPage<'a> {
    frame: Frame,
    shown: Shown<'a>,
}

enum Shown<'a> {
    SignedOut,
    /// The question, and the form that answers it.
    Confirmation {
        realm: &'a str,
    },
}

/// The `Set-Cookie` that takes the session cookie back from the browser.
/// Nothing is written for a name that is not a realm label.
fn clear_session_cookie(product: &Product, realm: &str) -> Option<String> {
    let secure = is_served_over_tls(product);
    is_realm_label(realm)
        .then(|| write_cookie(&name_session_cookie(realm, secure), "", Some(0), secure))
}

fn read_ticket(product: &Product, realm: &str, http: &HttpRequest) -> Option<SessionTicket> {
    let name = name_session_cookie(realm, is_served_over_tls(product));
    read_cookie(http, &name).and_then(|value| SessionTicket::parse(&value))
}

fn render_signed_out(product: &Product, realm: &str) -> HttpResponse {
    let mut page = render_page(product, StatusCode::OK, |frame| LogoutPage {
        frame,
        shown: Shown::SignedOut,
    });
    if let Some(Ok(cookie)) = clear_session_cookie(product, realm).map(|cookie| cookie.parse()) {
        page.headers_mut().append(SET_COOKIE, cookie);
    }
    page
}

#[get("/realms/{realm}/oauth2/logout")]
pub async fn begin(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
    query: web::Query<LogoutQuery>,
) -> HttpResponse {
    let ticket = read_ticket(&product, &realm, &http);
    let parameters = LogoutParameters {
        id_token_hint: query.id_token_hint.as_deref(),
        post_logout_redirect_uri: query.post_logout_redirect_uri.as_deref(),
        state: query.state.as_deref(),
    };
    match begin_logout(&product, &realm, parameters, ticket.as_ref()).await {
        Ok(Logout::SignedOut {
            location: Some(location),
        }) => {
            let mut response = HttpResponse::SeeOther();
            response
                .insert_header((LOCATION, location))
                .insert_header((CACHE_CONTROL, "no-store"));
            if let Some(cookie) = clear_session_cookie(&product, &realm) {
                response.insert_header((SET_COOKIE, cookie));
            }
            response.finish()
        }
        Ok(Logout::SignedOut { location: None }) => render_signed_out(&product, &realm),
        // Nothing a client sent is written on this page: the form carries no field.
        Ok(Logout::ConfirmationRequired) if is_realm_label(&realm) => {
            render_page(&product, StatusCode::OK, |frame| LogoutPage {
                frame,
                shown: Shown::Confirmation { realm: &realm },
            })
        }
        // A name that is not a realm label resolved to no realm: this is never reached.
        Ok(Logout::ConfirmationRequired) => {
            render_refusal(&product, &Failure::new(ErrorCode::RealmNotFound))
        }
        Err(failure) => render_refusal(&product, &failure),
    }
}

#[post("/realms/{realm}/oauth2/logout")]
pub async fn confirm(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
) -> HttpResponse {
    // The session cookie is withheld from a form another site posts: this
    // refuses such a post by name, before anything is read.
    if is_posted_from_elsewhere(&product, &http) {
        return HttpResponse::Forbidden()
            .insert_header((CACHE_CONTROL, "no-store"))
            .finish();
    }
    let ticket = read_ticket(&product, &realm, &http);
    if let Some(ticket) = ticket
        && let Err(failure) = confirm_logout(&product, &realm, &ticket).await
    {
        return render_refusal(&product, &failure);
    }
    render_signed_out(&product, &realm)
}

#[cfg(test)]
mod tests {
    use actix_web::http::StatusCode;
    use saffui_core::testkit::memory::MemoryStorage;

    use super::{LogoutPage, Shown};
    use crate::api::rest::endpoints::login::page::render_page;
    use crate::api::rest::endpoints::login::page::tests::{HOSTILE, assert_written_as_text};

    #[test]
    fn every_text_the_sign_out_page_shows_is_written_as_text() {
        let (product, _storage) = MemoryStorage::wire();

        let page = render_page(&product, StatusCode::OK, |frame| LogoutPage {
            frame,
            shown: Shown::Confirmation { realm: HOSTILE },
        });

        assert_written_as_text(page, 1);
    }
}
