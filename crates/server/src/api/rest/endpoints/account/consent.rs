//! The page on which a signed-in person sees what they allowed clients, and
//! withdraws it.

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use askama::Template;
use saffui_core::app::App as Product;
use saffui_core::consent::ListedConsent;
use saffui_core::consent::manage::{list_my_consents, withdraw_my_consent};
use saffui_core::error::{ErrorCode, Failure};
use serde::Deserialize;

use super::authenticator::read_ticket;
use crate::api::rest::endpoints::login::page::{
    Frame, is_posted_from_elsewhere, is_realm_label, render_page, render_refusal,
};
use crate::extract::form::read_posted_form;

#[derive(Deserialize)]
pub struct WithdrawalForm {
    client_id: String,
}

/// The page of what a person allowed clients.
#[derive(Template)]
#[template(path = "account/consent.html")]
struct ConsentsPage<'a> {
    frame: Frame,
    shown: Shown<'a>,
}

/// What the page shows under its heading.
enum Shown<'a> {
    /// Why the page refuses, and no form.
    Refusal {
        message: &'a str,
    },
    /// No client was allowed anything.
    Nothing,
    /// What each client was allowed, and the form that withdraws it.
    Listed {
        realm: &'a str,
        listed: &'a [ListedConsent],
    },
    Withdrawn,
}

fn render_shown(product: &Product, status: StatusCode, shown: Shown<'_>) -> HttpResponse {
    render_page(product, status, |frame| ConsentsPage { frame, shown })
}

/// A refusal of these pages: a person who is not signed in is told so.
fn refuse_request(product: &Product, failure: &Failure) -> HttpResponse {
    if failure.code == ErrorCode::SessionRequired {
        let message = failure.code.message();
        return render_shown(
            product,
            StatusCode::UNAUTHORIZED,
            Shown::Refusal { message },
        );
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
        return render_shown(&product, StatusCode::OK, Shown::Nothing);
    }
    let shown = Shown::Listed {
        realm: &realm,
        listed: &listed,
    };
    render_shown(&product, StatusCode::OK, shown)
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
        Ok(()) => render_shown(&product, StatusCode::OK, Shown::Withdrawn),
        Err(failure) => refuse_request(&product, &failure),
    }
}

#[cfg(test)]
mod tests {
    use actix_web::http::StatusCode;
    use saffui_core::consent::{Consent, ListedConsent};
    use saffui_core::testkit::memory::MemoryStorage;
    use uuid::Uuid;

    use super::{Shown, render_shown};
    use crate::api::rest::endpoints::login::page::tests::{HOSTILE, assert_written_as_text};

    #[test]
    fn every_text_the_page_of_consents_shows_is_written_as_text() {
        let (product, _storage) = MemoryStorage::wire();
        let listed = [ListedConsent {
            consent: Consent {
                person: Uuid::nil(),
                client_id: HOSTILE.to_owned(),
                scopes: vec![HOSTILE.to_owned(), HOSTILE.to_owned()],
                granted_at: product.now(),
            },
            client_name: HOSTILE.to_owned(),
        }];
        let pages = [
            (Shown::Refusal { message: HOSTILE }, 1),
            (
                Shown::Listed {
                    realm: HOSTILE,
                    listed: &listed,
                },
                5,
            ),
        ];

        for (shown, held) in pages {
            assert_written_as_text(render_shown(&product, StatusCode::OK, shown), held);
        }
    }
}
