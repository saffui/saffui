//! The consent page of a pending authorization request, and its answer.

use actix_web::http::StatusCode;
use actix_web::http::header::{CACHE_CONTROL, LOCATION, SET_COOKIE};
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use askama::Template;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use saffui_core::app::App as Product;
use saffui_core::consent::answer::{
    ConsentDecision, ConsentPrompt, answer_consent, describe_consent,
};
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::secret::Secret;
use serde::Deserialize;
use uuid::Uuid;

use super::page::{Frame, is_posted_from_elsewhere, is_realm_label, render_page, render_refusal};
use crate::api::rest::endpoints::account::authenticator::read_ticket;
use crate::extract::cookies::{is_served_over_tls, name_flow_cookie, read_cookie, write_cookie};
use crate::extract::form::read_posted_form;

#[derive(Deserialize)]
pub struct ConsentQuery {
    request: Option<String>,
}

#[derive(Deserialize)]
pub struct ConsentForm {
    request: String,
    decision: String,
}

/// The question a person answers for a client: who asks, and for what.
#[derive(Template)]
#[template(path = "login/consent.html")]
struct ConsentPage<'a> {
    frame: Frame,
    realm: &'a str,
    request: Uuid,
    prompt: &'a ConsentPrompt,
}

fn expire(product: &Product) -> HttpResponse {
    render_refusal(
        product,
        &Failure::new(ErrorCode::AuthorizationRequestExpired),
    )
}

/// The secret of the flow this browser started, from its cookie.
fn read_browser_secret(product: &Product, http: &HttpRequest, request: Uuid) -> Option<Secret> {
    read_cookie(
        http,
        &name_flow_cookie(request, is_served_over_tls(product)),
    )
    .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
    .map(Secret::new)
}

#[get("/realms/{realm}/consent")]
pub async fn show_consent(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
    query: web::Query<ConsentQuery>,
) -> HttpResponse {
    let Some(request) = query
        .request
        .as_deref()
        .and_then(|text| Uuid::parse_str(text).ok())
        .filter(|_| is_realm_label(&realm))
    else {
        return expire(&product);
    };
    let Some(browser_secret) = read_browser_secret(&product, &http, request) else {
        return expire(&product);
    };
    let ticket = read_ticket(&product, &realm, &http);
    let prompt =
        match describe_consent(&product, &realm, request, &browser_secret, ticket.as_ref()).await {
            Ok(prompt) => prompt,
            Err(failure) => return render_refusal(&product, &failure),
        };
    render_page(&product, StatusCode::OK, |frame| ConsentPage {
        frame,
        realm: &realm,
        request,
        prompt: &prompt,
    })
}

#[post("/realms/{realm}/consent")]
pub async fn submit_consent(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    // The cookies are withheld from a form another site posts: this refuses
    // such a post by name, before its form is read.
    if is_posted_from_elsewhere(&product, &http) || !is_realm_label(&realm) {
        return expire(&product);
    }
    let Some(form) = read_posted_form::<ConsentForm>(&http, payload).await else {
        return render_refusal(&product, &Failure::new(ErrorCode::RequestInvalid));
    };
    let decision = match form.decision.as_str() {
        "allow" => ConsentDecision::Allow,
        "deny" => ConsentDecision::Deny,
        _ => return expire(&product),
    };
    let Ok(request) = Uuid::parse_str(&form.request) else {
        return expire(&product);
    };
    let Some(browser_secret) = read_browser_secret(&product, &http, request) else {
        return expire(&product);
    };
    let ticket = read_ticket(&product, &realm, &http);
    match answer_consent(
        &product,
        &realm,
        request,
        &browser_secret,
        ticket.as_ref(),
        decision,
    )
    .await
    {
        Ok(location) => {
            let secure = is_served_over_tls(&product);
            HttpResponse::SeeOther()
                .insert_header((LOCATION, location))
                .insert_header((CACHE_CONTROL, "no-store"))
                // The flow is over: its cookie goes with it.
                .insert_header((
                    SET_COOKIE,
                    write_cookie(&name_flow_cookie(request, secure), "", Some(0), secure),
                ))
                .finish()
        }
        Err(failure) => render_refusal(&product, &failure),
    }
}

#[cfg(test)]
mod tests {
    use actix_web::http::StatusCode;
    use saffui_core::consent::answer::ConsentPrompt;
    use saffui_core::login::session::OFFLINE_SESSION_LIFETIME;
    use saffui_core::testkit::memory::MemoryStorage;
    use uuid::Uuid;

    use super::ConsentPage;
    use crate::api::rest::endpoints::login::page::render_page;
    use crate::api::rest::endpoints::login::page::tests::{HOSTILE, assert_written_as_text};

    #[test]
    fn every_text_the_consent_page_shows_is_written_as_text() {
        let (product, _storage) = MemoryStorage::wire();
        let prompt = ConsentPrompt {
            client_name: HOSTILE.to_owned(),
            scopes: vec![HOSTILE.to_owned(), HOSTILE.to_owned()],
            offline_access: Some(OFFLINE_SESSION_LIFETIME),
        };

        let page = render_page(&product, StatusCode::OK, |frame| ConsentPage {
            frame,
            realm: HOSTILE,
            request: Uuid::nil(),
            prompt: &prompt,
        });

        assert_written_as_text(page, 4);
    }
}
