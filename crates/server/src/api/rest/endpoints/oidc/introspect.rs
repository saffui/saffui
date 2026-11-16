//! Token introspection: what a client asks about a token it holds.

use actix_web::http::header::{CACHE_CONTROL, PRAGMA};
use actix_web::{HttpRequest, HttpResponse, post, web};
use saffui_core::app::App as Product;
use saffui_core::clients::authenticate::PresentedProof;
use saffui_core::oidc::introspect::introspect_token;
use serde::Deserialize;

use super::token::refuse_unreadable_identity;
use crate::error::render_protocol_failure;
use crate::extract::client_credentials::read_client_identity;

// No `Debug`: the form carries a secret or an assertion, and a token.
#[derive(Deserialize)]
pub struct TokenQuestion {
    pub(super) token: Option<String>,
    pub(super) client_id: Option<String>,
    pub(super) client_secret: Option<String>,
    pub(super) client_assertion_type: Option<String>,
    pub(super) client_assertion: Option<String>,
}

#[post("/realms/{realm}/oauth2/introspect")]
pub async fn describe_token(
    product: web::Data<Product>,
    realm: web::Path<String>,
    request: HttpRequest,
    form: web::Form<TokenQuestion>,
) -> HttpResponse {
    let form = form.into_inner();
    let identity = match read_client_identity(&request, form.client_id, form.client_secret) {
        Ok(identity) => identity,
        Err(unreadable) => return refuse_unreadable_identity(&unreadable),
    };
    let told = introspect_token(
        &product,
        &realm,
        identity.client_id.as_deref(),
        PresentedProof {
            secret: identity.secret,
            assertion_type: form.client_assertion_type.as_deref(),
            assertion: form.client_assertion.as_deref(),
        },
        form.token.as_deref(),
    )
    .await;
    match told {
        Ok(introspection) => HttpResponse::Ok()
            .insert_header((CACHE_CONTROL, "no-store"))
            .insert_header((PRAGMA, "no-cache"))
            .json(introspection),
        Err(failure) => render_protocol_failure(&failure, identity.asked_with_basic),
    }
}
