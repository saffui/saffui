//! Token revocation: a client gives back a refresh token it holds.

use actix_web::http::header::CACHE_CONTROL;
use actix_web::{HttpRequest, HttpResponse, post, web};
use saffui_core::app::App as Product;
use saffui_core::oidc::revoke::revoke_token;

use super::introspect::TokenQuestion;
use super::token::refuse_unreadable_identity;
use crate::error::render_protocol_failure;
use crate::extract::client_credentials::read_client_identity;

#[post("/realms/{realm}/oauth2/revoke")]
pub async fn revoke(
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
    let revoked = revoke_token(
        &product,
        &realm,
        identity.client_id.as_deref(),
        identity.secret,
        form.token.as_deref(),
    )
    .await;
    match revoked {
        Ok(()) => HttpResponse::Ok()
            .insert_header((CACHE_CONTROL, "no-store"))
            .finish(),
        Err(failure) => render_protocol_failure(&failure, identity.asked_with_basic),
    }
}
