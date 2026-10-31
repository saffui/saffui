//! The discovery document of a realm.

use actix_web::{HttpResponse, get, web};
use saffui_core::app::App as Product;
use saffui_core::oidc::discovery::describe_provider;
use saffui_core::tenancy::resolve::resolve_realm;

use crate::error::render_failure;

#[get("/realms/{realm}/.well-known/openid-configuration")]
pub async fn serve_provider_metadata(
    product: web::Data<Product>,
    realm: web::Path<String>,
) -> HttpResponse {
    match resolve_realm(&product, &realm).await {
        Ok((name, _scope)) => HttpResponse::Ok().json(describe_provider(&product.settings, &name)),
        Err(failure) => render_failure(&failure),
    }
}
