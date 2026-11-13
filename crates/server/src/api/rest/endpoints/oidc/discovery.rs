//! The discovery document of a realm.

use actix_web::{HttpResponse, get, web};
use saffui_core::app::App as Product;
use saffui_core::oidc::discovery::read_provider_metadata;

use crate::error::render_failure;

#[get("/realms/{realm}/.well-known/openid-configuration")]
pub async fn serve_provider_metadata(
    product: web::Data<Product>,
    realm: web::Path<String>,
) -> HttpResponse {
    match read_provider_metadata(&product, &realm).await {
        Ok(document) => HttpResponse::Ok().json(document),
        Err(failure) => render_failure(&failure),
    }
}
