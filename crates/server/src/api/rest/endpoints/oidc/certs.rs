//! The public keys of a realm.

use actix_web::{HttpResponse, get, web};
use saffui_core::app::App as Product;
use saffui_core::keys::jwks::publish_key_set;
use saffui_core::tenancy::resolve::resolve_realm;

use crate::error::render_failure;

#[get("/realms/{realm}/oauth2/jwks")]
pub async fn serve_key_set(product: web::Data<Product>, realm: web::Path<String>) -> HttpResponse {
    let published = async {
        let (_name, scope) = resolve_realm(&product, &realm).await?;
        publish_key_set(&product, scope).await
    }
    .await;
    match published {
        Ok(key_set) => HttpResponse::Ok().json(key_set),
        Err(failure) => render_failure(&failure),
    }
}
