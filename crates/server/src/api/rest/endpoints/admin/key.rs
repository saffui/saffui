//! The signing keys of a realm, turned over by an administrator.

use actix_web::{HttpResponse, delete, get, post, web};
use api::{KeyView, NewKey};
use saffui_core::app::App as Product;
use saffui_core::authz::capability::Capability;
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::keys::rotate::{list_realm_keys, remove_retired_key, rotate_signing_key};
use saffui_core::ports::crypto::SignatureAlgorithm;

use super::views::show_key;
use crate::error::render_failure;
use crate::extract::admin::Caller;
use crate::middleware::admin_guard::RequireCapability;

#[get(
    "/admin/v1/realms/{realm}/keys",
    wrap = "RequireCapability(Capability::KeyRead)"
)]
pub async fn list_keys(caller: Caller, product: web::Data<Product>) -> HttpResponse {
    match list_realm_keys(&product, caller.scope).await {
        Ok(keys) => {
            let items: Vec<KeyView> = keys.iter().map(show_key).collect();
            HttpResponse::Ok().json(serde_json::json!({ "items": items }))
        }
        Err(failure) => render_failure(&failure),
    }
}

#[post(
    "/admin/v1/realms/{realm}/keys",
    wrap = "RequireCapability(Capability::KeyWrite)"
)]
pub async fn rotate_key(
    caller: Caller,
    product: web::Data<Product>,
    wanted: web::Json<NewKey>,
) -> HttpResponse {
    let Some(algorithm) = SignatureAlgorithm::parse(&wanted.alg) else {
        return render_failure(&Failure::new(ErrorCode::AlgorithmUnknown));
    };
    match rotate_signing_key(&product, &caller, algorithm).await {
        Ok(key) => HttpResponse::Created().json(show_key(&key)),
        Err(failure) => render_failure(&failure),
    }
}

#[delete(
    "/admin/v1/realms/{realm}/keys/{kid}",
    wrap = "RequireCapability(Capability::KeyWrite)"
)]
pub async fn remove_key(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, key_id) = path.into_inner();
    match remove_retired_key(&product, &caller, &key_id).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}
