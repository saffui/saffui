use actix_web::{HttpResponse, get, web};
use saffui_core::app::App as Product;
use saffui_core::authz::capability::Capability;
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::oidc::discovery::name_issuer;

use super::views::show_realm;
use crate::error::render_failure;
use crate::extract::admin::Caller;
use crate::middleware::admin_guard::RequireCapability;

#[get(
    "/admin/v1/realms/{realm}",
    wrap = "RequireCapability(Capability::RealmRead)"
)]
pub async fn read_realm(caller: Caller, product: web::Data<Product>) -> HttpResponse {
    let read = async {
        let mut work = product.storage.begin(caller.scope).await?;
        work.read_realm()
            .await?
            .ok_or_else(|| Failure::new(ErrorCode::RealmNotFound))
    }
    .await;
    match read {
        Ok(realm) => {
            let issuer = name_issuer(&product.settings, &realm.name);
            HttpResponse::Ok().json(show_realm(&realm, issuer))
        }
        Err(failure) => render_failure(&failure),
    }
}
