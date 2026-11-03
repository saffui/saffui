//! The mounting. Every handler is named here once, by its path under
//! `rest/endpoints/` (`health::report_liveness`), under the plane that serves
//! it. A handler that is not named here answers nowhere, and nothing but
//! `tests/mounted.rs` would say so.

use crate::api::rest::endpoints::health::{self, DrainFlag};
use crate::api::rest::endpoints::oidc;
use actix_web::web;
use saffui_core::app::App as Product;

/// Mounts the data plane. The probe paths are not on it: a probe is never
/// reachable from where traffic is.
pub fn register_data_plane(
    product: web::Data<Product>,
) -> impl Fn(&mut web::ServiceConfig) + Clone + Send + 'static {
    move |config| {
        config
            .app_data(product.clone())
            // The only form of the plane: its limit and its refusals are the token's.
            .app_data(oidc::token::limit_form())
            .service(oidc::discovery::serve_provider_metadata)
            .service(oidc::certs::serve_key_set)
            .service(oidc::token::grant);
    }
}

/// Mounts the operations plane, which is served from a listener of its own.
pub fn register_ops_plane(
    product: web::Data<Product>,
    drain_flag: web::Data<DrainFlag>,
) -> impl FnOnce(&mut web::ServiceConfig) {
    move |config| {
        config
            .app_data(product)
            .app_data(drain_flag)
            .service(health::report_liveness)
            .service(health::report_readiness);
    }
}
