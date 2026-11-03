//! The mounting. Every handler is named here once, by its path under
//! `rest/endpoints/` (`health::report_liveness`), under the plane that serves
//! it. A handler that is not named here answers nowhere, and nothing but
//! `tests/mounted.rs` would say so.

use crate::api::rest::endpoints::health::{self, DrainFlag};
use crate::api::rest::endpoints::{admin, oidc};
use crate::error::{refuse_unreadable_json, refuse_unreadable_query};
use actix_web::web;
use saffui_core::app::App as Product;

/// The largest JSON body the data plane reads, in bytes: written here, not
/// inherited, since the plane is reached before anyone is authenticated.
const JSON_BODY_LIMIT: usize = 64 * 1024;

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
            .app_data(
                web::JsonConfig::default()
                    .limit(JSON_BODY_LIMIT)
                    .error_handler(refuse_unreadable_json),
            )
            .app_data(web::QueryConfig::default().error_handler(refuse_unreadable_query))
            .service(oidc::discovery::serve_provider_metadata)
            .service(oidc::certs::serve_key_set)
            .service(oidc::token::grant)
            .service(admin::realm::read_realm)
            .service(admin::client::list_clients)
            .service(admin::client::create_client)
            .service(admin::client::read_client)
            .service(admin::user::list_users)
            .service(admin::user::create_user)
            .service(admin::audit::verify_audit_chain);
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
