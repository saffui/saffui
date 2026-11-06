//! The mounting. Every handler is named here once, by its path under
//! `rest/endpoints/` (`health::report_liveness`), under the plane that serves
//! it. A handler that is not named here answers nowhere, and nothing but
//! `tests/mounted.rs` would say so.

use crate::api::rest::endpoints::health::{self, DrainFlag};
use crate::api::rest::endpoints::{account, admin, authz, login, oidc};
use crate::error::{refuse_unreadable_json, refuse_unreadable_query};
use crate::middleware::security_headers::protect_answers;
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
            // The forms of the plane: their limit and their refusals are the
            // token's. The hosted pages read theirs after their guard.
            .app_data(oidc::token::limit_form())
            .app_data(
                web::JsonConfig::default()
                    .limit(JSON_BODY_LIMIT)
                    .error_handler(refuse_unreadable_json),
            )
            .app_data(web::QueryConfig::default().error_handler(refuse_unreadable_query))
            .service(
                // An empty prefix: the scope is there for what it wraps, not
                // for a path. Its headers go on every answer, a refusal and
                // an unknown path included.
                web::scope("")
                    .wrap(protect_answers(&product))
                    .service(oidc::discovery::serve_provider_metadata)
                    .service(oidc::certs::serve_key_set)
                    .service(oidc::token::grant)
                    .service(oidc::userinfo::read)
                    .service(oidc::introspect::describe_token)
                    .service(oidc::revoke::take_back_token)
                    .service(oidc::logout::begin)
                    .service(oidc::logout::confirm)
                    .service(oidc::authorize::begin)
                    .service(authz::decide::ask_decision)
                    .service(login::page::show_sign_in)
                    .service(login::page::submit_sign_in)
                    .service(account::authenticator::show_authenticator)
                    .service(account::authenticator::begin_enrollment)
                    .service(account::authenticator::confirm_enrollment)
                    .service(account::security_key::show_security_keys)
                    .service(account::security_key::begin_enrollment)
                    .service(account::security_key::finish_enrollment)
                    .service(admin::realm::read_realm)
                    .service(admin::client::list_clients)
                    .service(admin::client::create_client)
                    .service(admin::client::read_client)
                    .service(admin::user::list_users)
                    .service(admin::user::create_user)
                    .service(admin::user::unlock_user)
                    .service(admin::user::remove_authenticator)
                    .service(admin::user::resume_person_codes)
                    .service(admin::user::remove_keys)
                    .service(admin::role::list_roles)
                    .service(admin::role::create_role)
                    .service(admin::role::delete_role)
                    .service(admin::group::list_groups)
                    .service(admin::group::create_group)
                    .service(admin::group::delete_group)
                    .service(admin::group::grant_group_role)
                    .service(admin::group::revoke_group_role)
                    .service(admin::group::add_group_member)
                    .service(admin::group::remove_group_member)
                    .service(admin::user::list_user_roles)
                    .service(admin::user::grant_user_role)
                    .service(admin::user::revoke_user_role)
                    .service(admin::relation::read_schema)
                    .service(admin::relation::write_schema)
                    .service(admin::relation::list_relations)
                    .service(admin::relation::write_relation)
                    .service(admin::relation::delete_relation)
                    .service(admin::relation::list_guards)
                    .service(admin::relation::write_guard)
                    .service(admin::relation::delete_guard)
                    .service(admin::policy::list_policies)
                    .service(admin::policy::create_policy)
                    .service(admin::policy::delete_policy)
                    .service(admin::audit::verify_audit_chain),
            );
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
