//! The mounting. Every handler is named here once, by its path under
//! `rest/endpoints/` (`health::report_liveness`), under the plane that serves
//! it. A handler that is not named here answers nowhere, and nothing but
//! `tests/mounted.rs` would say so.

use actix_web::web;

use crate::api::rest::endpoints::health::{self, DrainFlag};

/// Mounts the data plane. It has no route yet, so every path answers 404, the
/// probe paths included: a probe is never reachable from where traffic is.
pub fn register_data_plane(_config: &mut web::ServiceConfig) {}

/// Mounts the operations plane, which is served from a listener of its own.
pub fn register_ops_plane(
    drain_flag: web::Data<DrainFlag>,
) -> impl FnOnce(&mut web::ServiceConfig) {
    move |config| {
        config
            .app_data(drain_flag)
            .service(health::report_liveness)
            .service(health::report_readiness);
    }
}
