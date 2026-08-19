//! Where every route is registered.
//!
//! Two functions, because there are two listeners: what a caller reaches and
//! what an orchestrator asks. Both take a `ServiceConfig` rather than returning
//! an `App`, so a binary and a test compose them the same way and neither can
//! assemble a different server than the other.
//!
//! The admin plane is registered from the same table its guard reads. A handler
//! registered outside that table would be reachable and charged for nothing,
//! which is why registration walks it rather than being written twice.

use actix_web::dev::HttpServiceFactory;
use actix_web::web;
use deadpool_postgres::Pool;
use store::tenancy::Tenancy;

use crate::api::rest::endpoints::authz::decision;
use crate::api::rest::endpoints::ops::health;
use crate::api::rest::endpoints::ops::health::Vitals;
use crate::api::routes;
use crate::middleware::admin_guard::Guard;
use crate::middleware::admin_policy::AdminPolicy;
use crate::middleware::caller::Caller;
use services::pdp::Journal;

/// How much JSON an authenticated caller may send.
///
/// Raised for the admin plane and nowhere else. Hung on an enclosing scope it
/// would govern every extractor beneath it, so a realm import's ceiling would
/// become the ceiling of anything reachable before authentication.
const ADMIN_BODY: usize = 8 * 1024 * 1024;

/// Everything the planes need to answer.
#[derive(Clone)]
pub struct Plane {
    pub pool: Pool,
    pub tenancy: Tenancy,
    pub policy: AdminPolicy,
}

/// Register what a caller reaches.
pub fn register(plane: &Plane) -> impl FnOnce(&mut web::ServiceConfig) + Clone + '_ {
    move |config: &mut web::ServiceConfig| {
        config
            .app_data(web::Data::new(plane.pool.clone()))
            .app_data(web::Data::new(plane.tenancy.clone()))
            .app_data(web::Data::new(Journal::new(
                plane.pool.clone(),
                plane.tenancy.clone(),
            )))
            .service(admin_scope(plane))
            .service(authz_scope(plane));
    }
}

/// The administrative plane: a capability per route, from the table.
///
/// A scope rather than a registrar, because it is assembled before it is
/// registered: the table is walked to build it, and a half built scope is not
/// something to hand a `ServiceConfig`.
fn admin_scope(plane: &Plane) -> impl HttpServiceFactory + 'static {
    let mut scope = web::scope("/admin")
        // The raised ceiling stops here, at the authenticated boundary.
        .app_data(web::JsonConfig::default().limit(ADMIN_BODY))
        .wrap(Guard {
            pool: plane.pool.clone(),
            tenancy: plane.tenancy.clone(),
            policy: plane.policy.clone(),
        });

    for route in routes::routes() {
        let Some(build) = route.handler else {
            // Declared, and nothing answers it yet. The cost is settled first,
            // so a handler arriving later cannot arrive without one.
            continue;
        };
        // The scope prefixes what it mounts, so the table's full pattern has its
        // own prefix taken back off. The table keeps the full one because that
        // is what the guard compares against what actix reports for a request.
        let within = route
            .pattern
            .strip_prefix("/admin")
            .expect("an admin route is declared under /admin");
        scope = scope.service(web::resource(within).route(build()));
    }
    scope
}

/// The point of application: only that the token stood up.
///
/// What may be done is the question being asked here, so the transport does not
/// settle it first.
fn authz_scope(plane: &Plane) -> impl HttpServiceFactory + 'static {
    web::scope("/authz")
        .wrap(Caller {
            pool: plane.pool.clone(),
            tenancy: plane.tenancy.clone(),
        })
        .service(web::resource("/decision").route(web::post().to(decision::ask)))
}

/// Register what an orchestrator asks.
///
/// Its own listener, and nothing else on it. Sharing the data plane's port puts
/// a probe behind that plane's traffic and its limits, and makes it reachable
/// from wherever that port is.
pub fn register_ops(vitals: &Vitals) -> impl FnOnce(&mut web::ServiceConfig) + Clone + '_ {
    move |config: &mut web::ServiceConfig| {
        config
            .app_data(web::Data::new(vitals.clone()))
            .service(web::resource("/livez").route(web::get().to(health::alive)))
            .service(web::resource("/readyz").route(web::get().to(health::ready)))
            .service(web::resource("/startupz").route(web::get().to(health::started)));
    }
}
