//! Mounting the admin plane.
//!
//! The routes are registered from the same table the guard reads, so a route
//! that exists and a route that is declared are the same list. A handler
//! registered outside it would be reachable and unguarded, which is why
//! registration walks the table rather than being written twice.

use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::{App, web};
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

/// Everything the plane needs to answer.
#[derive(Clone)]
pub struct Plane {
    pub pool: Pool,
    pub tenancy: Tenancy,
    pub policy: AdminPolicy,
}

/// Mount the probes an orchestrator reads.
///
/// Its own listener, and nothing else on it. Sharing the data plane's port
/// means a probe queues behind real traffic, competes with its rate limiter,
/// and is reachable from wherever that port is: an orchestrator's questions and
/// a caller's are not the same question and do not belong on one door.
pub fn mount_ops<T, B>(app: App<T>, vitals: &Vitals) -> App<T>
where
    T: ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse<B>,
            Error = actix_web::Error,
            InitError = (),
        >,
{
    app.app_data(web::Data::new(vitals.clone()))
        .service(web::resource("/livez").route(web::get().to(health::alive)))
        .service(web::resource("/readyz").route(web::get().to(health::ready)))
        .service(web::resource("/startupz").route(web::get().to(health::started)))
}

/// Mount the admin scope, guarded.
pub fn mount<T, B>(app: App<T>, plane: &Plane) -> App<T>
where
    T: ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse<B>,
            Error = actix_web::Error,
            InitError = (),
        >,
{
    // The admin scope is built from the table, so a route mounted here and a
    // route the guard charges for are the same row. Registered by hand, the two
    // lists agree until somebody adds a handler to one of them.
    let mut admin = web::scope("/admin").wrap(Guard {
        pool: plane.pool.clone(),
        tenancy: plane.tenancy.clone(),
        policy: plane.policy.clone(),
    });
    for route in routes::routes().into_iter().filter(|r| r.handler.is_some()) {
        // The scope prefixes what it mounts, so the table's full pattern has its
        // own prefix taken back off. Keeping the full one in the table is what
        // lets the guard compare it to what actix reports for a request.
        let within = route
            .pattern
            .strip_prefix("/admin")
            .expect("an admin route is under /admin");
        let build = route.handler.expect("filtered to the routes that answer");
        admin = admin.service(web::resource(within).route(build()));
    }

    app.app_data(web::Data::new(plane.pool.clone()))
        .app_data(web::Data::new(plane.tenancy.clone()))
        .app_data(web::Data::new(Journal::new(
            plane.pool.clone(),
            plane.tenancy.clone(),
        )))
        .service(admin)
        // Its own scope, and its own gate. The admin plane demands a capability
        // per route; this demands only that the token stood up.
        .service(
            web::scope("/authz")
                .wrap(Caller {
                    pool: plane.pool.clone(),
                    tenancy: plane.tenancy.clone(),
                })
                .service(web::resource("/decision").route(web::post().to(decision::ask))),
        )
}
