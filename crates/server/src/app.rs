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

use crate::admin::{Caller, Guard};
use crate::enforce;
use crate::guard::AdminPolicy;
use crate::realms;

/// Everything the plane needs to answer.
#[derive(Clone)]
pub struct Plane {
    pub pool: Pool,
    pub tenancy: Tenancy,
    pub policy: AdminPolicy,
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
    app.app_data(web::Data::new(plane.pool.clone()))
        .app_data(web::Data::new(plane.tenancy.clone()))
        .service(
            web::scope("/admin")
                .wrap(Guard {
                    pool: plane.pool.clone(),
                    tenancy: plane.tenancy.clone(),
                    policy: plane.policy.clone(),
                })
                .service(web::resource("/realms").route(web::get().to(realms::list)))
                .service(web::resource("/realms/{realm}").route(web::get().to(realms::get))),
        )
        // Its own scope, and its own gate. The admin plane demands a capability
        // per route; this demands only that the token stood up, because what
        // may be done is what it is here to ask.
        .service(
            web::scope("/authz")
                .wrap(Caller {
                    pool: plane.pool.clone(),
                    tenancy: plane.tenancy.clone(),
                })
                .service(web::resource("/decision").route(web::post().to(enforce::ask))),
        )
}

/// Which patterns are mounted, for the test that compares them to the table.
pub fn mounted() -> Vec<(actix_web::http::Method, &'static str)> {
    vec![
        (actix_web::http::Method::GET, "/admin/realms"),
        (actix_web::http::Method::GET, "/admin/realms/{realm}"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every mounted route is declared. One that is not would be reachable and
    /// refused, which reads as a bug rather than as a closed door, and the
    /// pressure would be to open it rather than to declare it.
    #[test]
    fn every_mounted_route_is_declared() {
        for (method, pattern) in mounted() {
            assert!(
                crate::routes::required(&method, pattern).is_some(),
                "{method} {pattern} is mounted and declares no action"
            );
        }
    }

    /// And the reverse, weaker: a declared route that is not mounted is a
    /// promise nothing keeps. Reported rather than asserted, because the table
    /// deliberately declares what the plane will carry before it carries it.
    #[test]
    fn the_declared_routes_that_are_not_yet_mounted_are_known() {
        let mounted = mounted();
        let missing: Vec<String> = crate::routes::routes()
            .into_iter()
            .filter(|route| {
                !mounted
                    .iter()
                    .any(|(method, pattern)| method == route.method && *pattern == route.pattern)
            })
            .map(|route| format!("{} {}", route.method, route.pattern))
            .collect();

        assert_eq!(
            missing,
            vec![
                "POST /admin/realms".to_owned(),
                "PUT /admin/realms/{realm}".to_owned(),
            ],
            "the set of declared but unmounted routes changed without the test being updated"
        );
    }
}
