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
use std::sync::Arc;

use config::serving::{LoginUi, PublicOrigin};
use crypto::envelope::Envelope;
use crypto::provider::CryptoProvider;
use deadpool_postgres::Pool;
use store::tenancy::Tenancy;

use crate::api::rest::endpoints::authz::decision;
use crate::api::rest::endpoints::ops::health;
use crate::api::rest::endpoints::ops::health::Vitals;
use crate::api::rest::endpoints::protocol::{authorize, login, token};
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

/// How much form a caller with nothing to present may send.
///
/// A token request is a grant name, a client id, a secret, a code and at most a
/// client assertion, which is a signed JWT of well under a kilobyte. Anything
/// past this is not a request this endpoint would answer, and reading it is work
/// done for whoever asked.
///
/// Stated rather than left to the framework. The default happens to sit here
/// today, and a default is a value nobody chose: it moves with a dependency
/// bump, and the scope that would inherit the move is the one door reachable
/// with nothing presented.
const PROTOCOL_BODY: usize = 8 * 1024;

/// Everything the planes need to answer.
#[derive(Clone)]
pub struct Plane {
    pub pool: Pool,
    pub tenancy: Tenancy,
    pub policy: AdminPolicy,
    /// Where callers reach this deployment. Every issuer minted and every
    /// issuer accepted is built from it, so both planes hold the same one.
    pub origin: PublicOrigin,
    /// Where a browser is sent to authenticate. Not served here.
    pub login_ui: LoginUi,
    /// What signs. Verification reads published public halves and needs none of
    /// this; minting has to open a private one, which is the envelope's job.
    pub sealing: Sealing,
}

/// What it takes to open a realm's sealed keys.
///
/// One value rather than two fields, because neither half is any use alone and
/// a caller holding one would have to go looking for the other.
///
/// Shared rather than copied. `Envelope` is deliberately not `Clone`: a derived
/// one would duplicate deployment key material every time a worker was built,
/// and there is no reason for a second copy to exist.
#[derive(Clone)]
pub struct Sealing {
    pub provider: Arc<dyn CryptoProvider>,
    pub envelope: Arc<Envelope>,
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
            .app_data(web::Data::new(plane.origin.clone()))
            .app_data(web::Data::new(plane.login_ui.clone()))
            .app_data(web::Data::new(plane.sealing.clone()))
            .service(admin_scope(plane))
            .service(authz_scope(plane))
            .service(protocol_scope());
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
            origin: plane.origin.clone(),
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
            origin: plane.origin.clone(),
        })
        .service(web::resource("/decision").route(web::post().to(decision::ask)))
}

/// The protocol plane: what a client speaks to.
///
/// No gate. Every other door here stands behind one, and this is the door a
/// caller knocks on when it has nothing to present yet, so the checks a gate
/// would have made are the endpoint's own.
///
/// Its own scope rather than a line in the route table: that table strips an
/// `/admin` prefix it expects every entry to carry, and the strip is an
/// `expect`, so an entry mounted anywhere else kills the process at startup
/// rather than at the first request.
///
/// The form ceiling is hung here and not higher. A token request is a handful
/// of short fields, and the only thing a wider ceiling buys is how much an
/// unauthenticated caller may make the server read.
fn protocol_scope() -> impl HttpServiceFactory + 'static {
    web::scope("/realms/{realm}/protocol/openid-connect")
        .app_data(web::FormConfig::default().limit(PROTOCOL_BODY))
        .service(web::resource("/auth").route(web::get().to(authorize::begin)))
        .service(web::resource("/login").route(web::post().to(login::answer)))
        .service(web::resource("/token").route(web::post().to(token::ask)))
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
