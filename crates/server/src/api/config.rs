use actix_web::body::MessageBody;
use actix_web::dev::{HttpServiceFactory, ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::{App, Error, Route, web};
use commons::observability::{SaffuiRootSpan, WithRequestId};
use std::sync::Arc;
use tracing_actix_web::TracingLogger;

use config::proxying::Proxying;
use config::serving::{LoginUi, PublicOrigin};
use crypto::envelope::Envelope;
use crypto::provider::CryptoProvider;
use deadpool_postgres::Pool;
use store::tenancy::Tenancy;

use crate::api::rest::endpoints::authz::decision;
use crate::api::rest::endpoints::ops::health;
use crate::api::rest::endpoints::ops::health::Vitals;
use crate::api::rest::endpoints::protocol::{
    authorize, discovery, introspect, keys, login, logout, page, par, registration, revoke, token,
    userinfo,
};
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
    /// Where this deployment will dial when a client asks it to fetch.
    pub egress: config::serving::Egress,
    /// Where a browser is sent to authenticate. Not served here.
    pub login_ui: LoginUi,
    /// How many proxies stand in front, which is what makes a forwarded
    /// address readable rather than a value the caller chose.
    pub hops: Proxying,
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
    /// What carries a message out, when this deployment has said how. Absent
    /// refuses to send rather than choosing a way nobody asked for.
    pub sender: Option<std::sync::Arc<dyn services::messaging::Deliver>>,
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
            .app_data(web::Data::new(plane.hops.clone()))
            .app_data(web::Data::new(plane.egress))
            .app_data(web::Data::new(plane.login_ui.clone()))
            .app_data(web::Data::new(plane.sealing.clone()))
            .service(admin_scope(plane))
            .service(authz_scope(plane))
            .service(protocol_scope())
            // Not under the protocol scope. RFC 8414 §3 fixes this path at the
            // issuer's root, and a client builds it from the issuer rather than
            // from anything this server tells it.
            .service(
                web::resource("/realms/{realm}/.well-known/openid-configuration")
                    .route(web::get().to(discovery::published)),
            )
            // The same document at the name RFC 8414 §3.1 gives it: the
            // well-known segment goes after the host and the issuer's path
            // after that, so a client that reads OAuth metadata and one that
            // reads OpenID metadata both find this realm.
            .service(
                web::resource("/.well-known/oauth-authorization-server/realms/{realm}")
                    .route(web::get().to(discovery::published)),
            );
    }
}

/// An application that is watched: every request gets an id and a span, and
/// every record a handler makes lands under that span.
///
/// Built here so a binary and a test mount the same two middlewares in the
/// same order. The id is outermost, because it has to exist before the span
/// opens and has to reach the response after the span closes.
pub fn observed() -> App<
    impl ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse<impl MessageBody>,
        Error = Error,
        InitError = (),
    >,
> {
    App::new()
        .wrap(TracingLogger::<SaffuiRootSpan>::new())
        .wrap(WithRequestId)
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

    // One resource per path, carrying every verb the table declares for it:
    // two resources on one path would have the second shadow the first, and
    // every verb of the first answer 405.
    let mut by_path: Vec<(&'static str, Vec<Route>)> = Vec::new();
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
        match by_path.iter_mut().find(|(path, _)| *path == within) {
            Some((_, verbs)) => verbs.push(build()),
            None => by_path.push((within, vec![build()])),
        }
    }
    for (path, verbs) in by_path {
        let mut resource = web::resource(path);
        for verb in verbs {
            resource = resource.route(verb);
        }
        scope = scope.service(resource);
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
        .service(
            web::resource("/auth")
                .route(web::get().to(authorize::begin))
                .route(web::post().to(authorize::begin_posted)),
        )
        // One URL, two verbs: a browser is sent here to be shown the page, and
        // the page posts its answers back to where it came from.
        .service(
            web::resource("/login")
                .route(web::get().to(page::magic_link))
                .route(web::post().to(login::answer)),
        )
        .service(web::resource("/login.js").route(web::get().to(page::script)))
        .service(web::resource("/check-session").route(web::get().to(page::check_session)))
        .service(
            web::resource("/check-session.js").route(web::get().to(page::check_session_script)),
        )
        .service(web::resource("/form-post.js").route(web::get().to(page::form_post_script)))
        .service(web::resource("/login.css").route(web::get().to(page::style)))
        .service(web::resource("/token").route(web::post().to(token::ask)))
        .service(web::resource("/par").route(web::post().to(par::keep)))
        .service(
            web::resource("/register")
                .app_data(web::JsonConfig::default().limit(PROTOCOL_BODY))
                .route(web::post().to(registration::create)),
        )
        .service(
            web::resource("/register/{client}")
                .app_data(web::JsonConfig::default().limit(PROTOCOL_BODY))
                .route(web::get().to(registration::read))
                .route(web::put().to(registration::replace))
                .route(web::delete().to(registration::withdraw)),
        )
        .service(web::resource("/introspect").route(web::post().to(introspect::tell)))
        .service(web::resource("/revoke").route(web::post().to(revoke::take_back)))
        .service(web::resource("/certs").route(web::get().to(keys::published)))
        .service(
            web::resource("/logout")
                .route(web::get().to(logout::end))
                .route(web::post().to(logout::end_posted)),
        )
        .service(
            web::resource("/userinfo")
                .route(web::get().to(userinfo::tell))
                .route(web::post().to(userinfo::tell)),
        )
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
