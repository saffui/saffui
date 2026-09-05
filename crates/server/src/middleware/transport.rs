//! The realm's word on plain connections, kept.
//!
//! `ssl_enforcement` has been a column since the first schema, decoded,
//! settable from the console, and read by nothing: an operator could set
//! `all` and every plain request went on being answered. This is the reader.
//!
//! This server never terminates TLS on its HTTP listener, so a request's
//! scheme is a fact only the proxy in front can state, and only a named one
//! is believed: `Proxying::forwarded_scheme` applies the same rule the
//! client-certificate header already lives under. A request the proxy vouches
//! for as `https` passes without a single read. Anything else pays one realm
//! read, which on a deployment that is all https is no request at all.
//!
//! An unresolvable realm passes through untouched and the endpoint answers as
//! it would have, so a disabled realm and an absent one stay the same answer
//! here as everywhere else.

use std::future::{Future, Ready, ready};
use std::net::IpAddr;
use std::pin::Pin;
use std::rc::Rc;

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::http::header::HeaderName;
use actix_web::{Error, HttpResponse, web};
use config::proxying::Proxying;
use deadpool_postgres::Pool;
use models::entities::realm::SslEnforcement;
use store::tenancy::{Tenancy, resolve};

/// Whether this request must be turned away for arriving in the clear.
async fn refused_for_arriving_in_the_clear(request: &ServiceRequest) -> bool {
    let Some(proxying) = request.app_data::<web::Data<Proxying>>() else {
        return false;
    };
    let peer = request.peer_addr().map(|address| address.ip().to_string());

    // The scheme the terminating proxy wrote, believed only from a named peer.
    let vouched = proxying
        .scheme_header()
        .and_then(|named| HeaderName::from_bytes(named.as_bytes()).ok())
        .and_then(|named| request.headers().get(named).cloned());
    let spoken = proxying.forwarded_scheme(
        peer.as_deref(),
        vouched.as_ref().and_then(|value| value.to_str().ok()),
    );
    if spoken.is_some_and(|scheme| scheme.eq_ignore_ascii_case("https")) {
        return false;
    }

    // Plain, or nobody trustworthy said otherwise: the realm decides.
    let realm = request.match_info().get("realm").unwrap_or_default();
    let (Some(pool), Some(tenancy)) = (
        request.app_data::<web::Data<Pool>>(),
        request.app_data::<web::Data<Tenancy>>(),
    ) else {
        return false;
    };
    let Ok(mut connection) = pool.get().await else {
        return false;
    };
    let Ok(context) = resolve::realm_by_name(&connection, realm).await else {
        return false;
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return false;
    };
    let Ok(Some(held)) = store::providers::realms::load(&transaction, &context.realm_id).await
    else {
        return false;
    };
    match held.ssl_enforcement {
        None | Some(SslEnforcement::NotRequired) => false,
        Some(SslEnforcement::Always) => true,
        // For requests that did not come from a private address. The address
        // judged is the one the deployment believes the caller has, counted
        // from the right of what its own proxies wrote.
        Some(SslEnforcement::ExternalOnly) => {
            let carried = proxying
                .header()
                .and_then(|named| HeaderName::from_bytes(named.name().as_bytes()).ok())
                .and_then(|named| request.headers().get(named).cloned());
            let believed = proxying
                .caller(
                    peer.as_deref(),
                    carried.as_ref().and_then(|value| value.to_str().ok()),
                )
                .and_then(|address| address.parse::<IpAddr>().ok());
            !believed.is_some_and(from_a_private_address)
        }
    }
}

/// Loopback, RFC 1918, link-local, and their v6 kin.
///
/// Spelled out rather than leaning on the standard library for the v6 halves,
/// whose helpers are younger than the toolchain floor this builds on.
fn from_a_private_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(held) => held.is_loopback() || held.is_private() || held.is_link_local(),
        IpAddr::V6(held) => {
            held.is_loopback()
                // fc00::/7, unique local.
                || (held.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10, link local.
                || (held.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The refusal, spoken the way the protocol endpoints speak.
fn turned_away() -> HttpResponse {
    HttpResponse::Forbidden().json(serde_json::json!({
        "error": "invalid_request",
        "error_description": "this realm is served over https",
    }))
}

pub struct SecuredTransport;

impl<S, B> Transform<S, ServiceRequest> for SecuredTransport
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = SecuredTransportAnswering<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecuredTransportAnswering {
            service: Rc::new(service),
        }))
    }
}

pub struct SecuredTransportAnswering<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for SecuredTransportAnswering<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        Box::pin(async move {
            if refused_for_arriving_in_the_clear(&request).await {
                let (request, _) = request.into_parts();
                return Ok(ServiceResponse::new(
                    request,
                    turned_away().map_into_right_body(),
                ));
            }
            service
                .call(request)
                .await
                .map(|answered| answered.map_into_left_body())
        })
    }
}
