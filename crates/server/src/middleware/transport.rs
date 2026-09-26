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
//! here as everywhere else. A rule the database fails to hand over is answered
//! 503, not taken as leave to serve in the clear.
//!
//! The doors behind the admin guard and the decision door are judged by their
//! guards instead, by the realm that minted the caller's token once it has
//! verified: the only realm they can act in, which the admin plane names where
//! this middleware cannot read it and the decision door does not name at all.

use std::future::{Future, Ready, ready};
use std::net::IpAddr;
use std::pin::Pin;
use std::rc::Rc;
use store::error::StoreError;
use store::tenancy::{RealmNamed, Tenancy, UnitOfWork};

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::http::header::HeaderName;
use actix_web::{Error, HttpResponse, web};
use config::proxying::Proxying;
use models::entities::realm::{RealmModel, SslEnforcement};

use crate::api::rest::endpoints::protocol::dto::answer_unavailable;

/// The answer this request gets instead of being served, when it must not be.
async fn turn_away_arriving_in_the_clear(request: &ServiceRequest) -> Option<HttpResponse> {
    let proxying = request.app_data::<web::Data<Proxying>>()?;
    if vouched_https(request, proxying) {
        return None;
    }

    // Plain, or nobody trustworthy said otherwise: the realm decides.
    let realm = request.match_info().get("realm").unwrap_or_default();
    let tenancy = request.app_data::<web::Data<Tenancy>>()?;
    let transaction = match tenancy.begin_in(RealmNamed::ByName(realm)).await {
        Ok(transaction) => transaction,
        Err(StoreError::Unavailable | StoreError::Backend) => return Some(answer_unavailable()),
        Err(_) => return None,
    };
    let held = match services::realm::named(&transaction, &transaction.context().realm_id).await {
        Ok(Some(held)) => held,
        Ok(None) => return None,
        Err(_) => return Some(answer_unavailable()),
    };
    refuses_the_clear(&held, request, proxying).then(turned_away)
}

/// Whether the realm that minted a caller's token turns this request away in
/// the clear, for the doors whose realm is the token's rather than the path's.
///
/// Asked once the token has verified, so the realm whose rule is read is one
/// the token proves rather than one it merely names.
pub(crate) async fn token_realm_refuses_the_clear(
    request: &ServiceRequest,
    transaction: &UnitOfWork,
) -> Result<bool, services::realm::Unreadable> {
    let Some(proxying) = request.app_data::<web::Data<Proxying>>() else {
        return Ok(false);
    };
    if vouched_https(request, proxying) {
        return Ok(false);
    }
    let held = services::realm::named(transaction, &transaction.context().realm_id).await?;
    Ok(held.is_some_and(|held| refuses_the_clear(&held, request, proxying)))
}

/// Whether the terminating proxy this deployment names said `https`: the only
/// word on the scheme believed, from a named peer and no one else.
fn vouched_https(request: &ServiceRequest, proxying: &Proxying) -> bool {
    let peer = request.peer_addr().map(|address| address.ip().to_string());
    let vouched = proxying
        .scheme_header()
        .and_then(|named| HeaderName::from_bytes(named.as_bytes()).ok())
        .and_then(|named| request.headers().get(named).cloned());
    proxying
        .forwarded_scheme(
            peer.as_deref(),
            vouched.as_ref().and_then(|value| value.to_str().ok()),
        )
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
}

/// Whether a realm's word turns away a request nobody vouched for as https.
fn refuses_the_clear(held: &RealmModel, request: &ServiceRequest, proxying: &Proxying) -> bool {
    match held.ssl_enforcement {
        None | Some(SslEnforcement::NotRequired) => false,
        Some(SslEnforcement::Always) => true,
        // For requests that did not come from a private address. The address
        // judged is the one the deployment believes the caller has, counted
        // from the right of what its own proxies wrote.
        Some(SslEnforcement::ExternalOnly) => {
            let peer = request.peer_addr().map(|address| address.ip().to_string());
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
            if let Some(answer) = turn_away_arriving_in_the_clear(&request).await {
                let (request, _) = request.into_parts();
                return Ok(ServiceResponse::new(request, answer.map_into_right_body()));
            }
            service
                .call(request)
                .await
                .map(|answered| answered.map_into_left_body())
        })
    }
}
