//! CORS for the protocol endpoints, answered from what clients registered.
//!
//! A browser page may call the token endpoint, userinfo or revocation from
//! script only if its origin is among some client's `web_origins`; the
//! wildcard `"*"` is a registration like any other. The check is per realm
//! and per request, one existence read, and only when an `Origin` header
//! rode in. No registration, no headers, and the browser enforces the rest.

use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::http::Method;
use actix_web::http::header;
use actix_web::{Error, HttpResponse, web};
use deadpool_postgres::Pool;
use store::tenancy::{Tenancy, resolve};

/// Whether this realm admits the origin, by any of its clients' say.
async fn admitted(request: &ServiceRequest, origin: &str) -> bool {
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
    store::providers::clients::origin_admitted(&transaction, origin)
        .await
        .unwrap_or(false)
}

fn allowed_headers(response: &mut HttpResponse, origin: &str) {
    let set = |response: &mut HttpResponse, name, value: &str| {
        if let Ok(value) = header::HeaderValue::from_str(value) {
            response.headers_mut().insert(name, value);
        }
    };
    set(response, header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    set(response, header::VARY, "Origin");
    set(
        response,
        header::ACCESS_CONTROL_ALLOW_METHODS,
        "GET, POST, OPTIONS",
    );
    set(
        response,
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        "authorization, content-type, dpop",
    );
    set(response, header::ACCESS_CONTROL_MAX_AGE, "3600");
}

/// The wrap for the protocol scope: answer preflights for admitted origins,
/// and wear the allow headers on real answers to them.
pub struct BrowserCalls;

impl<S, B> Transform<S, ServiceRequest> for BrowserCalls
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = BrowserCallsAnswering<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(BrowserCallsAnswering {
            service: Rc::new(service),
        }))
    }
}

pub struct BrowserCallsAnswering<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for BrowserCallsAnswering<S>
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
        Box::pin(answered(request, service))
    }
}

async fn answered<S, B>(
    request: ServiceRequest,
    service: Rc<S>,
) -> Result<ServiceResponse<EitherBody<B>>, Error>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|held| held.to_str().ok())
        .map(str::to_owned);

    let Some(origin) = origin else {
        return service
            .call(request)
            .await
            .map(|answered| answered.map_into_left_body());
    };
    let allowed = admitted(&request, &origin).await;

    if request.method() == Method::OPTIONS {
        // A preflight is the browser's own question; no route answers it, so
        // this does, and only for an origin somebody registered.
        let mut answer = if allowed {
            HttpResponse::NoContent().finish()
        } else {
            HttpResponse::Forbidden().finish()
        };
        if allowed {
            allowed_headers(&mut answer, &origin);
        }
        let (request, _) = request.into_parts();
        return Ok(ServiceResponse::new(request, answer).map_into_right_body());
    }

    let mut answered = service.call(request).await?;
    if allowed {
        let set = |answered: &mut ServiceResponse<B>, name, value: &str| {
            if let Ok(value) = header::HeaderValue::from_str(value) {
                answered.headers_mut().insert(name, value);
            }
        };
        set(&mut answered, header::ACCESS_CONTROL_ALLOW_ORIGIN, &origin);
        set(&mut answered, header::VARY, "Origin");
        set(
            &mut answered,
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            "www-authenticate, dpop-nonce",
        );
    }
    Ok(answered.map_into_left_body())
}
