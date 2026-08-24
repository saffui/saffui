use std::future::{Ready, ready};
use std::rc::Rc;

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage, ResponseError};
use deadpool_postgres::Pool;
use store::tenancy::Tenancy;

use config::serving::PublicOrigin;

use crate::middleware::bearer::admitted;

/// Establish a caller, and require nothing of them.
///
/// The enforcement scope's gate. The admin plane's asks for a capability on top;
/// this asks only that the token stood up, because what may be done is the
/// decision point's question and not the transport's.
#[derive(Clone)]
pub struct Caller {
    pub pool: Pool,
    pub tenancy: Tenancy,
    /// See [`crate::middleware::admin_guard::Guard::origin`].
    pub origin: PublicOrigin,
}

impl<S, B> Transform<S, ServiceRequest> for Caller
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = CallerService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CallerService {
            service: Rc::new(service),
            gate: self.clone(),
        }))
    }
}

pub struct CallerService<S> {
    service: Rc<S>,
    gate: Caller,
}

impl<S, B> Service<ServiceRequest> for CallerService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let gate = self.gate.clone();

        Box::pin(async move {
            match admitted(&gate, &request).await {
                Ok(established) => {
                    request.extensions_mut().insert(established);
                    service
                        .call(request)
                        .await
                        .map(ServiceResponse::map_into_left_body)
                }
                Err(error) => {
                    let (request, _) = request.into_parts();
                    Ok(ServiceResponse::new(request, error.error_response()).map_into_right_body())
                }
            }
        })
    }
}
