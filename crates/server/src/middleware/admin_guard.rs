//! The guard of the administration plane. It does three things, in this
//! order: it authenticates the caller, confines it to the realm of the
//! path, and checks the capability the route requires. All of it happens
//! before the handler is called, so before anything of the body is read.
//!
//! A route says what it requires in its own macro, beside its verb and its
//! path: `wrap = "RequireCapability(Capability::RealmRead)"`.

use std::future::{Ready, ready};
use std::rc::Rc;

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::{HttpMessage, web};
use futures_util::future::LocalBoxFuture;
use saffui_core::app::App as Product;
use saffui_core::authz::admin::authorize_admin_call;
use saffui_core::authz::capability::Capability;
use saffui_core::error::{ErrorCode, Failure};

use crate::error::render_failure;
use crate::extract::bearer::read_bearer_token;

/// What a route of the administration plane requires of its caller.
pub(crate) struct RequireCapability(pub(crate) Capability);

impl<S, B> Transform<S, ServiceRequest> for RequireCapability
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Transform = AdminGuard<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AdminGuard {
            service: Rc::new(service),
            required: self.0,
        }))
    }
}

pub(crate) struct AdminGuard<S> {
    service: Rc<S>,
    required: Capability,
}

impl<S, B> Service<ServiceRequest> for AdminGuard<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let required = self.required;
        Box::pin(async move {
            let product = request.app_data::<web::Data<Product>>().cloned();
            let realm = request.match_info().get("realm").map(str::to_owned);
            let token = read_bearer_token(request.request());
            let decided = match (product, realm) {
                (Some(product), Some(realm)) => {
                    authorize_admin_call(&product, &realm, token.as_deref(), required).await
                }
                // A route of this plane that names no realm is a fault of the mounting.
                _ => Err(Failure::with_detail(
                    ErrorCode::Internal,
                    "an administration route without a realm or without the application",
                )),
            };
            match decided {
                Ok(caller) => {
                    // The handler reads who is calling from here and from nowhere else.
                    request.extensions_mut().insert(caller);
                    service
                        .call(request)
                        .await
                        .map(ServiceResponse::map_into_left_body)
                }
                // The handler is never called: nothing of the body is read.
                Err(failure) => Ok(request
                    .into_response(render_failure(&failure))
                    .map_into_right_body()),
            }
        })
    }
}
