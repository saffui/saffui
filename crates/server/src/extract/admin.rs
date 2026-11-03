//! Who is calling the administration plane. The guard decided it before the
//! handler ran: a handler reads it here, and gets its realm scope from the
//! guard and from nowhere else.

use std::future::{Ready, ready};
use std::ops::Deref;

use actix_web::dev::Payload;
use actix_web::error::InternalError;
use actix_web::{FromRequest, HttpMessage, HttpRequest};
use saffui_core::authz::admin::AdminCaller;
use saffui_core::error::{ErrorCode, Failure};

use crate::error::render_failure;

/// The caller the guard let through.
pub(crate) struct Caller(AdminCaller);

impl Deref for Caller {
    type Target = AdminCaller;

    fn deref(&self) -> &AdminCaller {
        &self.0
    }
}

impl FromRequest for Caller {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(request: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let caller = request.extensions().get::<AdminCaller>().cloned();
        // A route that declares no capability has no guard, and so no
        // caller: it is refused, never served to whoever asks.
        ready(caller.map(Self).ok_or_else(|| {
            let refusal = render_failure(&Failure::new(ErrorCode::CapabilityMissing));
            InternalError::from_response("no capability is declared", refusal).into()
        }))
    }
}
