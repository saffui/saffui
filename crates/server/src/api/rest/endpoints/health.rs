//! The probes of the operations plane.

use std::sync::atomic::{AtomicBool, Ordering};

use actix_web::{HttpResponse, get, web};
use saffui_core::app::App as Product;
use saffui_core::readiness::{Readiness, check_readiness};

/// Raised when shutdown is requested, and never lowered: from then on
/// readiness fails, so that traffic is routed elsewhere.
#[derive(Default)]
pub struct DrainFlag {
    draining: AtomicBool,
}

impl DrainFlag {
    pub fn start_drain(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }

    #[must_use]
    pub(crate) fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }
}

/// Liveness. It reads nothing and waits for nothing: anything it touched
/// could get a healthy process restarted.
#[get("/livez")]
pub async fn report_liveness() -> HttpResponse {
    HttpResponse::Ok().finish()
}

/// Readiness: 200 while this instance can serve. A refusal says why in its
/// body: this plane is the operator's, not the public's.
#[get("/readyz")]
pub async fn report_readiness(
    product: web::Data<Product>,
    drain_flag: web::Data<DrainFlag>,
) -> HttpResponse {
    match check_readiness(&product, drain_flag.is_draining()).await {
        Readiness::Ready => HttpResponse::Ok().finish(),
        Readiness::Draining => HttpResponse::ServiceUnavailable().body("draining\n"),
        Readiness::StorageUnavailable(reason) => {
            HttpResponse::ServiceUnavailable().body(format!("{reason}\n"))
        }
    }
}
