//! The probes of the operations plane.

use std::sync::atomic::{AtomicBool, Ordering};

use actix_web::{HttpResponse, get, web};

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

/// Readiness: 200 while serving, 503 from the moment shutdown is requested.
#[get("/readyz")]
pub async fn report_readiness(drain_flag: web::Data<DrainFlag>) -> HttpResponse {
    if drain_flag.is_draining() {
        HttpResponse::ServiceUnavailable().finish()
    } else {
        HttpResponse::Ok().finish()
    }
}
