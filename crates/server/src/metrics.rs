//! Request metrics, in the Prometheus text form.
//!
//! Three RED families over every request and one counter over login
//! outcomes, and nothing labelled by realm or tenant: those are unbounded,
//! and an unbounded label set is how a metrics endpoint takes its scraper
//! down. The route label is the matched template, never the raw path, for
//! the same reason.

use commons::feature::Feature;

/// Whether this build carries the machinery. Only this crate sees its own
/// cfg; the boot-time resolver asks each crate about what it compiles.
pub fn compiled(feature: Feature) -> bool {
    matches!(feature, Feature::Metrics) && cfg!(feature = "metrics")
}

#[cfg(feature = "metrics")]
mod measured {
    use std::future::{Future, Ready, ready};
    use std::pin::Pin;
    use std::rc::Rc;
    use std::sync::LazyLock;
    use std::time::Instant;

    use actix_web::Error;
    use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
    use prometheus::{
        HistogramVec, IntCounterVec, IntGauge, register_histogram_vec, register_int_counter_vec,
        register_int_gauge,
    };

    static REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            "saffui_http_requests_total",
            "Requests answered, by method, route template and status.",
            &["method", "route", "status"]
        )
        .expect("a fresh family")
    });

    static DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
        register_histogram_vec!(
            "saffui_http_request_duration_seconds",
            "How long answering took, by method and route template.",
            &["method", "route"]
        )
        .expect("a fresh family")
    });

    static IN_PROGRESS: LazyLock<IntGauge> = LazyLock::new(|| {
        register_int_gauge!(
            "saffui_http_requests_in_progress",
            "Requests currently being answered."
        )
        .expect("a fresh gauge")
    });

    static LOGINS: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            "saffui_logins_total",
            "Login conclusions, by outcome: admitted, refused, or sent_back.",
            &["outcome"]
        )
        .expect("a fresh family")
    });

    /// Count one concluded login. Steps along the way are not conclusions
    /// and are not counted; the access log carries those.
    pub fn login_counted(outcome: &str) {
        LOGINS.with_label_values(&[outcome]).inc();
    }

    /// Every family in the text exposition format, version 0.0.4.
    pub fn render() -> String {
        let mut out = Vec::new();
        let encoder = prometheus::TextEncoder::new();
        let _ = prometheus::Encoder::encode(&encoder, &prometheus::gather(), &mut out);
        String::from_utf8(out).unwrap_or_default()
    }

    /// The measuring middleware, outermost so the whole handling is inside
    /// the clock, error paths included.
    pub struct Measured;

    impl<S, B> Transform<S, ServiceRequest> for Measured
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        B: 'static,
    {
        type Response = ServiceResponse<B>;
        type Error = Error;
        type Transform = MeasuredService<S>;
        type InitError = ();
        type Future = Ready<Result<Self::Transform, Self::InitError>>;

        fn new_transform(&self, service: S) -> Self::Future {
            ready(Ok(MeasuredService {
                service: Rc::new(service),
            }))
        }
    }

    pub struct MeasuredService<S> {
        service: Rc<S>,
    }

    impl<S, B> Service<ServiceRequest> for MeasuredService<S>
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        B: 'static,
    {
        type Response = ServiceResponse<B>;
        type Error = Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

        actix_web::dev::forward_ready!(service);

        fn call(&self, request: ServiceRequest) -> Self::Future {
            let service = Rc::clone(&self.service);
            Box::pin(async move {
                let method = request.method().as_str().to_owned();
                let started = Instant::now();
                IN_PROGRESS.inc();
                let answered = service.call(request).await;
                IN_PROGRESS.dec();
                // The template the router matched, so the label set stays as
                // bounded as the route table. Everything unmatched is one
                // value, not one per probed path.
                let (route, status) = match &answered {
                    Ok(response) => (
                        response
                            .request()
                            .match_pattern()
                            .unwrap_or_else(|| "unmatched".to_owned()),
                        response.status().as_u16(),
                    ),
                    Err(error) => (
                        "unmatched".to_owned(),
                        error.as_response_error().status_code().as_u16(),
                    ),
                };
                REQUESTS
                    .with_label_values(&[&method, &route, &status.to_string()])
                    .inc();
                DURATION
                    .with_label_values(&[&method, &route])
                    .observe(started.elapsed().as_secs_f64());
                answered
            })
        }
    }
}

#[cfg(feature = "metrics")]
pub use measured::{Measured, login_counted, render};

/// The build without the machinery: counting is nothing, and the scrape
/// route is never registered.
#[cfg(not(feature = "metrics"))]
pub fn login_counted(_outcome: &str) {}
