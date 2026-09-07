//! Span export over OTLP, and the inbound half of trace propagation.
//!
//! Nothing here dials until an operator names a collector: the exporter is
//! only built over `SAFFUI_OTEL_ENDPOINT`, whatever the build carries and
//! whatever the feature switch says. The endpoint is the operator's own,
//! read from the environment like the database's, so it does not ride the
//! egress guard that judges addresses tenants write.

use commons::feature::Feature;

/// Whether this build carries the machinery. Only this crate sees its own
/// cfg; the boot-time resolver asks each crate about what it compiles.
pub fn compiled(feature: Feature) -> bool {
    matches!(feature, Feature::Otel) && cfg!(feature = "otel")
}

#[cfg(feature = "otel")]
mod exporting {
    use actix_web::dev::ServiceRequest;
    use opentelemetry::KeyValue;
    use opentelemetry::propagation::TextMapPropagator as _;
    use opentelemetry::trace::TraceContextExt as _;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    use tracing_subscriber::Layer;

    /// The export pipeline, held so it can be flushed and shut down when the
    /// process stops rather than dropped with spans still in the batch.
    pub struct Telemetry {
        provider: SdkTracerProvider,
    }

    impl Telemetry {
        /// Flush what the batch holds and stop the exporter. Called after
        /// the servers have stopped, so the last requests' spans leave too.
        pub fn shutdown(self) {
            if let Err(why) = self.provider.shutdown() {
                tracing::warn!(%why, "the span exporter did not shut down cleanly");
            }
        }
    }

    /// Read the W3C headers on every request from now on, and tie each new
    /// root span into the trace they name. Once per process; separate from
    /// `start` only so a test can propagate into its own local pipeline.
    pub fn install_propagation() {
        commons::observability::install_parenting(tie);
    }

    /// The tie itself: ran by the span builder on the span it just opened,
    /// because a span's exported identity is settled at its birth.
    fn tie(request: &ServiceRequest, span: &tracing::Span) {
        let parent = TraceContextPropagator::new().extract(&Carried(request.headers()));
        // Garbage in the header extracts to nothing valid, and the fresh
        // trace stands.
        if parent.span().span_context().is_valid()
            && let Err(why) = span.set_parent(parent)
        {
            tracing::debug!(%why, "a caller's trace context could not be tied");
        }
        // Onto the log line, fresh or inherited, so a line and a trace join
        // on the same key the journal row carries.
        let settled = span.context().span().span_context().trace_id();
        if settled != opentelemetry::trace::TraceId::INVALID {
            span.record(
                "trace_id",
                tracing::field::display(format!("{settled:032x}")),
            );
        }
    }

    /// The trace the current request belongs to, when there is one: what the
    /// audit journal writes beside what it records.
    pub fn current_trace_id() -> Option<String> {
        let id = tracing::Span::current()
            .context()
            .span()
            .span_context()
            .trace_id();
        (id != opentelemetry::trace::TraceId::INVALID).then(|| format!("{id:032x}"))
    }

    /// The W3C `traceparent` and `tracestate` a caller sent, off the headers.
    struct Carried<'request>(&'request actix_web::http::header::HeaderMap);

    impl opentelemetry::propagation::Extractor for Carried<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|value| value.to_str().ok())
        }

        fn keys(&self) -> Vec<&str> {
            self.0
                .keys()
                .map(actix_web::http::header::HeaderName::as_str)
                .collect()
        }
    }

    /// Build the pipeline against the named collector, and hand back the
    /// layer that feeds it. The ratio is parent-based: a request arriving
    /// inside a sampled trace stays sampled.
    pub fn start(
        endpoint: &str,
        ratio: f64,
    ) -> Result<
        (
            Telemetry,
            Box<dyn Layer<commons::observability::Watched> + Send + Sync>,
        ),
        String,
    > {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .build()
            .map_err(|why| format!("the span exporter cannot be built: {why}"))?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource())
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                ratio,
            ))))
            .build();
        let layer = tracing_opentelemetry::layer()
            .with_tracer(provider.tracer("saffui"))
            .boxed();
        install_propagation();
        Ok((Telemetry { provider }, layer))
    }

    /// Who this process is, to whoever reads the spans. The pod attributes
    /// ride only where an orchestrator set them; absent env, absent attribute.
    fn resource() -> opentelemetry_sdk::Resource {
        let mut telling = opentelemetry_sdk::Resource::builder()
            .with_service_name("saffui")
            .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")));
        for (variable, attribute) in [
            ("POD_NAME", "k8s.pod.name"),
            ("POD_NAMESPACE", "k8s.namespace.name"),
            ("POD_NODE", "k8s.node.name"),
            ("HOSTNAME", "host.name"),
            ("DEPLOY_ENV", "deployment.environment"),
        ] {
            if let Ok(value) = std::env::var(variable) {
                telling = telling.with_attribute(KeyValue::new(attribute, value));
            }
        }
        telling.build()
    }
}

#[cfg(feature = "otel")]
pub use exporting::{Telemetry, current_trace_id, install_propagation, start};

/// The build without the machinery: no request ever belongs to a trace.
#[cfg(not(feature = "otel"))]
pub fn current_trace_id() -> Option<String> {
    None
}
