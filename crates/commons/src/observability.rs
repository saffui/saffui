//! Logging setup, and what has to happen to a value before it is logged.
//!
//! Installing a subscriber is something a process does once, so it sits behind
//! a feature: a library only ever emits records, and nothing that does not
//! serve a process should compile the stack that formats them.
//!
//! [`sanitize_for_log`] is not behind anything. It is a pure function and the
//! one part of this that every layer needs.

/// Strip the characters that end a log line.
///
/// A value that reaches a log from outside — a realm name, a client id, a
/// header — can carry `\r\n` and write a second line of its own. That forged
/// line looks exactly like a real one to whatever reads the log, which is how a
/// login that never happened appears in an audit trail.
///
/// Not an escape and not a quote: the characters are removed, so nothing
/// downstream has to agree on how to read them back.
pub fn sanitize_for_log(input: &str) -> String {
    input.chars().filter(|c| *c != '\n' && *c != '\r').collect()
}

/// Install the process logger.
///
/// `directives` is an `EnvFilter` string — a bare level like `info`, or one per
/// module like `crypto=debug,config=info`. One the filter refuses — a level that
/// does not exist, say — falls back to `info` rather than leaving the process
/// silent, which is the one place a default beats a failure: a deployment with
/// no logs cannot tell you why it has none.
///
/// `format` is `json` for one object per line, anything else for compact text.
#[cfg(feature = "tracing-json")]
pub fn init(directives: &str, format: &str) {
    use tracing_subscriber::Layer;
    use tracing_subscriber::prelude::*;

    // Records emitted through the `log` facade — which is what the framework
    // crates use — routed into the same pipeline, so one filter and one format
    // cover everything the process emits.
    let _ = tracing_log::LogTracer::init();

    let filter = tracing_subscriber::EnvFilter::try_new(directives)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let layer = tracing_subscriber::fmt::layer();
    let layer = match format {
        "json" => layer
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .boxed(),
        _ => layer.compact().boxed(),
    };

    // `try_init` rather than `init`: a second call is a caller's mistake, not a
    // reason to abort a running process.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init();
}

/// The per-request root span, and the id every line under it carries.
#[cfg(feature = "request-span")]
mod request_span {
    use actix_web::dev::{ServiceRequest, ServiceResponse};
    use actix_web::{Error, HttpMessage};
    use tracing::Span;
    use tracing_actix_web::RootSpanBuilder;

    /// The correlation id for one request.
    ///
    /// Set at ingress and echoed to the client, so a line in a log and a
    /// complaint from a caller can be joined without guessing.
    #[derive(Clone, Debug)]
    pub struct RequestId(pub String);

    /// Opens the span every later record inherits.
    ///
    /// `tenant` and `realm` are declared empty and recorded once whatever
    /// resolves them has run. Declaring them here rather than adding them later
    /// is what lets a record made before resolution still carry the field, empty
    /// — a log where the field sometimes does not exist cannot be queried on.
    pub struct SaffuiRootSpan;

    impl RootSpanBuilder for SaffuiRootSpan {
        fn on_request_start(request: &ServiceRequest) -> Span {
            let request_id = request
                .extensions()
                .get::<RequestId>()
                .map(|id| id.0.clone())
                .unwrap_or_default();

            tracing::info_span!(
                "http-request",
                request_id = %request_id,
                method = %request.method(),
                // The path is caller-controlled, so it is cleaned before it
                // reaches a line.
                path = %super::sanitize_for_log(request.path()),
                tenant = tracing::field::Empty,
                realm = tracing::field::Empty,
                status = tracing::field::Empty,
            )
        }

        fn on_request_end<B>(span: Span, outcome: &Result<ServiceResponse<B>, Error>) {
            if let Ok(response) = outcome {
                span.record("status", response.status().as_u16());
            }
        }
    }
}

#[cfg(feature = "request-span")]
pub use request_span::{RequestId, SaffuiRootSpan};

#[cfg(test)]
mod tests {
    use super::*;

    /// A value from outside cannot end the line it is written on.
    #[test]
    fn a_logged_value_cannot_forge_a_second_line() {
        assert_eq!(
            sanitize_for_log("acme\r\n[FORGED] admin login succeeded"),
            "acme[FORGED] admin login succeeded"
        );

        for injected in ["\n", "\r", "\r\n", "a\nb\rc"] {
            let cleaned = sanitize_for_log(injected);

            assert!(!cleaned.contains('\n'), "{injected:?}");
            assert!(!cleaned.contains('\r'), "{injected:?}");
        }
    }

    /// Everything else survives, including the characters a quoting scheme
    /// would have had to escape.
    #[test]
    fn nothing_else_is_touched() {
        for value in [
            "plain-realm",
            "a\tb",
            "quote\"and'quote",
            "üñî",
            "{\"k\":1}",
            "",
        ] {
            assert_eq!(sanitize_for_log(value), value, "{value:?}");
        }
    }

    /// Installing the logger twice is a caller's mistake, not a reason to
    /// abort a running process.
    #[cfg(feature = "tracing-json")]
    #[test]
    fn installing_the_logger_twice_does_not_abort() {
        init("info", "json");
        init("crypto=debug,info", "text");

        // A directive the filter refuses leaves the process logging rather than
        // silent. `EnvFilter` reads bare words as target names, so a string that
        // merely looks wrong is accepted — it takes a level that does not exist,
        // which is the typo an operator actually makes.
        assert!(tracing_subscriber::EnvFilter::try_new("crypto=nonsense").is_err());
        init("crypto=nonsense", "text");
    }

    /// The line count is what changes, and only that.
    ///
    /// The point is not that the value is unrecognisable — an operator still has
    /// to read it — but that it occupies exactly one line.
    #[test]
    fn a_sanitised_value_is_one_line() {
        let forged = "tenant\r\n2026-08-16 INFO admin login from 10.0.0.1";
        let cleaned = sanitize_for_log(forged);

        assert_eq!(cleaned.lines().count(), 1);
        assert!(
            cleaned.contains("admin login"),
            "the value is still readable"
        );
    }
}
