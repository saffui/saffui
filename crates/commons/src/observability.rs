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

    // A span's close is the one line every request leaves: its fields, and
    // how long it was busy. That line is the access log, and there is no
    // second one written by hand to disagree with it.
    let layer = tracing_subscriber::fmt::layer()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE);
    let layer = match format {
        "json" => layer
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .boxed(),
        "compact" => layer.compact().boxed(),
        _ => layer.event_format(Readable).boxed(),
    };

    // `try_init` rather than `init`: a second call is a caller's mistake, not a
    // reason to abort a running process.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init();
}

/// One line, meant for a person: when, how loud, where from, what happened,
/// and the facts behind it.
///
/// ```text
/// 2026-08-23 09:15:42.123 INFO  [protocol::logout] logout told client_id=app status=200
/// ```
#[cfg(feature = "tracing-json")]
pub struct Readable;

#[cfg(feature = "tracing-json")]
impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for Readable
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        context: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        use tracing_subscriber::fmt::FormatFields as _;

        let metadata = event.metadata();
        let level = *metadata.level();
        write!(
            writer,
            "{} {level:<5} [{}] ",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            named(metadata)
        )?;

        // What happened, then what it happened to. The spans come from the
        // event's own scope and not from what is current, because a span's
        // closing line is emitted as it leaves.
        context.format_fields(writer.by_ref(), event)?;
        if let Some(scope) = context.event_scope() {
            for span in scope.from_root() {
                let extensions = span.extensions();
                if let Some(fields) =
                    extensions.get::<tracing_subscriber::fmt::FormattedFields<N>>()
                    && !fields.is_empty()
                {
                    write!(writer, " {fields}")?;
                }
            }
        }
        writeln!(writer)
    }
}

/// What to call the line's origin: a span's own name where there is one, and
/// the module otherwise. A span is named for what it does (`http-request`),
/// which beats the module that happens to declare it.
#[cfg(feature = "tracing-json")]
fn named(metadata: &tracing::Metadata<'_>) -> String {
    let name = metadata.name();
    // What `tracing` calls an ordinary event: the macro names it by file and
    // line, which is not a name anybody reads.
    if name.starts_with("event ") {
        shortened(metadata.target())
    } else {
        name.to_owned()
    }
}

/// The last two segments of a module path. `server::api::rest::endpoints::
/// protocol::logout` is a column of noise; `protocol::logout` is the answer.
#[cfg(feature = "tracing-json")]
fn shortened(target: &str) -> String {
    let mut parts: Vec<&str> = target.rsplit("::").take(2).collect();
    parts.reverse();
    parts.join("::")
}

/// The per-request root span, and the id every line under it carries.
#[cfg(feature = "request-span")]
mod request_span {
    use std::future::{Ready, ready};
    use std::pin::Pin;

    use actix_web::body::MessageBody;
    use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
    use actix_web::http::header::{HeaderName, HeaderValue};
    use actix_web::{Error, HttpMessage};
    use tracing::Span;
    use tracing_actix_web::RootSpanBuilder;

    /// The header the id travels in, both ways.
    pub const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

    /// The most an id a caller supplies may be. Longer is not an id, it is a
    /// payload looking for a log to land in.
    const LONGEST_ID: usize = 128;

    /// The correlation id for one request.
    ///
    /// Set at ingress and echoed to the client, so a line in a log and a
    /// complaint from a caller can be joined without guessing.
    #[derive(Clone, Debug)]
    pub struct RequestId(pub String);

    impl RequestId {
        /// The caller's, when it is shaped like one; ours otherwise.
        ///
        /// A caller's id is kept so a gateway can trace a request across every
        /// service it crossed. It is kept only when it is plainly an
        /// identifier: bounded, and nothing but printable ASCII, so it can
        /// neither end the line it is written on nor smuggle a payload into
        /// every record of the request.
        fn for_request(request: &ServiceRequest) -> Self {
            let supplied = request
                .headers()
                .get(REQUEST_ID)
                .and_then(|value| value.to_str().ok())
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= LONGEST_ID
                        && value.bytes().all(|byte| byte.is_ascii_graphic())
                });
            match supplied {
                Some(theirs) => RequestId(theirs.to_owned()),
                None => RequestId(uuid::Uuid::new_v4().to_string()),
            }
        }
    }

    /// Gives every request its id, before anything else looks.
    ///
    /// Its own middleware, outermost, rather than a line in the span builder:
    /// the id has to exist before the span opens and has to reach the
    /// response after the span closes, and a builder sees neither end.
    pub struct WithRequestId;

    impl<S, B> Transform<S, ServiceRequest> for WithRequestId
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        B: MessageBody + 'static,
    {
        type Response = ServiceResponse<B>;
        type Error = Error;
        type Transform = RequestIdService<S>;
        type InitError = ();
        type Future = Ready<Result<Self::Transform, Self::InitError>>;

        fn new_transform(&self, service: S) -> Self::Future {
            ready(Ok(RequestIdService { service }))
        }
    }

    pub struct RequestIdService<S> {
        service: S,
    }

    impl<S, B> Service<ServiceRequest> for RequestIdService<S>
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        B: MessageBody + 'static,
    {
        type Response = ServiceResponse<B>;
        type Error = Error;
        type Future =
            Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

        actix_web::dev::forward_ready!(service);

        fn call(&self, request: ServiceRequest) -> Self::Future {
            let id = RequestId::for_request(&request);
            request.extensions_mut().insert(id.clone());
            let answering = self.service.call(request);
            Box::pin(async move {
                let mut response = answering.await?;
                if let Ok(value) = HeaderValue::from_str(&id.0) {
                    response.headers_mut().insert(REQUEST_ID, value);
                }
                Ok(response)
            })
        }
    }

    /// Opens the span every later record inherits.
    ///
    /// `route`, `realm` and `status` are declared empty and recorded once the
    /// request has been routed and answered. Declaring them at the start
    /// rather than adding them later is what lets a record made before
    /// routing still carry the field, empty: a log where a field sometimes
    /// does not exist cannot be queried on.
    ///
    /// The path is recorded and the query is not. What a protocol request
    /// carries in its query is a state, a nonce, a code: the things a log
    /// must never hold, and the one place they could get in is closed here.
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
                route = tracing::field::Empty,
                realm = tracing::field::Empty,
                status = tracing::field::Empty,
            )
        }

        fn on_request_end<B>(span: Span, outcome: &Result<ServiceResponse<B>, Error>) {
            match outcome {
                Ok(response) => {
                    span.record("status", response.status().as_u16());
                    // Known only once routed: the pattern, which is what a
                    // dashboard groups by, and the realm the path named.
                    if let Some(route) = response.request().match_pattern() {
                        span.record("route", route);
                    }
                    if let Some(realm) = response.request().match_info().get("realm") {
                        span.record("realm", super::sanitize_for_log(realm));
                    }
                }
                Err(error) => {
                    span.record("status", error.as_response_error().status_code().as_u16());
                }
            }
        }
    }
}

#[cfg(feature = "request-span")]
pub use request_span::{REQUEST_ID, RequestId, SaffuiRootSpan, WithRequestId};

#[cfg(all(test, feature = "tracing-json"))]
mod readable {
    use super::shortened;

    /// A target is where a line came from, not the path to get there.
    #[test]
    fn a_target_is_shortened_to_what_names_it() {
        assert_eq!(
            shortened("server::api::rest::endpoints::protocol::logout"),
            "protocol::logout"
        );
        assert_eq!(
            shortened("commons::observability"),
            "commons::observability"
        );
        assert_eq!(shortened("saffui"), "saffui");
        assert_eq!(shortened(""), "");
    }
}

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
