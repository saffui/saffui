#[allow(unused_imports)]
use super::support;
use std::io::Write;
use std::sync::{Arc, Mutex};

use super::support::Plane;
use actix_web::http::StatusCode;
use actix_web::test;
use server::api::config::{Plane as Mounted, observed, register};
use tracing_subscriber::fmt::MakeWriter;

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
        ceiling: support::ceiling(),
    }
}

/// Where a test's subscriber writes, so the test can read it back.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn lines(&self) -> Vec<serde_json::Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Captured;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The subscriber the binary installs, scoped to one test and writing where
/// the test can look.
fn watched() -> (Captured, tracing::subscriber::DefaultGuard) {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(false)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_writer(captured.clone())
        .finish();
    (captured, tracing::subscriber::set_default(subscriber))
}

/// The readable format is one line a person can scan: when, how loud, where
/// from, then the facts.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_line_meant_for_a_person_reads_as_one() {
    let plane = Plane::with_actions(&[]).await;
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_writer(captured.clone())
        .with_ansi(false)
        .event_format(commons::observability::Readable)
        .finish();
    let _scope = tracing::subscriber::set_default(subscriber);
    let app = test::init_service(observed().configure(register(&mounted(&plane)))).await;

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/.well-known/openid-configuration",
                support::REALM
            ))
            .insert_header(("x-request-id", "req-readable"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);

    let text = captured.text();
    assert!(
        text.contains("req-readable"),
        "the id is not on the line: {text}"
    );
    assert!(
        text.contains("main"),
        "the realm is not on the line: {text}"
    );
    assert!(
        text.contains("[http-request]"),
        "the line is not named for what it is: {text}"
    );
}

/// Every request gets an id and is told it. A caller's own is kept when it is
/// shaped like one, and replaced when it is shaped like a payload.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn every_request_is_given_an_id_and_told_it() {
    let plane = Plane::with_actions(&[]).await;
    let app = test::init_service(observed().configure(register(&mounted(&plane)))).await;
    let path = format!(
        "/realms/{}/.well-known/openid-configuration",
        support::REALM
    );

    let response = test::call_service(&app, test::TestRequest::get().uri(&path).to_request()).await;
    let given = response
        .headers()
        .get("x-request-id")
        .expect("an id on every response")
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(given.len(), 36, "not a uuid: {given}");

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&path)
            .insert_header(("x-request-id", "gateway-7f3a"))
            .to_request(),
    )
    .await;
    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "gateway-7f3a",
        "a caller's id was not kept"
    );

    for forged in ["with space", &"x".repeat(129), "tab\there"] {
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&path)
                .insert_header(("x-request-id", forged))
                .to_request(),
        )
        .await;
        let kept = response
            .headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap();
        assert_ne!(kept, forged, "an id shaped like a payload was kept");
        assert_eq!(kept.len(), 36);
    }
}

/// One line per request: the id, the method, the route pattern, the realm and
/// the status. The query is not in it, however much the request carried.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_request_leaves_one_line_with_its_route_and_never_its_query() {
    let plane = Plane::with_actions(&[]).await;
    let (captured, _scope) = watched();
    let app = test::init_service(observed().configure(register(&mounted(&plane)))).await;

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/.well-known/openid-configuration?state=the-state-nobody-logs&nonce=n0",
                support::REALM
            ))
            .insert_header(("x-request-id", "req-one"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    // The span closes when the request is let go of, which in a running
    // server is the moment the response has been sent.
    drop(response);

    let closing: Vec<serde_json::Value> = captured
        .lines()
        .into_iter()
        .filter(|line| line["span"]["request_id"] == "req-one" && line["message"] == "close")
        .collect();
    assert_eq!(
        closing.len(),
        1,
        "not one line for the request: {}",
        captured.text()
    );
    let line = &closing[0]["span"];
    assert_eq!(line["method"], "GET");
    assert_eq!(
        line["route"],
        "/realms/{realm}/.well-known/openid-configuration"
    );
    assert_eq!(line["realm"], support::REALM);
    assert_eq!(line["status"], 200);
    assert!(
        closing[0].get("time.busy").is_some(),
        "no duration on the line: {}",
        closing[0]
    );

    let text = captured.text();
    assert!(
        !text.contains("the-state-nobody-logs") && !text.contains("nonce"),
        "the query reached the log: {text}"
    );
}

/// A refusal is on the record under the request it belongs to, with the
/// reason and the client, and with nothing else of what the client sent.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_refusal_is_recorded_under_its_request() {
    let plane = Plane::with_actions(&[]).await;
    let (captured, _scope) = watched();
    let app = test::init_service(observed().configure(register(&mounted(&plane)))).await;

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?response_type=code&client_id={}&scope=openid&redirect_uri=https://elsewhere.example/cb&state=unlogged-state",
                support::REALM,
                support::CONFIDENTIAL
            ))
            .insert_header(("x-request-id", "req-two"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let refusal = captured
        .lines()
        .into_iter()
        .find(|line| line["message"] == "authorization refused")
        .unwrap_or_else(|| panic!("no refusal on the record: {}", captured.text()));
    assert_eq!(refusal["span"]["request_id"], "req-two", "{refusal}");
    assert_eq!(refusal["error"], "invalid_request");
    assert_eq!(refusal["client_id"], support::CONFIDENTIAL);
    assert_eq!(refusal["level"], "WARN");
    assert!(
        !captured.text().contains("unlogged-state"),
        "the state reached the log"
    );
}

/// One line of the exposition, read back as a number. The families are
/// process-wide and other tests in this binary serve requests too, so
/// every count is compared to its own before, never to zero.
fn counted(rendered: &str, family: &str, wanted: &[&str]) -> f64 {
    rendered
        .lines()
        .filter(|line| line.starts_with(family))
        .filter(|line| wanted.iter().all(|needle| line.contains(needle)))
        .filter_map(|line| line.rsplit(' ').next()?.parse::<f64>().ok())
        .sum()
}

/// The families count what was served: the route label is the matched
/// template, never the raw path, and a concluded login lands under its
/// outcome. Measured through the same application a binary mounts.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_served_request_lands_in_the_families_by_template() {
    let plane = Plane::with_actions(&[]).await;
    let app = test::init_service(
        server::api::config::observed_with(true).configure(register(&mounted(&plane))),
    )
    .await;

    let certs_template = "route=\"/realms/{realm}/protocol/openid-connect/certs\"";
    let before = server::metrics::render();
    let certs_before = counted(&before, "saffui_http_requests_total", &[certs_template]);
    let refused_before = counted(&before, "saffui_logins_total", &["outcome=\"refused\""]);

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/certs",
                support::REALM
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // A whole refused login, so the outcome counter moves for the reason a
    // dashboard believes it does.
    let opened = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope=openid&state=s",
                support::REALM,
                support::CONFIDENTIAL,
                support::urlencode("https://app.example/callback"),
            ))
            .to_request(),
    )
    .await;
    let cookies: Vec<String> = opened
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let binding =
        support::cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login opened");
    let answered = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/login",
                support::REALM
            ))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .set_json(serde_json::json!({
                "username": support::SUBJECT,
                "password": "not-the-password",
            }))
            .to_request(),
    )
    .await;
    assert_eq!(answered.status(), StatusCode::UNAUTHORIZED);

    let after = server::metrics::render();
    assert!(
        counted(&after, "saffui_http_requests_total", &[certs_template]) > certs_before,
        "the certs request was not counted under its template:\n{after}"
    );
    assert!(
        counted(
            &after,
            "saffui_http_request_duration_seconds_count",
            &[certs_template]
        ) > 0.0,
        "no duration was observed for the certs route"
    );
    assert!(
        counted(&after, "saffui_logins_total", &["outcome=\"refused\""]) > refused_before,
        "the refused login was not counted:\n{after}"
    );
    // The label set stays as bounded as the route table: the raw path, with
    // the realm's name in it, never appears as a route.
    assert!(
        !after.contains("route=\"/realms/main/"),
        "a raw path reached the route label:\n{after}"
    );
}

/// A caller already inside a trace stays in it: the W3C header reparents
/// the request's span, the exported span carries the caller's trace id,
/// and the route rides it as an attribute. A caller outside any trace gets
/// a fresh one. Exported through an in-memory pipe, read back whole.
#[cfg(feature = "otel")]
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_callers_trace_carries_through_to_the_exported_span() {
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::prelude::*;

    let plane = Plane::with_actions(&[]).await;
    server::otel::install_propagation();
    let exporter = opentelemetry_sdk::trace::InMemorySpanExporter::default();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let _scope = tracing::subscriber::set_default(
        tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("the-test"))),
    );
    let app = test::init_service(observed().configure(register(&mounted(&plane)))).await;
    let path = format!("/realms/{}/protocol/openid-connect/certs", support::REALM);

    let inside = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&path)
            .insert_header(("traceparent", inside))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);

    let spans = exporter.get_finished_spans().expect("the exported spans");
    let carried = spans
        .iter()
        .find(|span| {
            span.name == "http-request"
                && span.span_context.trace_id()
                    == opentelemetry::trace::TraceId::from_hex("0af7651916cd43dd8448eb211c80319c")
                        .expect("a well-formed id")
        })
        .unwrap_or_else(|| {
            panic!(
                "no request span in the caller's trace: {:?}",
                spans
                    .iter()
                    .map(|span| (span.name.clone(), span.span_context.trace_id()))
                    .collect::<Vec<_>>()
            )
        });
    assert!(
        carried.attributes.iter().any(|held| {
            held.key.as_str() == "route"
                && held.value.as_str() == "/realms/{realm}/protocol/openid-connect/certs"
        }),
        "the route is not on the span: {:?}",
        carried.attributes
    );

    // Outside any trace: a fresh id, not zero and not the caller's.
    let response = test::call_service(&app, test::TestRequest::get().uri(&path).to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);
    let spans = exporter.get_finished_spans().expect("the exported spans");
    let fresh = spans
        .iter()
        .filter(|span| span.name == "http-request")
        .map(|span| span.span_context.trace_id())
        .find(|id| {
            *id != opentelemetry::trace::TraceId::from_hex("0af7651916cd43dd8448eb211c80319c")
                .expect("a well-formed id")
        })
        .expect("a fresh trace for the untraced caller");
    assert_ne!(fresh, opentelemetry::trace::TraceId::INVALID);
}

/// One key joins the three records: the trace id lands on the log line, and
/// an admin write made inside that trace journals it inside the hashed
/// envelope, projected into the queryable column, with the chain still
/// verifying whole over rows that carry the key and rows that do not.
#[cfg(feature = "otel")]
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_trace_joins_the_log_line_and_the_journal_row() {
    use models::entities::authz::AdminAction;
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::prelude::*;

    let plane = Plane::with_actions(&[AdminAction::UserWrite]).await;
    server::otel::install_propagation();
    let exporter = opentelemetry_sdk::trace::InMemorySpanExporter::default();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let captured = Captured::default();
    let _scope = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .with_writer(captured.clone())
            .finish()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("the-test"))),
    );
    let app = test::init_service(observed().configure(register(&mounted(&plane)))).await;

    let bearer = plane.token(&support::claims());
    let inside = "00-1bad2cafe00dfeed5566778899aabbcc-b7ad6b7169203331-01";
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/admin/realms/{}/users", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .insert_header(("traceparent", inside))
            .set_json(serde_json::json!({ "user_name": "traced-person" }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    drop(response);

    let line = captured
        .lines()
        .into_iter()
        .find(|line| line["message"] == "close" && line["span"]["status"] == 201)
        .unwrap_or_else(|| panic!("no closing line for the write: {}", captured.text()));
    assert_eq!(
        line["span"]["trace_id"], "1bad2cafe00dfeed5566778899aabbcc",
        "the log line does not carry the trace: {line}"
    );

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &store::tenancy::TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    let journalled: String = transaction
        .query_one(
            "SELECT envelope ->> 'trace_id' FROM audit_events \
             WHERE trace_id = $1 AND kind = 'admin.write'",
            &[&"1bad2cafe00dfeed5566778899aabbcc"],
        )
        .await
        .expect("the journal row is findable by its projected trace")
        .get(0);
    assert_eq!(journalled, "1bad2cafe00dfeed5566778899aabbcc");
    let verified = store::audit::verify(&transaction, support::sealing().provider.digest())
        .await
        .expect("a verification");
    assert!(
        verified.holds(),
        "the chain broke under the carried key at {:?}",
        verified.broken_at
    );
}
