//! What a request leaves in the log, and what it must not.
//!
//! One line per request, with the id the caller can quote back, the route a
//! dashboard groups by, the realm and the status. Never the query: a protocol
//! request carries a state, a nonce, a code in it, and a log that held those
//! would be the place to steal them from.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use actix_web::http::StatusCode;
use actix_web::test;
use server::api::config::{Plane as Mounted, observed, register};
use support::Plane;
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
        sealing: support::sealing(),
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
