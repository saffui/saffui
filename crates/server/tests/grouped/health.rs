#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use server::api::config::register_ops;
use server::api::rest::endpoints::ops::health::Vitals;

async fn ask(vitals: &Vitals, path: &str) -> (StatusCode, String) {
    let app = test::init_service(App::new().configure(register_ops(vitals, true))).await;
    let response = test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
    let status = response.status();
    let body = String::from_utf8(test::read_body(response).await.to_vec()).unwrap_or_default();
    (status, body)
}

/// Alive says the process runs, and touches nothing that could be down. What it
/// touches is what can get the pod restarted, and a restart fixes the process
/// and nothing else.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn alive_answers_before_anything_is_ready() {
    let plane = Plane::with_actions(&[]).await;
    let vitals = Vitals::new(plane.pool(), 999);

    let (status, _) = ask(&vitals, "/livez").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a process that had not finished starting was reported as dead"
    );

    // And it keeps saying so while nothing else does.
    let (starting, _) = ask(&vitals, "/startupz").await;
    let (not_ready, _) = ask(&vitals, "/readyz").await;
    assert_eq!(starting, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(not_ready, StatusCode::SERVICE_UNAVAILABLE);
}

/// Ready means this pod can serve now, and it says which check refused.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn ready_answers_once_the_database_and_the_schema_agree() {
    let plane = Plane::with_actions(&[]).await;
    let vitals = Vitals::new(plane.pool(), 999);

    let (before, why) = ask(&vitals, "/readyz").await;
    assert_eq!(before, StatusCode::SERVICE_UNAVAILABLE);
    assert!(why.contains("starting"), "{why}");

    vitals.started();
    let (after, body) = ask(&vitals, "/readyz").await;
    assert_eq!(after, StatusCode::OK, "{body}");
    assert!(body.contains("\"ready\":true"), "{body}");

    let (started, _) = ask(&vitals, "/startupz").await;
    assert_eq!(started, StatusCode::OK);
}

/// A database that has migrated past this build is a pod that cannot read what
/// its peers now write. It leaves the rotation rather than serving stale reads.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_schema_ahead_of_this_build_takes_the_pod_out_of_service() {
    let plane = Plane::with_actions(&[]).await;
    let behind = Vitals::new(plane.pool(), 1);
    behind.started();

    let (status, why) = ask(&behind, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(why.contains("schema ahead"), "{why}");

    // Alive still answers: restarting this pod would not move the schema back.
    let (alive, _) = ask(&behind, "/livez").await;
    assert_eq!(
        alive,
        StatusCode::OK,
        "a pod behind the schema was reported dead, so it would be restarted forever"
    );
}

/// Draining takes the pod out of the rotation while it finishes what it has.
/// Alive stays true, because the process is meant to keep running until it is
/// done, not to be killed.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn draining_stops_new_traffic_and_not_the_process() {
    let plane = Plane::with_actions(&[]).await;
    let vitals = Vitals::new(plane.pool(), 999);
    vitals.started();

    assert_eq!(ask(&vitals, "/readyz").await.0, StatusCode::OK);

    vitals.drain();
    let (status, why) = ask(&vitals, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(why.contains("draining"), "{why}");
    assert_eq!(
        ask(&vitals, "/livez").await.0,
        StatusCode::OK,
        "a draining pod was reported dead and would be killed mid request"
    );
}

/// The probes carry no guard, so they answer when authentication cannot. A
/// probe that has to authenticate fails exactly when it is most needed.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_probes_ask_nothing_of_the_caller() {
    let plane = Plane::with_actions(&[]).await;
    let vitals = Vitals::new(plane.pool(), 999);
    vitals.started();

    for path in ["/livez", "/readyz", "/startupz"] {
        let app = test::init_service(App::new().configure(register_ops(&vitals, true))).await;
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(path)
                .insert_header(("authorization", "Bearer nonsense"))
                .to_request(),
        )
        .await;
        assert_ne!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{path} refused a caller instead of answering an orchestrator"
        );
    }
}

/// The scrape is a switch: turned on it answers off the operations surface,
/// turned off the route is absent, and a scraper reads the truth either way.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_scrape_is_there_exactly_when_it_is_turned_on() {
    let plane = Plane::with_actions(&[]).await;
    let vitals = Vitals::new(plane.pool(), 999);
    vitals.started();

    let exposing = test::init_service(App::new().configure(register_ops(&vitals, true))).await;
    let answered = test::call_service(
        &exposing,
        test::TestRequest::get().uri("/metrics").to_request(),
    )
    .await;
    assert_eq!(answered.status(), StatusCode::OK);
    let kind = answered
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(kind.starts_with("text/plain"), "not the text form: {kind}");

    let dark = test::init_service(App::new().configure(register_ops(&vitals, false))).await;
    let refused =
        test::call_service(&dark, test::TestRequest::get().uri("/metrics").to_request()).await;
    assert_eq!(
        refused.status(),
        StatusCode::NOT_FOUND,
        "a turned-off scrape still answers"
    );
}
