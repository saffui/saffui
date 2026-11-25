use actix_web::http::StatusCode;
use actix_web::{App, test, web};
use saffui_core::ports::storage::StorageUnavailable;
use saffui_core::testkit::memory::MemoryStorage;
use server::api::config::{register_data_plane, register_ops_plane};
use server::api::rest::endpoints::health::DrainFlag;

const PROBES: [&str; 2] = ["/livez", "/readyz"];

#[actix_web::test]
async fn the_ops_plane_answers_200_on_both_probes_while_serving() {
    let (product, _storage) = MemoryStorage::wire();
    let drain_flag = web::Data::new(DrainFlag::default());
    let app = test::init_service(
        App::new().configure(register_ops_plane(web::Data::new(product), drain_flag)),
    )
    .await;

    for path in PROBES {
        let request = test::TestRequest::get().uri(path).to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
    }
}

#[actix_web::test]
async fn the_ops_plane_answers_503_on_readyz_and_200_on_livez_once_shutdown_is_requested() {
    let (product, _storage) = MemoryStorage::wire();
    let drain_flag = web::Data::new(DrainFlag::default());
    let app = test::init_service(App::new().configure(register_ops_plane(
        web::Data::new(product),
        drain_flag.clone(),
    )))
    .await;
    drain_flag.start_drain();

    let request = test::TestRequest::get().uri("/readyz").to_request();
    let response = test::call_service(&app, request).await;
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "GET /readyz"
    );

    // A process that drains is not dead: liveness must not get it killed.
    let request = test::TestRequest::get().uri("/livez").to_request();
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK, "GET /livez");
}

#[actix_web::test]
async fn the_data_plane_answers_404_on_both_probe_paths() {
    let (product, _storage) = MemoryStorage::wire();
    let app =
        test::init_service(App::new().configure(register_data_plane(web::Data::new(product))))
            .await;

    for path in PROBES {
        let request = test::TestRequest::get().uri(path).to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "GET {path}");
    }
}

#[actix_web::test]
async fn readyz_answers_503_and_says_why_when_the_storage_cannot_serve() {
    let (product, storage) = MemoryStorage::wire();
    storage.fail_with(StorageUnavailable::SchemaAhead);
    let drain_flag = web::Data::new(DrainFlag::default());
    let app = test::init_service(
        App::new().configure(register_ops_plane(web::Data::new(product), drain_flag)),
    )
    .await;
    let request = test::TestRequest::get().uri("/readyz").to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = test::read_body(response).await;
    assert_eq!(
        body, "the database schema is ahead of this binary\n",
        "the operator reads the reason in the body"
    );

    // A database that is down must not get a healthy process restarted.
    let request = test::TestRequest::get().uri("/livez").to_request();
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK, "GET /livez");
}
