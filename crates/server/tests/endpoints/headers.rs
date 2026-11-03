use actix_web::http::Method;
use actix_web::{App, test, web};
use saffui_core::settings::{PublicOrigin, Settings};
use saffui_core::testkit::memory::MemoryStorage;
use server::api::config::register_data_plane;

/// The headers of an answer of the data plane, by name.
async fn read_headers(
    product: saffui_core::app::App,
    method: Method,
    path: &str,
) -> Vec<(String, String)> {
    let app =
        test::init_service(App::new().configure(register_data_plane(web::Data::new(product))))
            .await;
    let request = test::TestRequest::default()
        .method(method)
        .uri(path)
        .to_request();
    let response = test::call_service(&app, request).await;
    response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(known, _)| known == name)
        .map(|(_, value)| value.as_str())
}

#[actix_web::test]
async fn every_answer_of_the_data_plane_says_what_a_browser_must_not_do_with_it() {
    let (product, _storage) = MemoryStorage::wire();

    // A document, an unknown path, and a refusal of the administration plane.
    for (method, path) in [
        (Method::GET, "/realms/acme/.well-known/openid-configuration"),
        (Method::GET, "/nowhere"),
        (Method::GET, "/admin/v1/realms/acme"),
    ] {
        let headers = read_headers(product.clone(), method, path).await;
        assert_eq!(
            find(&headers, "x-content-type-options"),
            Some("nosniff"),
            "{path}"
        );
        assert_eq!(find(&headers, "x-frame-options"), Some("DENY"), "{path}");
        assert_eq!(
            find(&headers, "referrer-policy"),
            Some("no-referrer"),
            "{path}"
        );
        assert_eq!(
            find(&headers, "strict-transport-security"),
            Some("max-age=31536000"),
            "an origin served over TLS says so: {path}"
        );
    }
}

#[actix_web::test]
async fn an_origin_of_this_machine_in_clear_asks_for_no_transport_security() {
    let (mut product, _storage) = MemoryStorage::wire();
    product.settings = Settings {
        public_origin: PublicOrigin::parse("http://localhost:8080").expect("an origin"),
    };

    let headers = read_headers(product, Method::GET, "/nowhere").await;

    assert_eq!(find(&headers, "x-frame-options"), Some("DENY"));
    assert_eq!(find(&headers, "strict-transport-security"), None);
}
