use actix_web::http::StatusCode;
use actix_web::{App, test, web};
use saffui_core::tenancy::realm::{NewRealm, provision_first_realm};
use saffui_core::testkit::memory::MemoryStorage;
use serde_json::{Value, json};
use server::api::config::register_data_plane;

async fn get_json(product: saffui_core::app::App, path: &str) -> (StatusCode, Value) {
    let app =
        test::init_service(App::new().configure(register_data_plane(web::Data::new(product))))
            .await;
    let response = test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

#[actix_web::test]
async fn a_realm_publishes_the_public_half_of_its_keys() {
    let (product, _storage) = MemoryStorage::wire();
    provision_first_realm(
        &product,
        NewRealm {
            tenant_name: "Acme",
            realm_name: "acme",
        },
    )
    .await
    .expect("a realm");

    let (status, key_set) = get_json(product, "/realms/acme/oauth2/jwks").await;

    assert_eq!(status, StatusCode::OK);
    let keys = key_set["keys"].as_array().expect("a list of keys");
    let algorithms: Vec<&Value> = keys.iter().map(|key| &key["alg"]).collect();
    assert_eq!(algorithms, ["ES256", "RS256"]);
    for key in keys {
        assert_eq!(key["use"], "sig");
        assert!(key["kid"].is_string());
    }
}

#[actix_web::test]
async fn an_unknown_realm_has_no_keys_to_show() {
    let (product, _storage) = MemoryStorage::wire();

    let (status, body) = get_json(product, "/realms/nobody/oauth2/jwks").await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        body,
        json!({
            "code": "realm.not_found",
            "error_code": 100,
            "message": "No such realm.",
        })
    );
}
