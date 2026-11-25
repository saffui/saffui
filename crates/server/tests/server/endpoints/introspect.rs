use actix_web::http::StatusCode;
use actix_web::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use actix_web::{App, test, web};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use saffui_core::testkit::fixtures::{create_realm, create_service_client};
use saffui_core::testkit::memory::MemoryStorage;
use serde_json::Value;
use server::api::config::register_data_plane;

struct Answer {
    status: StatusCode,
    cache_control: Option<String>,
    body: String,
}

impl Answer {
    fn read_json(&self) -> Value {
        serde_json::from_str(&self.body).expect("JSON")
    }
}

async fn post_form(
    product: &saffui_core::app::App,
    path: &str,
    basic: Option<(&str, &str)>,
    form: &str,
) -> Answer {
    let app = test::init_service(
        App::new().configure(register_data_plane(web::Data::new(product.clone()))),
    )
    .await;
    let mut request = test::TestRequest::post()
        .uri(path)
        .insert_header((CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(form.to_owned());
    if let Some((client_id, secret)) = basic {
        let credentials = STANDARD.encode(format!("{client_id}:{secret}"));
        request = request.insert_header((AUTHORIZATION, format!("Basic {credentials}")));
    }
    let response = test::call_service(&app, request.to_request()).await;
    let cache_control = response
        .headers()
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let status = response.status();
    let body = test::read_body(response).await;
    Answer {
        status,
        cache_control,
        body: String::from_utf8(body.to_vec()).expect("text"),
    }
}

#[actix_web::test]
async fn a_service_learns_what_a_token_says_and_cannot_take_an_access_token_back() {
    let (product, _storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    let secret = create_service_client(&product, scope, "billing", &["invoices:read"]).await;
    let secret = String::from_utf8(secret.expose().to_vec()).expect("a printable secret");
    let basic = Some(("billing", secret.as_str()));
    let granted = post_form(
        &product,
        "/realms/acme/oauth2/token",
        basic,
        "grant_type=client_credentials",
    )
    .await;
    let access_token = granted.read_json()["access_token"]
        .as_str()
        .expect("a token")
        .to_owned();

    let told = post_form(
        &product,
        "/realms/acme/oauth2/introspect",
        basic,
        &format!("token={access_token}"),
    )
    .await;
    assert_eq!(told.status, StatusCode::OK, "{}", told.body);
    assert_eq!(told.cache_control.as_deref(), Some("no-store"));
    let told = told.read_json();
    assert_eq!(told["active"], true);
    assert_eq!(told["client_id"], "billing");
    assert_eq!(told["token_type"], "Bearer");

    let unknown = post_form(
        &product,
        "/realms/acme/oauth2/introspect",
        basic,
        "token=not-a-token",
    )
    .await;
    assert_eq!(unknown.body, r#"{"active":false}"#);
    let anonymous = post_form(
        &product,
        "/realms/acme/oauth2/introspect",
        None,
        &format!("token={access_token}"),
    )
    .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(anonymous.read_json()["error"], "invalid_client");

    let kept = post_form(
        &product,
        "/realms/acme/oauth2/revoke",
        basic,
        &format!("token={access_token}"),
    )
    .await;
    assert_eq!(kept.status, StatusCode::BAD_REQUEST);
    assert_eq!(kept.read_json()["error"], "unsupported_token_type");
    let nothing = post_form(
        &product,
        "/realms/acme/oauth2/revoke",
        basic,
        "token=not-a-token",
    )
    .await;
    assert_eq!(nothing.status, StatusCode::OK);
    assert_eq!(nothing.cache_control.as_deref(), Some("no-store"));
    assert!(nothing.body.is_empty());
}
