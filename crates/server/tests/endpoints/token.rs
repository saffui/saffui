use actix_web::http::StatusCode;
use actix_web::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE};
use actix_web::{App, test, web};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use saffui_core::ports::storage::StorageUnavailable;
use saffui_core::testkit::fixtures::{create_realm, create_service_client};
use saffui_core::testkit::memory::MemoryStorage;
use serde_json::Value;
use server::api::config::register_data_plane;

const TOKEN: &str = "/realms/acme/oauth2/token";

struct Answer {
    status: StatusCode,
    cache_control: Option<String>,
    challenge: Option<String>,
    body: Value,
}

/// A realm `acme` with a service client `billing`, and its secret.
async fn start() -> (saffui_core::app::App, std::sync::Arc<MemoryStorage>, String) {
    let (product, storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    let secret = create_service_client(&product, scope, "billing", &["invoices:read"]).await;
    let secret = String::from_utf8(secret.expose().to_vec()).expect("a printable secret");
    (product, storage, secret)
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
    let read = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    Answer {
        status: response.status(),
        cache_control: read(CACHE_CONTROL),
        challenge: read(WWW_AUTHENTICATE),
        body: test::read_body_json(response).await,
    }
}

#[actix_web::test]
async fn a_service_gets_a_token_with_the_basic_scheme_and_no_cache_may_keep_it() {
    let (product, _storage, secret) = start().await;

    let answer = post_form(
        &product,
        TOKEN,
        Some(("billing", &secret)),
        "grant_type=client_credentials",
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.cache_control.as_deref(), Some("no-store"));
    assert_eq!(answer.body["token_type"], "Bearer");
    assert_eq!(answer.body["expires_in"], 300);
    assert_eq!(answer.body["scope"], "invoices:read");
    assert_eq!(
        answer.body["access_token"]
            .as_str()
            .map(|token| token.split('.').count()),
        Some(3),
        "a compact signed token"
    );
}

#[actix_web::test]
async fn a_service_gets_a_token_with_its_credentials_in_the_form() {
    let (product, _storage, secret) = start().await;

    let form = format!("grant_type=client_credentials&client_id=billing&client_secret={secret}");
    let answer = post_form(&product, TOKEN, None, &form).await;

    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
}

#[actix_web::test]
async fn the_token_is_signed_by_the_key_the_realm_publishes() {
    let (product, _storage, secret) = start().await;
    let answer = post_form(
        &product,
        TOKEN,
        Some(("billing", &secret)),
        "grant_type=client_credentials",
    )
    .await;
    let header = answer.body["access_token"]
        .as_str()
        .and_then(|token| token.split('.').next())
        .and_then(|header| URL_SAFE_NO_PAD.decode(header).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .expect("a token header");

    let app = test::init_service(
        App::new().configure(register_data_plane(web::Data::new(product.clone()))),
    )
    .await;
    let request = test::TestRequest::get()
        .uri("/realms/acme/oauth2/jwks")
        .to_request();
    let key_set: Value = test::call_and_read_body_json(&app, request).await;

    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(key_set["keys"].as_array().map(Vec::len), Some(1));
    assert_eq!(key_set["keys"][0]["kid"], header["kid"]);
    assert_eq!(key_set["keys"][0]["use"], "sig");
}

#[actix_web::test]
async fn a_wrong_secret_is_refused_with_401_and_challenged_only_when_basic_was_used() {
    let (product, _storage, _secret) = start().await;

    let with_basic = post_form(
        &product,
        TOKEN,
        Some(("billing", "wrong")),
        "grant_type=client_credentials",
    )
    .await;
    let in_form = post_form(
        &product,
        TOKEN,
        None,
        "grant_type=client_credentials&client_id=billing&client_secret=wrong",
    )
    .await;

    for answer in [&with_basic, &in_form] {
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        assert_eq!(answer.body["error"], "invalid_client");
        assert_eq!(
            answer.cache_control.as_deref(),
            Some("no-store"),
            "a refusal is not cached either"
        );
    }
    assert_eq!(with_basic.challenge.as_deref(), Some("Basic"));
    assert_eq!(in_form.challenge, None);
}

#[actix_web::test]
async fn an_unknown_realm_answers_as_an_unknown_client() {
    let (product, _storage, secret) = start().await;

    let answer = post_form(
        &product,
        "/realms/nowhere/oauth2/token",
        Some(("billing", &secret)),
        "grant_type=client_credentials",
    )
    .await;

    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.body["error"], "invalid_client");
}

#[actix_web::test]
async fn credentials_given_twice_a_repeated_parameter_and_a_form_too_large_are_invalid_requests() {
    let (product, _storage, secret) = start().await;
    let both = format!("grant_type=client_credentials&client_id=billing&client_secret={secret}");
    let repeated = "grant_type=client_credentials&grant_type=client_credentials";
    let too_large = format!("grant_type=client_credentials&scope={}", "a".repeat(9000));

    for form in [both.as_str(), repeated, too_large.as_str()] {
        let answer = post_form(&product, TOKEN, Some(("billing", &secret)), form).await;
        assert_eq!(
            answer.status,
            StatusCode::BAD_REQUEST,
            "{}",
            &form[..form.len().min(60)]
        );
        assert_eq!(answer.body["error"], "invalid_request");
        assert_eq!(answer.cache_control.as_deref(), Some("no-store"));
    }
}

#[actix_web::test]
async fn a_grant_that_is_not_served_and_a_scope_that_is_not_allowed_say_which() {
    let (product, _storage, secret) = start().await;
    let basic = Some(("billing", secret.as_str()));

    let unsupported = post_form(&product, TOKEN, basic, "grant_type=password").await;
    assert_eq!(unsupported.status, StatusCode::BAD_REQUEST);
    assert_eq!(unsupported.body["error"], "unsupported_grant_type");

    let scope = post_form(
        &product,
        TOKEN,
        basic,
        "grant_type=client_credentials&scope=admin",
    )
    .await;
    assert_eq!(scope.status, StatusCode::BAD_REQUEST);
    assert_eq!(scope.body["error"], "invalid_scope");
}

#[actix_web::test]
async fn a_storage_that_is_down_is_temporarily_unavailable_and_not_the_clients_fault() {
    let (product, storage, secret) = start().await;
    storage.fail_with(StorageUnavailable::PoolExhausted);

    let answer = post_form(
        &product,
        TOKEN,
        Some(("billing", &secret)),
        "grant_type=client_credentials",
    )
    .await;

    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(answer.body["error"], "temporarily_unavailable");
}
