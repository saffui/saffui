use actix_web::http::StatusCode;
use actix_web::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE};
use actix_web::{App, test, web};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use saffui_core::clients::ClientAuthMethod;
use saffui_core::ports::storage::StorageUnavailable;
use saffui_core::secret::Secret;
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

/// Registers in `acme` a service that proves itself by `method`, and
/// returns the secret it was shown.
async fn register_service(
    product: &saffui_core::app::App,
    client_id: &str,
    method: ClientAuthMethod,
) -> String {
    use saffui_core::clients::register::NewClient;
    use saffui_core::tenancy::resolve::resolve_realm;
    use saffui_core::testkit::fixtures::check_and_register_client;

    let scope = resolve_realm(product, "acme").await.expect("the realm").1;
    let scopes = ["invoices:read".to_owned()];
    let mut work = product.storage.begin(scope).await.expect("a unit of work");
    let (_client, secret) = check_and_register_client(
        product,
        work.as_mut(),
        NewClient {
            client_id,
            name: client_id,
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &[],
            post_logout_redirect_uris: &[],
            response_types: &[],
            public: false,
            requires_consent: false,
            id_token_signed_response_alg: None,
            auth_method: Some(method),
            jwks: None,
            jwks_uri: None,
            auth_signing_alg: None,
            created_by: None,
        },
    )
    .await
    .expect("a client");
    work.commit().await.expect("a commit");
    String::from_utf8(secret.expect("a secret").expose().to_vec()).expect("a printable secret")
}

#[actix_web::test]
async fn a_secret_is_read_where_its_client_registered_it_and_nowhere_else() {
    let (product, _storage, secret) = start().await;
    let posted = register_service(&product, "poster", ClientAuthMethod::ClientSecretPost).await;
    let in_form = |client_id, secret| {
        format!("grant_type=client_credentials&client_id={client_id}&client_secret={secret}")
    };

    let poster_in_form = post_form(&product, TOKEN, None, &in_form("poster", &posted)).await;
    let billing_in_form = post_form(&product, TOKEN, None, &in_form("billing", &secret)).await;
    let poster_in_basic = post_form(
        &product,
        TOKEN,
        Some(("poster", &posted)),
        "grant_type=client_credentials",
    )
    .await;

    assert_eq!(
        poster_in_form.status,
        StatusCode::OK,
        "{}",
        poster_in_form.body
    );
    for (refused, why) in [
        (&billing_in_form, "registered for the Basic scheme"),
        (&poster_in_basic, "registered for the form"),
    ] {
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{why}");
        assert_eq!(refused.body["error"], "invalid_client", "{why}");
    }
}

/// An assertion of `client_id` signed with its secret, as its form carries it.
fn write_assertion(
    product: &saffui_core::app::App,
    client_id: &str,
    secret: &str,
    jti: &str,
) -> String {
    let claims = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": "https://id.example.test/realms/acme",
        "jti": jti,
        "exp": product.now().unix_timestamp() + 60,
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let mac = product
        .digester
        .hmac_sha256(&Secret::new(secret.as_bytes().to_vec()), input.as_bytes())
        .expect("a mac");
    format!(
        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer\
         &client_assertion={input}.{}",
        URL_SAFE_NO_PAD.encode(mac)
    )
}

#[actix_web::test]
async fn an_assertion_in_the_form_proves_its_client_at_the_token_and_introspection_endpoints_once()
{
    let (product, _storage, _secret) = start().await;
    let secret = register_service(&product, "signer", ClientAuthMethod::ClientSecretJwt).await;
    let first = write_assertion(&product, "signer", &secret, "a-1");

    let granted = post_form(
        &product,
        TOKEN,
        None,
        &format!("grant_type=client_credentials&{first}"),
    )
    .await;
    let replayed = post_form(
        &product,
        TOKEN,
        None,
        &format!("grant_type=client_credentials&{first}"),
    )
    .await;
    let token = granted.body["access_token"].as_str().expect("a token");
    let told = post_form(
        &product,
        "/realms/acme/oauth2/introspect",
        None,
        &format!(
            "token={token}&{}",
            write_assertion(&product, "signer", &secret, "a-2")
        ),
    )
    .await;
    let beside_a_secret = post_form(
        &product,
        TOKEN,
        Some(("signer", &secret)),
        &format!(
            "grant_type=client_credentials&{}",
            write_assertion(&product, "signer", &secret, "a-3")
        ),
    )
    .await;

    assert_eq!(granted.status, StatusCode::OK, "{}", granted.body);
    assert_eq!(replayed.status, StatusCode::UNAUTHORIZED);
    assert_eq!(replayed.body["error"], "invalid_client");
    assert_eq!(told.status, StatusCode::OK, "{}", told.body);
    assert_eq!(told.body["active"], true);
    assert_eq!(beside_a_secret.status, StatusCode::BAD_REQUEST);
    assert_eq!(beside_a_secret.body["error"], "invalid_request");
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
    assert_eq!(header["alg"], "ES256");
    let signing = key_set["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|key| key["kid"] == header["kid"]))
        .expect("the key that signed is published");
    assert_eq!(signing["alg"], "ES256");
    assert_eq!(signing["use"], "sig");
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
