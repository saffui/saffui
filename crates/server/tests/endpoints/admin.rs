use actix_web::http::header::{AUTHORIZATION, CONTENT_TYPE, WARNING, WWW_AUTHENTICATE};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test, web};
use saffui_core::authz::capability::Capability;
use saffui_core::testkit::fixtures::{create_administrator, create_realm};
use saffui_core::testkit::memory::MemoryStorage;
use serde_json::Value;
use server::api::config::register_data_plane;

pub(crate) struct Answer {
    pub(crate) status: StatusCode,
    pub(crate) challenge: Option<String>,
    pub(crate) warning: Option<String>,
    pub(crate) body: Value,
}

pub(crate) async fn call(
    product: &saffui_core::app::App,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> Answer {
    let app = test::init_service(
        App::new().configure(register_data_plane(web::Data::new(product.clone()))),
    )
    .await;
    let mut request = test::TestRequest::default().method(method).uri(path);
    if let Some(token) = token {
        request = request.insert_header((AUTHORIZATION, format!("Bearer {token}")));
    }
    if let Some(body) = body {
        request = request
            .insert_header((CONTENT_TYPE, "application/json"))
            .set_payload(body.to_owned());
    }
    let response = test::call_service(&app, request.to_request()).await;
    let read = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let (status, challenge, warning) = (response.status(), read(WWW_AUTHENTICATE), read(WARNING));
    let bytes = test::read_body(response).await;
    Answer {
        status,
        challenge,
        warning,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

/// The realm `acme` and a token of a client granted `capabilities` in it.
pub(crate) async fn start(capabilities: &[Capability]) -> (saffui_core::app::App, String) {
    let (product, _storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    let token = create_administrator(&product, "acme", scope, "operator", capabilities).await;
    (product, token)
}

#[actix_web::test]
async fn an_administrator_reads_its_realm() {
    let (product, token) = start(&[Capability::RealmRead]).await;

    let answer = call(
        &product,
        Method::GET,
        "/admin/v1/realms/acme",
        Some(&token),
        None,
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.body["name"], "acme");
    assert_eq!(answer.body["issuer"], "https://id.example.test/realms/acme");
    assert_eq!(answer.body["enabled"], true);
}

#[actix_web::test]
async fn a_call_without_a_token_or_with_a_broken_one_is_challenged_with_401() {
    let (product, _token) = start(&Capability::ALL).await;

    for token in [None, Some("not.a.token")] {
        let answer = call(&product, Method::GET, "/admin/v1/realms/acme", token, None).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        assert_eq!(answer.challenge.as_deref(), Some("Bearer"));
        assert_eq!(answer.body["code"], "auth.admin_authentication_failed");
    }
}

#[actix_web::test]
async fn a_token_reaches_only_the_realm_that_minted_it_and_an_unknown_realm_answers_the_same() {
    let (product, token) = start(&Capability::ALL).await;
    let globex = create_realm(&product, "globex").await;
    create_administrator(&product, "globex", globex, "operator", &Capability::ALL).await;

    for realm in ["globex", "nowhere"] {
        let path = format!("/admin/v1/realms/{realm}");
        let answer = call(&product, Method::GET, &path, Some(&token), None).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(
            answer.body["code"], "auth.admin_authentication_failed",
            "{path}"
        );
    }
}

#[actix_web::test]
async fn a_capability_the_route_does_not_require_opens_nothing() {
    let (product, token) = start(&[Capability::AuditRead]).await;

    let answer = call(
        &product,
        Method::GET,
        "/admin/v1/realms/acme",
        Some(&token),
        None,
    )
    .await;

    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.body["code"], "auth.capability_missing");
    assert_eq!(
        answer.challenge, None,
        "a forbidden caller is not challenged"
    );
}

#[actix_web::test]
async fn an_administrator_asks_whether_the_audit_chain_of_its_realm_is_whole() {
    let (product, token) = start(&[Capability::AuditRead]).await;

    let answer = call(
        &product,
        Method::GET,
        "/admin/v1/realms/acme/audit/verification",
        Some(&token),
        None,
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body["intact"], true);
    // The realm, its key, the administrator, and the token it was given.
    assert_eq!(answer.body["events"], 4);
    assert!(answer.warning.is_none());
}
