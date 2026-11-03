use actix_web::http::header::{AUTHORIZATION, CONTENT_TYPE, WARNING, WWW_AUTHENTICATE};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test, web};
use saffui_core::authz::capability::Capability;
use saffui_core::testkit::fixtures::{create_administrator, create_realm};
use saffui_core::testkit::memory::MemoryStorage;
use serde_json::{Value, json};
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

#[actix_web::test]
async fn a_missing_capability_is_refused_with_403_before_the_body_is_read() {
    let (product, token) = start(&[Capability::ClientRead]).await;
    let path = "/admin/v1/realms/acme/clients";

    // Not JSON at all: a guard that ran after the body would answer 400.
    let refused = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some("{not json"),
    )
    .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.body["code"], "auth.capability_missing");

    let (product, token) = start(&[Capability::ClientWrite]).await;
    let unreadable = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some("{not json"),
    )
    .await;
    assert_eq!(
        unreadable.status,
        StatusCode::BAD_REQUEST,
        "with the capability, the body is read and refused"
    );
    assert_eq!(unreadable.body["code"], "platform.request_invalid");
}

#[actix_web::test]
async fn a_created_client_is_shown_its_secret_once_then_listed_without_it() {
    let (product, token) = start(&[Capability::ClientRead, Capability::ClientWrite]).await;
    let path = "/admin/v1/realms/acme/clients";
    let wanted = json!({ "client_id": "billing", "scopes": ["invoices:read"] }).to_string();

    let created = call(&product, Method::POST, path, Some(&token), Some(&wanted)).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["client"]["client_id"], "billing");
    assert!(
        created.body["client_secret"]
            .as_str()
            .is_some_and(|secret| secret.len() >= 43),
        "256 bits of secret, shown once"
    );

    let again = call(&product, Method::POST, path, Some(&token), Some(&wanted)).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.body["code"], "client.identifier_taken");

    let one = call(
        &product,
        Method::GET,
        &format!("{path}/billing"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(one.status, StatusCode::OK);
    assert_eq!(one.body["scopes"], json!(["invoices:read"]));
    let listed = call(
        &product,
        Method::GET,
        &format!("{path}?count=true"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["total"], 2);
    assert_eq!(listed.body["items"][0]["client_id"], "billing");
    assert_eq!(listed.body["items"][1]["client_id"], "operator");
    assert!(
        !listed.body.to_string().contains("secret"),
        "nothing about a secret is ever listed: {}",
        listed.body
    );

    let missing = call(
        &product,
        Method::GET,
        &format!("{path}/nobody"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.body["code"], "client.not_found");
}

#[actix_web::test]
async fn nobody_grants_a_capability_they_do_not_hold_and_an_unknown_one_does_not_exist() {
    let (product, token) = start(&[Capability::ClientWrite]).await;
    let path = "/admin/v1/realms/acme/clients";
    let ask = |capability: &str| {
        json!({ "client_id": "helper", "capabilities": [capability] }).to_string()
    };

    let escalation = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some(&ask("audit:read")),
    )
    .await;
    assert_eq!(escalation.status, StatusCode::FORBIDDEN);
    assert_eq!(escalation.body["code"], "auth.capability_missing");

    let unknown = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some(&ask("client:*")),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown.body["code"], "client.capability_unknown");

    let held = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some(&ask("client:write")),
    )
    .await;
    assert_eq!(held.status, StatusCode::CREATED, "{}", held.body);

    let extra_field = json!({ "client_id": "other", "is_admin": true }).to_string();
    let refused = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some(&extra_field),
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "an unknown field is not ignored"
    );
}

#[actix_web::test]
async fn a_list_is_cut_to_500_with_a_warning_and_refused_past_an_offset_of_100000() {
    let (product, token) = start(&[Capability::ClientRead]).await;
    let path = "/admin/v1/realms/acme/clients";

    let default = call(&product, Method::GET, path, Some(&token), None).await;
    assert_eq!(
        (default.body["first"].clone(), default.body["max"].clone()),
        (json!(0), json!(100))
    );
    assert!(
        default.body.get("total").is_none(),
        "the count is computed only when asked"
    );
    assert_eq!(default.warning, None);

    let cut = call(
        &product,
        Method::GET,
        &format!("{path}?max=9000"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(cut.status, StatusCode::OK);
    assert_eq!(cut.body["max"], 500);
    assert!(cut.warning.is_some_and(|warning| warning.contains("500")));

    let too_far = call(
        &product,
        Method::GET,
        &format!("{path}?first=100001"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(too_far.status, StatusCode::BAD_REQUEST);
    assert_eq!(too_far.body["code"], "platform.list_offset_too_large");

    let unreadable = call(
        &product,
        Method::GET,
        &format!("{path}?max=many"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(unreadable.status, StatusCode::BAD_REQUEST);
    assert_eq!(unreadable.body["code"], "platform.request_invalid");
}

#[actix_web::test]
async fn an_administrator_creates_a_person_and_lists_them_without_their_password() {
    let (product, token) = start(&[Capability::UserRead, Capability::UserWrite]).await;
    let path = "/admin/v1/realms/acme/users";
    let wanted = json!({
        "username": " Ada ",
        "email": "Ada@Example.org",
        "password": "correct horse battery",
    })
    .to_string();

    let created = call(&product, Method::POST, path, Some(&token), Some(&wanted)).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["username"], "ada");
    assert_eq!(created.body["email"], "ada@example.org");

    let again = call(&product, Method::POST, path, Some(&token), Some(&wanted)).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.body["code"], "user.username_taken");

    let listed = call(
        &product,
        Method::GET,
        &format!("{path}?count=true"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["total"], 1);
    assert_eq!(listed.body["items"][0]["username"], "ada");
    let told = listed.body.to_string();
    assert!(
        !told.contains("password") && !told.contains("correct horse"),
        "nothing about a password is ever listed: {told}"
    );
}

#[actix_web::test]
async fn an_administrator_unlocks_a_person_by_name_and_a_reader_may_not() {
    let (product, token) = start(&[Capability::UserWrite]).await;
    let wanted = json!({ "username": "ada", "password": "correct horse battery" }).to_string();
    let created = call(
        &product,
        Method::POST,
        "/admin/v1/realms/acme/users",
        Some(&token),
        Some(&wanted),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);

    let unlocked = call(
        &product,
        Method::POST,
        "/admin/v1/realms/acme/users/ada/unlock",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(unlocked.status, StatusCode::NO_CONTENT, "{}", unlocked.body);
    let unknown = call(
        &product,
        Method::POST,
        "/admin/v1/realms/acme/users/nobody/unlock",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.body["code"], "user.not_found");

    let (product, token) = start(&[Capability::UserRead]).await;
    let refused = call(
        &product,
        Method::POST,
        "/admin/v1/realms/acme/users/ada/unlock",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn reading_people_does_not_let_one_create_them_and_a_field_nobody_reads_is_refused() {
    let (product, token) = start(&[Capability::UserRead]).await;
    let path = "/admin/v1/realms/acme/users";
    let wanted = json!({ "username": "ada" }).to_string();

    let refused = call(&product, Method::POST, path, Some(&token), Some(&wanted)).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);

    let (product, token) = start(&[Capability::UserWrite]).await;
    let more = json!({ "username": "ada", "is_admin": true }).to_string();
    let unread = call(&product, Method::POST, path, Some(&token), Some(&more)).await;
    assert_eq!(unread.status, StatusCode::BAD_REQUEST, "{}", unread.body);
    let short = json!({ "username": "ada", "password": "short" }).to_string();
    let weak = call(&product, Method::POST, path, Some(&token), Some(&short)).await;
    assert_eq!(weak.status, StatusCode::BAD_REQUEST);
    assert_eq!(weak.body["code"], "user.password_unacceptable");
}

#[actix_web::test]
async fn an_administrator_registers_an_application_that_holds_no_secret_and_no_capability() {
    let (product, token) = start(&[Capability::ClientRead, Capability::ClientWrite]).await;
    let path = "/admin/v1/realms/acme/clients";
    let wanted = json!({
        "client_id": "webapp",
        "scopes": ["openid"],
        "redirect_uris": ["https://app.example.org/callback"],
        "public": true,
    })
    .to_string();

    let created = call(&product, Method::POST, path, Some(&token), Some(&wanted)).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["client"]["public"], true);
    assert_eq!(
        created.body["client"]["redirect_uris"],
        json!(["https://app.example.org/callback"])
    );
    assert!(
        created.body.get("client_secret").is_none(),
        "a public application is given no secret: {}",
        created.body
    );

    let lending = json!({
        "client_id": "portal",
        "redirect_uris": ["https://portal.example.org/callback"],
        "capabilities": ["client:read"],
    })
    .to_string();
    let refused = call(&product, Method::POST, path, Some(&token), Some(&lending)).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
}
