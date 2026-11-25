use actix_web::http::{Method, StatusCode};
use saffui_core::authz::capability::Capability;
use serde_json::{Value, json};

use super::admin::{Answer, call, start};

const REGISTER: &str = "/realms/acme/oauth2/register";
const SETTINGS: &str = "/admin/v1/realms/acme/settings";
const TOKENS: &str = "/admin/v1/realms/acme/initial-access-tokens";

fn send<'a>(
    product: &'a saffui_core::app::App,
    method: Method,
    path: &'a str,
    token: Option<&'a str>,
    body: Option<&'a Value>,
) -> impl Future<Output = Answer> + 'a {
    let body = body.map(Value::to_string);
    async move { call(product, method, path, token, body.as_deref()).await }
}

fn assert_never_kept(answer: &Answer) {
    assert_eq!(
        answer.caching,
        (Some("no-store".to_owned()), Some("no-cache".to_owned())),
        "{}",
        answer.body
    );
}

#[actix_web::test]
async fn a_closed_realm_refuses_in_the_words_of_registration_and_no_cache_keeps_it() {
    let (product, _token) = start(&[Capability::RealmRead]).await;

    let refused = send(
        &product,
        Method::POST,
        REGISTER,
        None,
        Some(&json!({ "redirect_uris": ["https://app.example.org/cb"] })),
    )
    .await;

    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_never_kept(&refused);
    assert_eq!(refused.body["error"], "access_denied");
    assert!(refused.body["error_description"].is_string());
    let discovered = send(
        &product,
        Method::GET,
        "/realms/acme/.well-known/openid-configuration",
        None,
        None,
    )
    .await;
    assert!(discovered.body.get("registration_endpoint").is_none());
}

#[actix_web::test]
async fn an_open_realm_registers_a_client_and_manages_it_with_a_token_that_serves_once() {
    let (product, operator) = start(&[Capability::RealmWrite, Capability::UserRead]).await;
    let opened = send(
        &product,
        Method::PUT,
        "/admin/v1/realms/acme/settings/registration",
        Some(&operator),
        Some(&json!({ "registration": "open" })),
    )
    .await;
    assert_eq!(opened.status, StatusCode::OK, "{}", opened.body);
    assert_eq!(
        opened.body,
        json!({
            "registration": "open",
            "registrable_scopes": ["openid", "profile", "email"],
            "max_registered_clients": 100,
            "max_redirect_uris": 5,
            "max_daily_registrations": 100,
        })
    );
    let discovered = send(
        &product,
        Method::GET,
        "/realms/acme/.well-known/openid-configuration",
        None,
        None,
    )
    .await;
    assert_eq!(
        discovered.body["registration_endpoint"],
        "https://id.example.test/realms/acme/oauth2/register"
    );

    let registered = send(
        &product,
        Method::POST,
        REGISTER,
        None,
        Some(&json!({ "redirect_uris": ["https://app.example.org/cb"], "client_name": "App" })),
    )
    .await;
    assert_eq!(
        registered.status,
        StatusCode::CREATED,
        "{}",
        registered.body
    );
    assert_never_kept(&registered);
    let client_id = registered.body["client_id"]
        .as_str()
        .expect("an identifier");
    let managed_at = format!("{REGISTER}/{client_id}");
    assert_eq!(
        registered.body["registration_client_uri"],
        format!("https://id.example.test{managed_at}")
    );
    let first = registered.body["registration_access_token"]
        .as_str()
        .expect("a token");

    let read = send(&product, Method::GET, &managed_at, Some(first), None).await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.body);
    assert_never_kept(&read);
    let second = read.body["registration_access_token"]
        .as_str()
        .expect("the next token");
    let again = send(&product, Method::GET, &managed_at, Some(first), None).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        again.challenge.as_deref(),
        Some("Bearer error=\"invalid_token\"")
    );
    assert_eq!(again.body["error"], "invalid_token");
    let unknown = send(
        &product,
        Method::GET,
        &format!("{REGISTER}/nobody"),
        Some(second),
        None,
    )
    .await;
    assert_eq!(
        (unknown.status, &unknown.body),
        (again.status, &again.body),
        "an unknown client answers as a wrong token"
    );
    let without = send(&product, Method::GET, &managed_at, None, None).await;
    assert_eq!(without.status, StatusCode::UNAUTHORIZED);

    let updated = send(
        &product,
        Method::PUT,
        &managed_at,
        Some(second),
        Some(&json!({
            "client_id": client_id,
            "redirect_uris": ["https://app.example.org/other"],
            "client_name": "Renamed",
        })),
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.body);
    assert_never_kept(&updated);
    assert_eq!(updated.body["client_name"], "Renamed");
    let third = updated.body["registration_access_token"]
        .as_str()
        .expect("the next token");

    let deleted = send(&product, Method::DELETE, &managed_at, Some(third), None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_never_kept(&deleted);
    let gone = send(&product, Method::DELETE, &managed_at, Some(third), None).await;
    assert_eq!(gone.status, StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn a_client_that_registers_itself_is_refused_how_it_would_sign_its_requests() {
    let (product, operator) = start(&[Capability::RealmWrite, Capability::UserRead]).await;
    let opened = send(
        &product,
        Method::PUT,
        "/admin/v1/realms/acme/settings/registration",
        Some(&operator),
        Some(&json!({ "registration": "open" })),
    )
    .await;
    assert_eq!(opened.status, StatusCode::OK, "{}", opened.body);

    for (member, value) in [
        ("request_object_signing_alg", json!("RS256")),
        ("require_signed_request_object", json!(true)),
    ] {
        let mut metadata = json!({ "redirect_uris": ["https://app.example.org/cb"] });
        metadata[member] = value;
        let refused = send(&product, Method::POST, REGISTER, None, Some(&metadata)).await;

        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{member}");
        assert_eq!(refused.body["error"], "invalid_client_metadata", "{member}");
    }
}

#[actix_web::test]
async fn a_body_past_its_limit_or_that_is_not_json_is_metadata_that_cannot_be_read() {
    let (product, operator) = start(&[Capability::RealmWrite, Capability::UserRead]).await;
    send(
        &product,
        Method::PUT,
        "/admin/v1/realms/acme/settings/registration",
        Some(&operator),
        Some(&json!({ "registration": "open" })),
    )
    .await;
    // Past the limit by a member this version passes over: whole, the
    // metadata would be honored.
    let long = json!({
        "redirect_uris": ["https://app.example.org/cb"],
        "a_member_from_later": "x".repeat(32 * 1024),
    });

    for body in [long.to_string(), "not JSON".to_owned()] {
        let refused = call(&product, Method::POST, REGISTER, None, Some(&body)).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
        assert_never_kept(&refused);
        assert_eq!(refused.body["error"], "invalid_client_metadata");
    }
    let refused = send(
        &product,
        Method::POST,
        REGISTER,
        None,
        Some(&json!({ "redirect_uris": ["https://app.example.org/cb"], "software_statement": "e30" })),
    )
    .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.body["error"], "invalid_software_statement");
}

#[actix_web::test]
async fn the_settings_are_read_under_realm_read_and_written_under_realm_write() {
    let (product, reader) = start(&[Capability::RealmRead]).await;

    let read = send(&product, Method::GET, SETTINGS, Some(&reader), None).await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.body);
    assert_eq!(read.body["registration"], "closed");
    for (method, path, body) in [
        (
            Method::PUT,
            "/admin/v1/realms/acme/settings/registration",
            Some(json!({ "registration": "open" })),
        ),
        (Method::GET, TOKENS, None),
        (
            Method::POST,
            TOKENS,
            Some(json!({ "uses": 1, "expires_in": 60 })),
        ),
    ] {
        let refused = send(&product, method, path, Some(&reader), body.as_ref()).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(refused.body["code"], "auth.capability_missing");
    }
}

#[actix_web::test]
async fn an_initial_token_is_shown_once_listed_without_it_and_taken_back() {
    let (product, operator) = start(&[Capability::RealmWrite]).await;
    let refused = send(
        &product,
        Method::PUT,
        "/admin/v1/realms/acme/settings/registration",
        Some(&operator),
        Some(&json!({ "registration": "wide" })),
    )
    .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.body["code"], "realm.settings_invalid");

    let made = send(
        &product,
        Method::POST,
        TOKENS,
        Some(&operator),
        Some(&json!({ "uses": 2, "expires_in": 3600 })),
    )
    .await;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
    assert_never_kept(&made);
    let token = made.body["initial_access_token"]
        .as_str()
        .expect("the token, shown once");
    let id = made.body["id"].as_str().expect("an identifier");
    assert_eq!(made.body["uses_left"], 2);

    let listed = send(&product, Method::GET, TOKENS, Some(&operator), None).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    assert_eq!(listed.body["items"][0]["id"], id);
    assert!(!listed.body.to_string().contains(token), "{}", listed.body);

    let path = format!("{TOKENS}/{id}");
    let removed = send(&product, Method::DELETE, &path, Some(&operator), None).await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let gone = send(&product, Method::DELETE, &path, Some(&operator), None).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    assert_eq!(gone.body["code"], "client.initial_token_not_found");
    let malformed = send(
        &product,
        Method::DELETE,
        &format!("{TOKENS}/not-an-id"),
        Some(&operator),
        None,
    )
    .await;
    assert_eq!(malformed.status, StatusCode::NOT_FOUND);
}

/// Sends `body` to `path` from `peer`, saying it is of `content_type`.
async fn send_typed(
    product: &saffui_core::app::App,
    method: Method,
    path: &str,
    token: Option<&str>,
    content_type: &str,
    body: &str,
) -> StatusCode {
    use actix_web::http::header::{AUTHORIZATION, CONTENT_TYPE};
    use actix_web::{App, test, web};
    use server::api::config::register_data_plane;

    let app = test::init_service(
        App::new().configure(register_data_plane(web::Data::new(product.clone()))),
    )
    .await;
    let mut request = test::TestRequest::default()
        .method(method)
        .uri(path)
        .peer_addr("203.0.113.7:4000".parse().expect("an address"))
        .insert_header((CONTENT_TYPE, content_type))
        .set_payload(body.to_owned());
    if let Some(token) = token {
        request = request.insert_header((AUTHORIZATION, format!("Bearer {token}")));
    }
    let response = test::call_service(&app, request.to_request()).await;
    response.status()
}

#[actix_web::test]
async fn metadata_that_does_not_say_it_is_json_is_refused_before_it_is_read_or_counted() {
    use saffui_core::login::throttle::MAX_RECENT_REGISTRATIONS_PER_ADDRESS;

    let (product, operator) = start(&[
        Capability::RealmWrite,
        Capability::UserRead,
        Capability::ClientRead,
    ])
    .await;
    send(
        &product,
        Method::PUT,
        "/admin/v1/realms/acme/settings/registration",
        Some(&operator),
        Some(&json!({ "registration": "open" })),
    )
    .await;
    let metadata = json!({ "redirect_uris": ["https://app.example.org/cb"] }).to_string();
    let count_clients = async || {
        send(
            &product,
            Method::GET,
            "/admin/v1/realms/acme/clients",
            Some(&operator),
            None,
        )
        .await
        .body["items"]
            .as_array()
            .map_or(0, Vec::len)
    };
    let before = count_clients().await;

    for content_type in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "application/jsonx",
    ]
    .into_iter()
    .cycle()
    .take(usize::try_from(MAX_RECENT_REGISTRATIONS_PER_ADDRESS + 1).expect("a count"))
    {
        assert_eq!(
            send_typed(
                &product,
                Method::POST,
                REGISTER,
                None,
                content_type,
                &metadata
            )
            .await,
            StatusCode::BAD_REQUEST,
            "{content_type}"
        );
    }
    assert_eq!(count_clients().await, before, "nothing was made");
    assert_eq!(
        send_typed(
            &product,
            Method::POST,
            REGISTER,
            None,
            "application/json",
            &metadata
        )
        .await,
        StatusCode::CREATED,
        "the same address, past its bound had anything been counted"
    );
    let registered = call(&product, Method::POST, REGISTER, None, Some(&metadata)).await;
    assert_eq!(
        registered.status,
        StatusCode::CREATED,
        "{}",
        registered.body
    );
    assert_eq!(
        send_typed(
            &product,
            Method::POST,
            REGISTER,
            None,
            "Application/JSON; charset=utf-8",
            &metadata
        )
        .await,
        StatusCode::CREATED,
        "JSON, however it is spelled"
    );

    let client_id = registered.body["client_id"]
        .as_str()
        .expect("an identifier");
    let token = registered.body["registration_access_token"]
        .as_str()
        .expect("a token");
    let managed_at = format!("{REGISTER}/{client_id}");
    let changed =
        json!({ "client_id": client_id, "redirect_uris": ["https://app.example.org/cb"] });
    assert_eq!(
        send_typed(
            &product,
            Method::PUT,
            &managed_at,
            Some(token),
            "text/plain",
            &changed.to_string()
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    let read = send(&product, Method::GET, &managed_at, Some(token), None).await;
    assert_eq!(read.status, StatusCode::OK, "the token was not spent");
}

#[actix_web::test]
async fn an_administrator_ends_the_registration_of_a_client_that_registered_itself() {
    let (product, operator) = start(&[
        Capability::ClientWrite,
        Capability::RealmWrite,
        Capability::UserRead,
    ])
    .await;
    send(
        &product,
        Method::PUT,
        "/admin/v1/realms/acme/settings/registration",
        Some(&operator),
        Some(&json!({ "registration": "open" })),
    )
    .await;
    let registered = send(
        &product,
        Method::POST,
        REGISTER,
        None,
        Some(&json!({ "redirect_uris": ["https://app.example.org/cb"] })),
    )
    .await;
    let client_id = registered.body["client_id"]
        .as_str()
        .expect("an identifier");
    let ending = format!("/admin/v1/realms/acme/clients/{client_id}/registration");

    let ended = send(&product, Method::DELETE, &ending, Some(&operator), None).await;
    assert_eq!(ended.status, StatusCode::NO_CONTENT, "{}", ended.body);
    for path in [
        ending,
        "/admin/v1/realms/acme/clients/operator/registration".to_owned(),
    ] {
        let refused = send(&product, Method::DELETE, &path, Some(&operator), None).await;
        assert_eq!(refused.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(refused.body["code"], "client.registration_not_found");
    }
    let managed_at = format!("{REGISTER}/{client_id}");
    let token = registered.body["registration_access_token"]
        .as_str()
        .expect("a token");
    assert_eq!(
        send(&product, Method::GET, &managed_at, Some(token), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED,
        "its token ended with it"
    );
}
