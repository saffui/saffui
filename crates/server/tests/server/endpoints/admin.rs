use actix_web::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, PRAGMA, WARNING, WWW_AUTHENTICATE,
};
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
    /// What a cache is told of the answer: `Cache-Control`, then `Pragma`.
    pub(crate) caching: (Option<String>, Option<String>),
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
    let caching = (read(CACHE_CONTROL), read(PRAGMA));
    let bytes = test::read_body(response).await;
    Answer {
        status,
        challenge,
        warning,
        caching,
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
    // The realm, its two keys, the administrator, and the token it was given.
    assert_eq!(answer.body["events"], 5);
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
    assert_eq!(
        created.caching,
        (Some("no-store".to_owned()), Some("no-cache".to_owned())),
        "the one showing of a secret is kept by no cache"
    );
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
    let secret = created.body["client_secret"].as_str().expect("a secret");
    let names_a_secret = listed.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .flat_map(|item| item.as_object().expect("an object").keys())
        .any(|name| name.contains("secret") || name.contains("digest"));
    assert!(
        !names_a_secret && !listed.body.to_string().contains(secret),
        "nothing about a secret is ever listed: {}",
        listed.body
    );
    assert_eq!(
        listed.body["items"][0]["token_endpoint_auth_method"],
        "client_secret_basic"
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

#[actix_web::test]
async fn an_administrator_names_where_an_application_is_loaded_at_a_sign_out_and_reads_it_back() {
    let (product, token) = start(&[Capability::ClientRead, Capability::ClientWrite]).await;
    let path = "/admin/v1/realms/acme/clients";
    let address = "https://app.example.org/signed-out?from=idp";
    let wanted = json!({
        "client_id": "webapp",
        "scopes": ["openid"],
        "redirect_uris": ["https://app.example.org/callback"],
        "frontchannel_logout_uri": address,
    })
    .to_string();

    let created = call(&product, Method::POST, path, Some(&token), Some(&wanted)).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["client"]["frontchannel_logout_uri"], address);
    let read = call(
        &product,
        Method::GET,
        &format!("{path}/webapp"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(
        read.body["frontchannel_logout_uri"], address,
        "{}",
        read.body
    );

    for (refused, why) in [
        (
            json!({
                "client_id": "elsewhere",
                "redirect_uris": ["https://app.example.org/callback"],
                "frontchannel_logout_uri": "https://elsewhere.example.org/out",
            }),
            "on no origin it sends people back to",
        ),
        (
            json!({
                "client_id": "billing",
                "scopes": ["invoices:read"],
                "frontchannel_logout_uri": "https://app.example.org/out",
            }),
            "a service has no session to be told of",
        ),
        (
            json!({
                "client_id": "flagged",
                "redirect_uris": ["https://app.example.org/callback"],
                "frontchannel_logout_session_required": true,
            }),
            "a field this version does not read",
        ),
    ] {
        let answer = call(
            &product,
            Method::POST,
            path,
            Some(&token),
            Some(&refused.to_string()),
        )
        .await;
        assert_eq!(
            answer.status,
            StatusCode::BAD_REQUEST,
            "{why}: {}",
            answer.body
        );
    }
    let plain = json!({
        "client_id": "plain",
        "redirect_uris": ["https://app.example.org/callback"],
    })
    .to_string();
    let created = call(&product, Method::POST, path, Some(&token), Some(&plain)).await;
    assert_eq!(
        created.body["client"]["frontchannel_logout_uri"],
        Value::Null,
        "{}",
        created.body
    );
}

#[actix_web::test]
async fn an_administrator_turns_a_secret_over_and_the_old_one_proves_nothing_from_then_on() {
    use saffui_core::clients::authenticate::PresentedSecret;
    use saffui_core::oidc::token::{TokenRequest, grant_token};
    use saffui_core::secret::Secret;

    let (product, token) = start(&[Capability::ClientRead, Capability::ClientWrite]).await;
    let path = "/admin/v1/realms/acme/clients";
    let created = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some(&json!({ "client_id": "billing", "scopes": ["invoices:read"] }).to_string()),
    )
    .await;
    let old = created.body["client_secret"]
        .as_str()
        .expect("a secret")
        .to_owned();
    let application = json!({
        "client_id": "webapp",
        "redirect_uris": ["https://app.example.org/callback"],
        "public": true,
    });
    call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some(&application.to_string()),
    )
    .await;
    let ask = async |secret: &str| {
        let request = TokenRequest {
            grant_type: Some("client_credentials"),
            client_id: Some("billing"),
            client_secret: Some(PresentedSecret::Basic(Secret::new(
                secret.as_bytes().to_vec(),
            ))),
            ..TokenRequest::default()
        };
        grant_token(&product, "acme", request).await.is_ok()
    };

    let rotated = call(
        &product,
        Method::POST,
        &format!("{path}/billing/secret"),
        Some(&token),
        None,
    )
    .await;

    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
    assert_eq!(
        rotated.caching,
        (Some("no-store".to_owned()), Some("no-cache".to_owned()))
    );
    let new = rotated.body["client_secret"]
        .as_str()
        .expect("the new secret, shown once");
    assert_ne!(new, old);
    assert!(ask(new).await, "the new secret proves the client");
    assert!(!ask(&old).await, "the old one proves nothing");
    for (client_id, status, code) in [
        ("webapp", StatusCode::CONFLICT, "client.has_no_secret"),
        ("nobody", StatusCode::NOT_FOUND, "client.not_found"),
    ] {
        let refused = call(
            &product,
            Method::POST,
            &format!("{path}/{client_id}/secret"),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(refused.status, status, "{client_id}");
        assert_eq!(refused.body["code"], code, "{client_id}");
    }
    let (product, reader) = start(&[Capability::ClientRead]).await;
    let refused = call(
        &product,
        Method::POST,
        &format!("{path}/operator/secret"),
        Some(&reader),
        None,
    )
    .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.body["code"], "auth.capability_missing");
}

#[actix_web::test]
async fn a_client_of_a_key_gives_it_inline_and_names_its_method_and_algorithm_by_name() {
    use saffui_core::ports::crypto::SignatureAlgorithm;

    let (product, token) = start(&[Capability::ClientRead, Capability::ClientWrite]).await;
    let path = "/admin/v1/realms/acme/clients";
    let key = product
        .signer
        .generate_key(SignatureAlgorithm::Es256, Box::new(()))
        .await
        .expect("a key");
    let keyed = |changes: Value| {
        let mut wanted = json!({
            "client_id": "keyed",
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "jwks": { "keys": [key.public_jwk.clone()] },
        });
        for (name, value) in changes.as_object().expect("an object") {
            wanted[name] = value.clone();
        }
        wanted.to_string()
    };

    for (changes, code) in [
        (
            json!({ "jwks_uri": "https://keys.example.org/jwks" }),
            "client.jwks_invalid",
        ),
        (
            json!({ "token_endpoint_auth_method": "tls_client_auth" }),
            "client.auth_method_invalid",
        ),
        (
            json!({ "token_endpoint_auth_signing_alg": "HS512" }),
            "realm.algorithm_unknown",
        ),
    ] {
        let refused = call(
            &product,
            Method::POST,
            path,
            Some(&token),
            Some(&keyed(changes.clone())),
        )
        .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{changes}");
        assert_eq!(refused.body["code"], code, "{changes}");
    }
    let created = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some(&keyed(json!({}))),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert!(
        created.body.get("client_secret").is_none(),
        "a client of a key keeps no secret: {}",
        created.body
    );
    assert_eq!(
        created.body["client"]["token_endpoint_auth_method"],
        "private_key_jwt"
    );
    assert_eq!(
        created.body["client"]["token_endpoint_auth_signing_alg"],
        "ES256"
    );
}

#[actix_web::test]
async fn an_administrator_names_how_an_application_signs_its_requests_and_whether_it_must() {
    use saffui_core::ports::crypto::SignatureAlgorithm;

    let (product, token) = start(&[Capability::ClientRead, Capability::ClientWrite]).await;
    let path = "/admin/v1/realms/acme/clients";
    let key = product
        .signer
        .generate_key(SignatureAlgorithm::Es256, Box::new(()))
        .await
        .expect("a key");
    let application = |changes: Value| {
        let mut wanted = json!({
            "client_id": "signing",
            "redirect_uris": ["https://app.example.org/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": { "keys": [key.public_jwk.clone()] },
            "request_object_signing_alg": "ES256",
            "require_signed_request_object": true,
        });
        for (name, value) in changes.as_object().expect("an object") {
            wanted[name] = value.clone();
        }
        wanted.to_string()
    };

    for (changes, code) in [
        (
            json!({ "request_object_signing_alg": "none" }),
            "realm.algorithm_unknown",
        ),
        (
            json!({ "request_object_signing_alg": "HS256" }),
            "client.auth_method_invalid",
        ),
        (
            json!({ "request_object_signing_alg": null }),
            "platform.request_invalid",
        ),
    ] {
        let refused = call(
            &product,
            Method::POST,
            path,
            Some(&token),
            Some(&application(changes.clone())),
        )
        .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{changes}");
        assert_eq!(refused.body["code"], code, "{changes}");
    }
    let created = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some(&application(json!({}))),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(
        created.body["client"]["request_object_signing_alg"],
        "ES256"
    );
    assert_eq!(
        created.body["client"]["require_signed_request_object"],
        true
    );
    let read = call(
        &product,
        Method::GET,
        &format!("{path}/signing"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(read.body["request_object_signing_alg"], "ES256");
    assert_eq!(read.body["require_signed_request_object"], true);
}

#[actix_web::test]
async fn an_administrator_moves_a_secret_between_the_header_and_the_form_and_nowhere_else() {
    let (product, token) = start(&[Capability::ClientRead, Capability::ClientWrite]).await;
    let path = "/admin/v1/realms/acme/clients";
    let created = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some(&json!({ "client_id": "billing", "scopes": ["invoices:read"] }).to_string()),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let change = async |method: &str| {
        call(
            &product,
            Method::PUT,
            &format!("{path}/billing/auth-method"),
            Some(&token),
            Some(&json!({ "token_endpoint_auth_method": method }).to_string()),
        )
        .await
    };

    let moved = change("client_secret_post").await;

    assert_eq!(moved.status, StatusCode::OK, "{}", moved.body);
    assert_eq!(
        moved.body["token_endpoint_auth_method"],
        "client_secret_post"
    );
    assert!(
        moved.body.get("client_secret").is_none(),
        "nothing is drawn, nothing is shown: {}",
        moved.body
    );
    for method in [
        "none",
        "client_secret_jwt",
        "private_key_jwt",
        "tls_client_auth",
    ] {
        let refused = change(method).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{method}");
        assert_eq!(
            refused.body["code"], "client.auth_method_invalid",
            "{method}"
        );
    }
    let with_more = call(
        &product,
        Method::PUT,
        &format!("{path}/billing/auth-method"),
        Some(&token),
        Some(r#"{"token_endpoint_auth_method":"client_secret_post","x":1}"#),
    )
    .await;
    assert_eq!(
        with_more.status,
        StatusCode::BAD_REQUEST,
        "a member nobody reads: {}",
        with_more.body
    );
}

/// Asks the decision point of `acme`, as a client that sends `body` of
/// `content_type`, with `authorization` when it sends one.
async fn ask_decision(
    product: &saffui_core::app::App,
    authorization: Option<String>,
    content_type: &str,
    body: String,
) -> (StatusCode, Value) {
    let app = test::init_service(
        App::new().configure(register_data_plane(web::Data::new(product.clone()))),
    )
    .await;
    let mut request = test::TestRequest::default()
        .method(Method::POST)
        .uri("/realms/acme/authz/decide")
        .insert_header((CONTENT_TYPE, content_type.to_owned()))
        .set_payload(body);
    if let Some(authorization) = authorization {
        request = request.insert_header((AUTHORIZATION, authorization));
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    let bytes = test::read_body(response).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[actix_web::test]
async fn a_client_moved_to_the_form_is_not_heard_at_the_decision_point() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    let (product, token) = start(&[Capability::ClientRead, Capability::ClientWrite]).await;
    let path = "/admin/v1/realms/acme/clients";
    let created = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some(&json!({ "client_id": "billing" }).to_string()),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let secret = created.body["client_secret"]
        .as_str()
        .expect("a secret, shown once")
        .to_owned();
    let basic = || {
        Some(format!(
            "Basic {}",
            STANDARD.encode(format!("billing:{secret}"))
        ))
    };
    let question =
        json!({ "subject_token": "t", "action": "read", "resource": { "type": "document" } });
    let (status, body) =
        ask_decision(&product, basic(), "application/json", question.to_string()).await;
    assert_eq!(status, StatusCode::OK, "heard in the Basic scheme: {body}");

    let moved = call(
        &product,
        Method::PUT,
        &format!("{path}/billing/auth-method"),
        Some(&token),
        Some(&json!({ "token_endpoint_auth_method": "client_secret_post" }).to_string()),
    )
    .await;
    assert_eq!(moved.status, StatusCode::OK, "{}", moved.body);

    for (authorization, content_type, body, how) in [
        (
            basic(),
            "application/json",
            question.to_string(),
            "in the Basic scheme",
        ),
        (
            None,
            "application/x-www-form-urlencoded",
            format!("client_id=billing&client_secret={secret}"),
            "in the form",
        ),
    ] {
        let (status, answer) = ask_decision(&product, authorization, content_type, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{how}: {answer}");
        assert_eq!(answer["error"], "invalid_client", "{how}");
    }
}
