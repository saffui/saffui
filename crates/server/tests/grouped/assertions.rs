#[allow(unused_imports)]
use super::support;
use super::support::{Plane, SigningKey};
use actix_web::http::StatusCode;
use actix_web::{App, test};
use chrono::Utc;
use config::serving::Egress;
use crypto::jose::jwk::Jwk;
use crypto::jose::jws::{HS256, JwsHeader};
use crypto::jose::jwt::{self, JwtPayload};
use models::entities::realm::ClientRegistration;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};

fn mounted(plane: &Plane) -> Mounted {
    mounted_dialling(plane, Egress::Outward)
}

fn mounted_dialling(plane: &Plane, egress: Egress) -> Mounted {
    Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress,
        sealing: support::sealing(),
    }
}

fn token_endpoint() -> String {
    format!(
        "{}/protocol/openid-connect/token",
        support::origin().issuer(support::REALM)
    )
}

/// Register a client, and hand back its identifier and its secret.
async fn registered(plane: &Plane, metadata: Value) -> (String, Option<String>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/register",
                support::REALM
            ))
            .set_json(&metadata)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body: Value = test::read_body_json(response).await;
    (
        body["client_id"]
            .as_str()
            .expect("an identifier")
            .to_owned(),
        body["client_secret"].as_str().map(str::to_owned),
    )
}

/// The claims §3 requires, before a case spoils one of them.
fn claims(client_id: &str, jti: &str) -> JwtPayload {
    let now = Utc::now().timestamp();
    let mut payload = JwtPayload::new();
    for (named, value) in [("iss", client_id), ("sub", client_id), ("jti", jti)] {
        payload.set_claim(named, Some(Value::from(value))).unwrap();
    }
    payload
        .set_claim("aud", Some(Value::from(token_endpoint())))
        .unwrap();
    payload
        .set_claim("exp", Some(Value::from(now + 60)))
        .unwrap();
    payload.set_claim("iat", Some(Value::from(now))).unwrap();
    payload
}

fn signed_with_secret(payload: &JwtPayload, secret: &str) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    let signer = HS256
        .signer_from_bytes(secret.as_bytes())
        .expect("a signer");
    jwt::encode_with_signer(payload, &header, &signer).expect("a signed assertion")
}

/// Present an assertion and hand back the status.
async fn presenting(plane: &Plane, client_id: Option<&str>, assertion: &str) -> StatusCode {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut form = vec![
        ("token".to_owned(), "not-a-token".to_owned()),
        (
            "client_assertion_type".to_owned(),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned(),
        ),
        ("client_assertion".to_owned(), assertion.to_owned()),
    ];
    if let Some(client_id) = client_id {
        form.push(("client_id".to_owned(), client_id.to_owned()));
    }
    test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/introspect",
                support::REALM
            ))
            .set_form(&form)
            .to_request(),
    )
    .await
    .status()
}

/// One thing an assertion gets wrong.
type Spoil = Box<dyn Fn(&mut JwtPayload)>;

fn jwks_of(key: &Jwk) -> Value {
    serde_json::to_value(json!({ "keys": [serde_json::to_value(key.as_ref()).unwrap()] })).unwrap()
}

/// A client that publishes its keys authenticates by signing with them, and
/// §9's own checks are each what refuses when it fails.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_key_the_client_holds_authenticates_it() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let key = SigningKey::generate("client-key");
    let (client_id, secret) = registered(
        &plane,
        json!({
            "client_name": "signs its own",
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": jwks_of(&key.public()),
        }),
    )
    .await;
    // §9: nothing shared, so nothing to hand back.
    assert!(secret.is_none(), "a key-signing client was given a secret");

    let assertion = key.sign(&claims(&client_id, "first"), &key.kid);
    assert_eq!(
        presenting(&plane, Some(&client_id), &assertion).await,
        StatusCode::OK
    );

    // One assertion, one use. Without this an intercepted one is a credential
    // until it expires.
    assert_eq!(
        presenting(&plane, Some(&client_id), &assertion).await,
        StatusCode::UNAUTHORIZED,
        "an assertion was accepted twice"
    );

    // §9 lets the assertion be the only thing naming the client.
    let alone = key.sign(&claims(&client_id, "no-client-id"), &key.kid);
    assert_eq!(presenting(&plane, None, &alone).await, StatusCode::OK);
}

/// Each of §3's bindings, spoiled one at a time.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_assertion_missing_one_of_its_bindings_is_refused() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let key = SigningKey::generate("client-key");
    let (client_id, _) = registered(
        &plane,
        json!({
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": jwks_of(&key.public()),
        }),
    )
    .await;

    let now = Utc::now().timestamp();
    let spoiled: Vec<(&str, Spoil)> = vec![
        (
            "another audience",
            Box::new(|payload: &mut JwtPayload| {
                payload
                    .set_claim("aud", Some(Value::from("https://elsewhere.test/token")))
                    .unwrap();
            }),
        ),
        (
            "another issuer",
            Box::new(|payload: &mut JwtPayload| {
                payload
                    .set_claim("iss", Some(Value::from("somebody-else")))
                    .unwrap();
            }),
        ),
        (
            "another subject",
            Box::new(|payload: &mut JwtPayload| {
                payload
                    .set_claim("sub", Some(Value::from("somebody-else")))
                    .unwrap();
            }),
        ),
        (
            "an expiry in the past",
            Box::new(move |payload: &mut JwtPayload| {
                payload
                    .set_claim("exp", Some(Value::from(now - 3600)))
                    .unwrap();
            }),
        ),
        (
            "an expiry a year out",
            Box::new(move |payload: &mut JwtPayload| {
                payload
                    .set_claim("exp", Some(Value::from(now + 31_536_000)))
                    .unwrap();
            }),
        ),
        (
            "no expiry",
            Box::new(|payload: &mut JwtPayload| {
                payload.set_claim("exp", None).unwrap();
            }),
        ),
        (
            "no identifier",
            Box::new(|payload: &mut JwtPayload| {
                payload.set_claim("jti", None).unwrap();
            }),
        ),
    ];
    for (named, spoil) in spoiled {
        let mut payload = claims(&client_id, named);
        spoil(&mut payload);
        assert_eq!(
            presenting(&plane, Some(&client_id), &key.sign(&payload, &key.kid)).await,
            StatusCode::UNAUTHORIZED,
            "{named} was accepted"
        );
    }

    // A real signature by a key this client never published.
    let other = SigningKey::generate("client-key");
    assert_eq!(
        presenting(
            &plane,
            Some(&client_id),
            &other.sign(&claims(&client_id, "other-key"), &other.kid)
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "a signature by another key was accepted"
    );
}

/// The shared-secret method, whose secret this deployment has to be able to
/// read back and therefore seals rather than hashes.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_secret_only_the_two_of_them_hold_authenticates_by_hmac() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let (client_id, secret) = registered(
        &plane,
        json!({
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "client_secret_jwt",
        }),
    )
    .await;
    let secret = secret.expect("a shared secret");

    let assertion = signed_with_secret(&claims(&client_id, "hmac-first"), &secret);
    assert_eq!(
        presenting(&plane, Some(&client_id), &assertion).await,
        StatusCode::OK
    );
    assert_eq!(
        presenting(&plane, Some(&client_id), &assertion).await,
        StatusCode::UNAUTHORIZED,
        "an assertion was accepted twice"
    );
    assert_eq!(
        presenting(
            &plane,
            Some(&client_id),
            &signed_with_secret(
                &claims(&client_id, "wrong-secret"),
                "not-the-secret-but-long-enough-for-hmac"
            )
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}

/// The method is the client's registration, not the request's choice. Either
/// direction would be a downgrade: a shared secret standing in for a key, or a
/// key standing in for one.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_registered_method_is_the_only_one_that_works() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let key = SigningKey::generate("client-key");
    let (signing_client, _) = registered(
        &plane,
        json!({
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": jwks_of(&key.public()),
        }),
    )
    .await;
    let (secret_client, secret) = registered(
        &plane,
        json!({
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "client_secret_basic",
        }),
    )
    .await;
    let secret = secret.expect("a secret");

    // A client registered for a secret is not authenticated by an assertion.
    assert_eq!(
        presenting(
            &plane,
            Some(&secret_client),
            &signed_with_secret(&claims(&secret_client, "not-its-method"), &secret)
        )
        .await,
        StatusCode::UNAUTHORIZED
    );

    // And one registered for a key is not authenticated by the secret it does
    // not have.
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/introspect",
                support::REALM
            ))
            .set_form([
                ("token", "not-a-token"),
                ("client_id", signing_client.as_str()),
                ("client_secret", "anything"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // An HMAC where a published key is expected: the two families never share
    // a verifier, so this is a bad signature and not a shortcut.
    assert_eq!(
        presenting(
            &plane,
            Some(&signing_client),
            &signed_with_secret(
                &claims(&signing_client, "wrong-family"),
                "a-guessed-secret-of-thirty-two-bytes-or-more"
            )
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}

/// §9: a client that signs its own assertions has to publish the keys they are
/// checked against, and a registration naming neither could never authenticate.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn signing_with_a_key_needs_the_keys_published() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/register",
                support::REALM
            ))
            .set_json(json!({
                "redirect_uris": ["https://app.example/cb"],
                "token_endpoint_auth_method": "private_key_jwt",
            }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let answered: Value = test::read_body_json(response).await;
    assert_eq!(
        answered["error"].as_str(),
        Some("invalid_client_metadata"),
        "{answered}"
    );
}

/// Discovery names both methods, since a client reads it to know how to
/// authenticate at all.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn both_methods_are_advertised() {
    let plane = Plane::with_actions(&[]).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/.well-known/openid-configuration",
                support::REALM
            ))
            .to_request(),
    )
    .await;
    let published: Value = test::read_body_json(response).await;
    let methods = published["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("the methods");
    for named in ["client_secret_jwt", "private_key_jwt"] {
        assert!(
            methods.iter().any(|held| held.as_str() == Some(named)),
            "{named} is performed and not named: {published}"
        );
    }
    let algorithms = published["token_endpoint_auth_signing_alg_values_supported"]
        .as_array()
        .expect("the algorithms");
    for named in ["HS256", "RS256", "ES256"] {
        assert!(
            algorithms.iter().any(|held| held.as_str() == Some(named)),
            "{named}: {published}"
        );
    }
}

/// A client that publishes its keys is read from where it published them, and
/// read again once what was read has been kept long enough: a client rotates,
/// and a set kept forever stops verifying the client it was read for.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn keys_published_elsewhere_are_read_and_read_again() {
    use actix_web::{HttpResponse, HttpServer, web};
    use std::sync::{Arc, Mutex};

    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;

    // What the client publishes, which it replaces partway through.
    let first = SigningKey::generate("first-key");
    let second = SigningKey::generate("second-key");
    let published = Arc::new(Mutex::new(jwks_of(&first.public())));
    let served = Arc::clone(&published);
    let server = HttpServer::new(move || {
        let served = Arc::clone(&served);
        App::new().route(
            "/jwks",
            web::get().to(move || {
                let served = Arc::clone(&served);
                async move { HttpResponse::Ok().json(served.lock().unwrap().clone()) }
            }),
        )
    })
    .bind(("127.0.0.1", 0))
    .expect("a port");
    let port = server.addrs().first().expect("an address").port();
    let running = server.run();
    let handle = running.handle();
    tokio::spawn(running);

    let app = test::init_service(
        App::new().configure(register(&mounted_dialling(&plane, Egress::Anywhere))),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/register",
                support::REALM
            ))
            .set_json(json!({
                "redirect_uris": ["https://app.example/cb"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": format!("http://127.0.0.1:{port}/jwks"),
            }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let held: Value = test::read_body_json(response).await;
    let client_id = held["client_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();

    let presenting_dialling = |assertion: String| {
        let plane = &plane;
        let client_id = client_id.clone();
        async move {
            let app = test::init_service(
                App::new().configure(register(&mounted_dialling(plane, Egress::Anywhere))),
            )
            .await;
            let response = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri(&format!(
                        "/realms/{}/protocol/openid-connect/introspect",
                        support::REALM
                    ))
                    .set_form(&[
                        ("token".to_owned(), "not-a-token".to_owned()),
                        (
                            "client_assertion_type".to_owned(),
                            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned(),
                        ),
                        ("client_assertion".to_owned(), assertion),
                        ("client_id".to_owned(), client_id),
                    ])
                    .to_request(),
            )
            .await;
            let status = response.status();
            let body: Value = test::read_body_json(response).await;
            (status, body)
        }
    };

    let (status, told) =
        presenting_dialling(first.sign(&claims(&client_id, "published-1"), &first.kid)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the published key set was not read: {told}"
    );

    // Rotated. What was read is kept for a while, so the new key is not yet
    // known and the old one still is.
    *published.lock().unwrap() = jwks_of(&second.public());
    assert_eq!(
        presenting_dialling(second.sign(&claims(&client_id, "rotated-too-soon"), &second.kid))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    // Once what was kept is stale, the set is read again and the new key works.
    plane.age_client_keys(&client_id).await;
    assert_eq!(
        presenting_dialling(second.sign(&claims(&client_id, "rotated"), &second.kid))
            .await
            .0,
        StatusCode::OK,
        "a rotated key set was never read again"
    );

    handle.stop(true).await;
}
