#[allow(unused_imports)]
use super::support;
use super::support::{Plane, SigningKey};
use actix_web::http::StatusCode;
use actix_web::{App, test};
use chrono::Utc;
use crypto::jose::jwt::JwtPayload;
use serde_json::{Value, json};
use server::api::config::register;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;

fn mounted(plane: &Plane) -> server::api::config::Plane {
    server::api::config::Plane {
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
        ceiling: support::ceiling(),
    }
}

/// The confidential client, opted into the poll delivery and registered to
/// sign its backchannel requests with the key it publishes.
async fn opted_signing(plane: &Plane, key: &SigningKey) {
    use models::entities::attributes::AttributeValue;
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
        .await
        .unwrap()
        .expect("the client");
    client.jwks = Some(json!({
        "keys": [serde_json::to_value(key.public().as_ref()).unwrap()],
    }));
    let bag = client.configs.get_or_insert_with(Default::default);
    for (named, value) in [
        ("ciba.delivery_mode", "poll"),
        ("ciba.request_signing_alg", "ES256"),
    ] {
        bag.insert(named.to_owned(), AttributeValue::Str(value.to_owned()));
    }
    assert!(
        store::providers::clients::update(&transaction, &client)
            .await
            .unwrap()
    );
    transaction.commit().await.unwrap();
}

async fn posted(plane: &Plane, form: &[(&str, &str)]) -> (StatusCode, Value) {
    posted_through(plane, config::serving::Egress::Outward, form).await
}

/// The same, on a plane that dials where the deployment lets it.
async fn posted_through(
    plane: &Plane,
    egress: config::serving::Egress,
    form: &[(&str, &str)],
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&server::api::config::Plane {
        egress,
        ..mounted(plane)
    })))
    .await;
    let mut sent: Vec<(String, String)> = vec![
        ("client_id".into(), support::CONFIDENTIAL.into()),
        ("client_secret".into(), support::CLIENT_SECRET.into()),
    ];
    for (named, value) in form {
        sent.push(((*named).into(), (*value).into()));
    }
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/bc-authorize"
            ))
            .set_form(&sent)
            .to_request(),
    )
    .await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn signed_request(key: &SigningKey, claims: &[(&str, Value)]) -> String {
    static DRAWN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let now = Utc::now().timestamp();
    let drawn = DRAWN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut payload = JwtPayload::new();
    for (named, value) in [
        ("iss", Value::from(support::CONFIDENTIAL)),
        ("aud", Value::from(support::origin().issuer(REALM))),
        ("jti", Value::from(format!("jti-{now}-{drawn}"))),
        ("iat", Value::from(now)),
        ("nbf", Value::from(now)),
        ("exp", Value::from(now + 120)),
    ] {
        payload.set_claim(named, Some(value)).unwrap();
    }
    for (named, value) in claims {
        payload.set_claim(named, Some(value.clone())).unwrap();
    }
    key.sign(&payload, &key.kid)
}

fn hint_token(key: &SigningKey, named: &str, value: &str) -> String {
    let mut payload = JwtPayload::new();
    payload.set_claim(named, Some(Value::from(value))).unwrap();
    key.sign(&payload, &key.kid)
}

/// A signed request is presented once, CIBA §7.1.1: the same request again is
/// refused, and one refused after its identifier was spent stays spent.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_signed_request_is_presented_once() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("ciba-signer");
    opted_signing(&plane, &key).await;

    let request = signed_request(
        &key,
        &[
            ("scope", Value::from("openid")),
            ("login_hint", Value::from(support::SUBJECT)),
        ],
    );
    let (status, opened) = posted(&plane, &[("request", &request)]).await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let (status, told) = posted(&plane, &[("request", &request)]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a signed request was taken twice: {told}"
    );
    assert_eq!(
        told["error_description"], "the request was presented before",
        "{told}"
    );

    // Refused for what it asks, after its identifier was read: still spent.
    let refused = signed_request(
        &key,
        &[
            ("scope", Value::from("openid")),
            ("login_hint", Value::from(support::SUBJECT)),
            ("requested_expiry", Value::from("not a number")),
        ],
    );
    let (status, first) = posted(&plane, &[("request", &refused)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{first}");
    let (_, again) = posted(&plane, &[("request", &refused)]).await;
    assert_eq!(
        again["error_description"], "the request was presented before",
        "a request refused after its identifier was spent was read again: {again}"
    );
}

/// A registered signer speaks only in signatures: the bare form is refused,
/// the signed one opens, a stranger's signature is refused, and the signed
/// hint token resolves the person, with the ghost for a subject nobody is.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_signing_client_is_held_to_its_signature() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("ciba-signer");
    opted_signing(&plane, &key).await;

    // Bare form from a registered signer: refused.
    let (status, told) = posted(&plane, &[("login_hint", support::SUBJECT)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert!(
        told["error_description"]
            .as_str()
            .is_some_and(|held| held.contains("signs its backchannel")),
        "{told}"
    );

    // The signed initiation opens, parameters read from inside the token.
    let request = signed_request(
        &key,
        &[
            ("scope", Value::from("openid")),
            ("login_hint", Value::from(support::SUBJECT)),
            ("binding_message", Value::from("Virement 240")),
        ],
    );
    let (status, opened) = posted(&plane, &[("request", &request)]).await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    assert!(opened["auth_req_id"].is_string(), "{opened}");

    // A stranger's key signs nothing here.
    let stranger = SigningKey::generate("stranger");
    let forged = signed_request(&stranger, &[("login_hint", Value::from(support::SUBJECT))]);
    let (status, told) = posted(&plane, &[("request", &forged)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");

    // A signed request without its window is refused whole.
    let mut payload = JwtPayload::new();
    for (named, value) in [
        ("iss", Value::from(support::CONFIDENTIAL)),
        ("aud", Value::from(support::origin().issuer(REALM))),
        ("jti", Value::from("no-window")),
        ("login_hint", Value::from(support::SUBJECT)),
    ] {
        payload.set_claim(named, Some(value)).unwrap();
    }
    let windowless = key.sign(&payload, &key.kid);
    let (status, _) = posted(&plane, &[("request", &windowless)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The hint token, inside a signed request: the client vouches for the
    // subject by signing, and the person is found by account or address.
    let hinted = hint_token(&key, "email", support::SUBJECT_EMAIL);
    let request = signed_request(
        &key,
        &[
            ("scope", Value::from("openid")),
            ("login_hint_token", Value::from(hinted)),
        ],
    );
    let (status, opened) = posted(&plane, &[("request", &request)]).await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    assert!(opened["auth_req_id"].is_string(), "{opened}");

    // Ada sees the request on her account console: the hint token reached
    // the same doorbell.
    let bearer = plane.token(&support::account_console_claims());
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/bc-pending"
            ))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .to_request(),
    )
    .await;
    // The list shows the digest, never the clear id, so the proof is by
    // count: both signed initiations, the named one and the hint-token one,
    // landed on ada's doorbell.
    let waiting: Value = test::read_body_json(response).await;
    assert_eq!(
        waiting["pending"].as_array().map(Vec::len),
        Some(2),
        "{waiting}"
    );

    // A verified hint naming nobody opens the same ghost an unknown
    // login_hint does: a normal answer nobody can ever approve.
    let ghost = hint_token(&key, "sub", "nobody-here");
    let request = signed_request(
        &key,
        &[
            ("scope", Value::from("openid")),
            ("login_hint_token", Value::from(ghost)),
        ],
    );
    let (status, opened) = posted(&plane, &[("request", &request)]).await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    assert!(opened["auth_req_id"].is_string(), "{opened}");
}

/// A signing client that publishes its keys at an address is held to the keys
/// it publishes, read before its signed request is judged.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_signed_request_is_read_under_the_keys_its_client_publishes() {
    use std::sync::{Arc, Mutex};

    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("ciba-signer");
    opted_signing(&plane, &key).await;
    let (uri, _, handle) = support::serving_keys(Arc::new(Mutex::new(json!({
        "keys": [serde_json::to_value(key.public().as_ref()).unwrap()],
    }))));
    // The key moves to where the client publishes it: nothing is kept inline.
    {
        let transaction = plane
            .scoped(&TenantContext::new(support::TENANT, REALM))
            .await;
        let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
            .await
            .unwrap()
            .expect("the client");
        client.jwks = None;
        client.jwks_uri = Some(uri);
        assert!(
            store::providers::clients::update(&transaction, &client)
                .await
                .unwrap()
        );
        transaction.commit().await.unwrap();
    }

    let request = signed_request(
        &key,
        &[
            ("scope", Value::from("openid")),
            ("login_hint", Value::from(support::SUBJECT)),
        ],
    );
    let (status, opened) = posted_through(
        &plane,
        config::serving::Egress::Anywhere,
        &[("request", &request)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a signed request was not read under the keys its client publishes: {opened}"
    );
    handle.stop(false).await;
}

/// A hint token naming an address two accounts share names neither of them,
/// as a plain hint does: the request opens as the ghost, on nobody's doorbell.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_hint_token_naming_a_shared_address_names_neither() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("ciba-signer");
    opted_signing(&plane, &key).await;
    plane.plant_account_sharing_subject_email().await;
    plane.open_login_of("twin-login", "ada-twin").await;

    let hinted = hint_token(&key, "email", support::SUBJECT_EMAIL);
    let request = signed_request(
        &key,
        &[
            ("scope", Value::from("openid")),
            ("login_hint_token", Value::from(hinted)),
        ],
    );
    let (status, opened) = posted(&plane, &[("request", &request)]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a shared address was told apart: {opened}"
    );

    let mut twin_claims = support::account_console_claims();
    for (named, value) in [("sub", "ada-twin"), ("sid", "twin-login")] {
        twin_claims
            .set_claim(named, Some(Value::from(value)))
            .expect("a claim");
    }
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    for claims in [support::account_console_claims(), twin_claims] {
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!(
                    "/realms/{REALM}/protocol/openid-connect/bc-pending"
                ))
                .insert_header(("authorization", format!("Bearer {}", plane.token(&claims))))
                .to_request(),
        )
        .await;
        let waiting: Value = test::read_body_json(response).await;
        assert_eq!(
            waiting["pending"].as_array().map(Vec::len),
            Some(0),
            "an address two accounts share rang one of them: {waiting}"
        );
    }
}
