
#[allow(unused_imports)]
use super::support;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use chrono::Utc;
use crypto::jose::jwt::JwtPayload;
use serde_json::{Value, json};
use server::api::config::register;
use store::tenancy::TenantContext;
use super::support::{Plane, SigningKey};

const REALM: &str = support::REALM;

fn mounted(plane: &Plane) -> server::api::config::Plane {
    server::api::config::Plane {
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
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    }
}

/// The confidential client, opted into the poll delivery and registered to
/// sign its backchannel requests with the key it publishes.
async fn opted_signing(plane: &Plane, key: &SigningKey) {
    use models::entities::attributes::AttributeValue;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
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
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
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
    let now = Utc::now().timestamp();
    let mut payload = JwtPayload::new();
    for (named, value) in [
        ("iss", Value::from(support::CONFIDENTIAL)),
        ("aud", Value::from(support::origin().issuer(REALM))),
        ("jti", Value::from(format!("jti-{now}-{}", claims.len()))),
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

    // Ada sees the request: the hint token reached the same doorbell.
    let bearer = {
        let code = plane
            .mint_code(support::CONFIDENTIAL, support::REDIRECT, "openid", None)
            .await;
        let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
        let encoded = data_encoding::BASE64
            .encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
                .insert_header(("authorization", format!("Basic {encoded}")))
                .set_form([
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", support::REDIRECT),
                ])
                .to_request(),
        )
        .await;
        let body: Value = test::read_body_json(response).await;
        body["access_token"].as_str().expect("a token").to_owned()
    };
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
