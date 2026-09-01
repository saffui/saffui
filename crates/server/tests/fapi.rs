mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use chrono::Utc;
use crypto::jose::jwt::JwtPayload;
use crypto::provider::CryptoProvider;
use data_encoding::BASE64URL_NOPAD;
use serde_json::{Value, json};
use server::api::config::register;
use store::tenancy::TenantContext;
use support::{Plane, SigningKey, urlencode};

const REALM: &str = support::REALM;
const FINTECH: &str = "fintech";
const REDIRECT: &str = "https://fin.example/callback";
const VERIFIER: &str = "a-code-verifier-of-plausible-length-for-s256";

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

/// A confidential client wearing the profile: private_key_jwt with an inline
/// key set, ES256 identity tokens, the code flow, and `profile: fapi2` on the
/// bag the operator writes.
async fn planted_fintech(plane: &Plane) -> SigningKey {
    use crypto::provider::SignAlg;
    use models::auditable::AuditableModel;
    use models::entities::attributes::AttributeValue;
    use models::entities::client::ClientCreateModel;

    let key = SigningKey::generate("fintech-key");
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let mut client = ClientCreateModel {
        name: FINTECH.into(),
        display_name: FINTECH.into(),
        description: String::new(),
        enabled: Some(true),
    }
    .into_model(
        FINTECH.to_owned(),
        REALM.into(),
        AuditableModel::from_creator(support::TENANT.into(), "root".into()),
    );
    store::providers::clients::create(&transaction, &client)
        .await
        .unwrap();
    client.public_client = Some(false);
    client.client_authenticator_type = Some("private-key-jwt".into());
    client.jwks = Some(json!({
        "keys": [serde_json::to_value(key.public().as_ref()).unwrap()],
    }));
    client.id_token_signed_response_alg = Some(SignAlg::Es256);
    client.redirect_uris = Some(vec![REDIRECT.to_owned()]);
    client.standard_flow_enabled = Some(true);
    client.configs.get_or_insert_with(Default::default).insert(
        "profile".to_owned(),
        AttributeValue::Str("fapi2".to_owned()),
    );
    store::providers::clients::update(&transaction, &client)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    key
}

fn assertion(key: &SigningKey, jti: &str) -> String {
    let now = Utc::now().timestamp();
    let mut payload = JwtPayload::new();
    for (named, value) in [("iss", FINTECH), ("sub", FINTECH), ("jti", jti)] {
        payload.set_claim(named, Some(Value::from(value))).unwrap();
    }
    payload
        .set_claim(
            "aud",
            Some(Value::from(format!(
                "{}/protocol/openid-connect/token",
                support::origin().issuer(REALM)
            ))),
        )
        .unwrap();
    payload
        .set_claim("exp", Some(Value::from(now + 60)))
        .unwrap();
    payload.set_claim("iat", Some(Value::from(now))).unwrap();
    key.sign(&payload, &key.kid)
}

fn challenge() -> String {
    let hashed = crypto::provider::DigestProvider::hash(
        support::provider().digest(),
        crypto::provider::HashAlg::Sha256,
        VERIFIER.as_bytes(),
    )
    .expect("a digest");
    BASE64URL_NOPAD.encode(&hashed)
}

async fn pushed(
    plane: &Plane,
    key: &SigningKey,
    jti: &str,
    form: &[(&str, &str)],
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let assertion = assertion(key, jti);
    let mut sent: Vec<(String, String)> = vec![
        ("client_id".into(), FINTECH.into()),
        (
            "client_assertion_type".into(),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
        ),
        ("client_assertion".into(), assertion),
    ];
    for (named, value) in form {
        sent.push(((*named).into(), (*value).into()));
    }
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/par"))
            .set_form(&sent)
            .to_request(),
    )
    .await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// Where the browser lands when sent to the authorization endpoint.
async fn sent_to_authorize(plane: &Plane, query: &str) -> (StatusCode, String) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/auth?{query}"
            ))
            .to_request(),
    )
    .await;
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    (status, location)
}

async fn exchanged(
    plane: &Plane,
    key: &SigningKey,
    jti: &str,
    code: &str,
    proof: Option<&str>,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let assertion = assertion(key, jti);
    let mut asked = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
        .set_form([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("client_id", FINTECH),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", &assertion),
        ]);
    if let Some(proof) = proof {
        asked = asked.insert_header(("dpop", proof.to_owned()));
    }
    let response = test::call_service(&app, asked.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn token_url() -> String {
    format!(
        "{}/protocol/openid-connect/token",
        support::origin().issuer(REALM)
    )
}

/// The whole profile at its doors: nothing reaches the authorization endpoint
/// but a pushed, proof-keyed code request; nothing leaves the token endpoint
/// unbound; and a client provisioned against its own profile is refused whole.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_profile_holds_at_every_door() {
    let plane = Plane::with_actions(&[]).await;
    let key = planted_fintech(&plane).await;
    let challenge = challenge();

    // The front door: a request that did not push is refused, PKCE or not.
    let (_, landing) = sent_to_authorize(
        &plane,
        &format!(
            "client_id={FINTECH}&redirect_uri={}&response_type=code&scope=openid&state=s\
             &code_challenge={challenge}&code_challenge_method=S256",
            urlencode(REDIRECT),
        ),
    )
    .await;
    assert!(
        landing.contains("error=invalid_request"),
        "a direct request was honoured: {landing}"
    );

    // The push door: what the profile forbids is refused where the client
    // still reads a status code.
    let (status, told) = pushed(
        &plane,
        &key,
        "push-1",
        &[
            ("redirect_uri", REDIRECT),
            ("response_type", "code"),
            ("scope", "openid"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert!(
        told["error_description"]
            .as_str()
            .is_some_and(|held| held.contains("proof key")),
        "{told}"
    );
    let (status, told) = pushed(
        &plane,
        &key,
        "push-2",
        &[
            ("redirect_uri", REDIRECT),
            ("response_type", "token"),
            ("scope", "openid"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert!(
        told["error_description"]
            .as_str()
            .is_some_and(|held| held.contains("code flow")),
        "{told}"
    );

    // Pushed whole, the request stands and the browser may be sent.
    let (status, told) = pushed(
        &plane,
        &key,
        "push-3",
        &[
            ("redirect_uri", REDIRECT),
            ("response_type", "code"),
            ("scope", "openid"),
            ("state", "s"),
            ("nonce", "n-once"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let reference = told["request_uri"].as_str().expect("a reference");
    let (status, landing) = sent_to_authorize(
        &plane,
        &format!("client_id={FINTECH}&request_uri={}", urlencode(reference)),
    )
    .await;
    assert!(
        !landing.contains("error=") && status != StatusCode::BAD_REQUEST,
        "a pushed, proof-keyed code request was refused: {status} {landing}"
    );

    // The token door: the same code is refused bare and answered bound.
    let code = plane
        .mint_code(FINTECH, REDIRECT, "openid", Some((&challenge, "S256")))
        .await;
    let (status, told) = exchanged(&plane, &key, "token-1", &code, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert!(
        told["error_description"]
            .as_str()
            .is_some_and(|held| held.contains("sender-constrained")),
        "{told}"
    );

    let holder = SigningKey::generate("holder-key");
    let proof = holder.proof(
        "POST",
        &token_url(),
        None,
        "proof-1",
        Utc::now().timestamp(),
    );
    let (status, minted) = exchanged(&plane, &key, "token-2", &code, Some(&proof)).await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    let access = minted["access_token"].as_str().expect("a token");
    let claims = plane.claims_of(access).await;
    assert!(
        claims["cnf"]["jkt"].is_string(),
        "the token names no key: {claims}"
    );
    // The identity token is signed the way the profile demands.
    let id_token = minted["id_token"].as_str().expect("an identity token");
    let header: Value = serde_json::from_slice(
        &BASE64URL_NOPAD
            .decode(id_token.split('.').next().unwrap().as_bytes())
            .expect("base64"),
    )
    .expect("a header");
    assert_eq!(header["alg"], "ES256", "{header}");

    // Renewal is held to the same constraint: bare it is refused, proven it
    // turns.
    let renewal = minted["refresh_token"].as_str().expect("a refresh token");
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let bare = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
            .set_form([
                ("grant_type", "refresh_token"),
                ("refresh_token", renewal),
                ("client_id", FINTECH),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", &assertion(&key, "token-3")),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(bare.status(), StatusCode::BAD_REQUEST);
    let proof = holder.proof(
        "POST",
        &token_url(),
        None,
        "proof-2",
        Utc::now().timestamp(),
    );
    let proven = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
            .insert_header(("dpop", proof))
            .set_form([
                ("grant_type", "refresh_token"),
                ("refresh_token", renewal),
                ("client_id", FINTECH),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", &assertion(&key, "token-4")),
            ])
            .to_request(),
    )
    .await;
    let status = proven.status();
    let told: Value = test::read_body_json(proven).await;
    assert_eq!(status, StatusCode::OK, "{told}");

    // Provisioned against its own profile, the client is refused whole at the
    // front door rather than served under it.
    {
        use crypto::provider::SignAlg;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let mut client = store::providers::clients::load(&transaction, FINTECH)
            .await
            .unwrap()
            .expect("the client");
        client.id_token_signed_response_alg = Some(SignAlg::Rs256);
        store::providers::clients::update(&transaction, &client)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }
    let (status, told) = pushed(
        &plane,
        &key,
        "push-4",
        &[
            ("redirect_uri", REDIRECT),
            ("response_type", "code"),
            ("scope", "openid"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let reference = told["request_uri"]
        .as_str()
        .expect("a reference")
        .to_owned();
    let (_, landing) = sent_to_authorize(
        &plane,
        &format!("client_id={FINTECH}&request_uri={}", urlencode(&reference)),
    )
    .await;
    assert!(
        landing.contains("error=unauthorized_client"),
        "a misprovisioned profile client was served: {landing}"
    );
}
