mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use crypto::jose::jwe::{JweHeader, RSA_OAEP_256, deserialize_compact};
use models::entities::client::JweRegistration;
use models::entities::keys::{JweAlgorithm, JweEncryption};
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use support::{Plane, SigningKey, cookie_value, urlencode};

const REDIRECT: &str = "https://app.example/callback";

fn mounted(plane: &Plane) -> Mounted {
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
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    }
}

fn asking() -> JweRegistration {
    JweRegistration::new(JweAlgorithm::RsaOaep256, Some(JweEncryption::A256Gcm))
}

/// Open the private half and hand back what was inside, with the header.
fn opened(key: &SigningKey, token: &str) -> (String, JweHeader) {
    let decrypter = RSA_OAEP_256
        .decrypter_from_jwk(key.private())
        .expect("a decrypter");
    let (payload, header) = deserialize_compact(token, &decrypter).expect("an encrypted answer");
    (String::from_utf8(payload).expect("a payload"), header)
}

/// Sign in and hand back the code the client may exchange.
async fn code_for(plane: &Plane) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope=openid%20profile&state=s&nonce=n-0S6",
                support::REALM,
                support::CONFIDENTIAL,
                urlencode(REDIRECT),
            ))
            .to_request(),
    )
    .await;
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let binding = cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login");

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/login",
                support::REALM
            ))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .set_form([
                ("username", support::SUBJECT),
                ("password", support::PASSWORD),
            ])
            .to_request(),
    )
    .await;
    let landing = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("a landing")
        .to_owned();
    landing
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .expect("a code")
        .to_owned()
}

/// Exchange the code, and hand back what the token endpoint answered.
async fn exchanged(plane: &Plane, code: &str) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/token",
                support::REALM
            ))
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", REDIRECT),
                ("client_id", support::CONFIDENTIAL),
                ("client_secret", support::CLIENT_SECRET),
            ])
            .to_request(),
    )
    .await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

async fn userinfo_with(plane: &Plane, access: &str) -> (StatusCode, String, String) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/userinfo",
                support::REALM
            ))
            .insert_header(("authorization", format!("Bearer {access}")))
            .to_request(),
    )
    .await;
    let status = response.status();
    let kind = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = String::from_utf8(test::read_body(response).await.to_vec()).expect("a body");
    (status, kind, body)
}

/// The identity token comes back wrapped, and what is inside it is the signed
/// one: a nested JWT, which the header says so the recipient verifies what it
/// decrypts rather than reading it as claims.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_identity_token_is_wrapped_for_the_client_that_asked() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate_encryption("wrapping");
    plane
        .register_client_encryption(
            support::CONFIDENTIAL,
            serde_json::json!({ "keys": [key.public_for_encryption().as_ref()] }),
            Some(asking()),
            None,
        )
        .await;

    let code = code_for(&plane).await;
    let (status, answered) = exchanged(&plane, &code).await;
    assert_eq!(status, StatusCode::OK, "{answered}");

    let told = answered["id_token"].as_str().expect("an identity token");
    assert_eq!(told.split('.').count(), 5, "the token was not encrypted");

    let (inside, header) = opened(&key, told);
    assert_eq!(header.algorithm(), Some("RSA-OAEP-256"));
    assert_eq!(header.content_encryption(), Some("A256GCM"));
    assert_eq!(
        header.content_type(),
        Some("JWT"),
        "a nested token that does not say so is read as claims"
    );
    assert_eq!(
        inside.split('.').count(),
        3,
        "what was inside was not signed"
    );

    // The access and refresh tokens are this server's to read back, not the
    // client's, and are left alone.
    for named in ["access_token", "refresh_token"] {
        let held = answered[named].as_str().expect(named);
        assert_eq!(held.split('.').count(), 3, "{named} was wrapped too");
    }
}

/// A client that registered no encryption is answered as it always was.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_that_asked_for_none_is_answered_in_the_clear() {
    let plane = Plane::with_actions(&[]).await;

    let code = code_for(&plane).await;
    let (status, answered) = exchanged(&plane, &code).await;
    assert_eq!(status, StatusCode::OK, "{answered}");
    assert_eq!(
        answered["id_token"]
            .as_str()
            .expect("a token")
            .split('.')
            .count(),
        3
    );
}

/// A client that registered encryption and published no key it can be used
/// with is refused, never answered with something readable.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_that_cannot_be_encrypted_to_is_refused_rather_than_read() {
    let plane = Plane::with_actions(&[]).await;
    // Published for signing, which is not a grant to encrypt.
    let signing = SigningKey::generate_rsa("for-signing");
    plane
        .register_client_encryption(
            support::CONFIDENTIAL,
            serde_json::json!({ "keys": [signing.public().as_ref()] }),
            Some(asking()),
            None,
        )
        .await;

    let code = code_for(&plane).await;
    let (status, answered) = exchanged(&plane, &code).await;
    assert_ne!(status, StatusCode::OK, "a readable token was handed out");
    assert_eq!(answered["id_token"], Value::Null, "{answered}");
}

/// A key published for signing is not a grant to encrypt.
///
/// Held apart from the test above because that one is refused for naming the
/// wrong algorithm: this key names the right one and differs only in what its
/// owner published it for.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_key_published_for_signing_is_not_a_key_to_encrypt_to() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate_encryption("says-sig");
    let mut published = key.public_for_encryption();
    published.set_algorithm("RSA-OAEP-256");
    published.set_key_use("sig");
    plane
        .register_client_encryption(
            support::CONFIDENTIAL,
            serde_json::json!({ "keys": [published.as_ref()] }),
            Some(asking()),
            None,
        )
        .await;

    let code = code_for(&plane).await;
    let (status, answered) = exchanged(&plane, &code).await;
    assert_ne!(status, StatusCode::OK, "a readable token was handed out");
    assert_eq!(answered["id_token"], Value::Null, "{answered}");
}

/// A client publishes what it publishes, in the order it likes.
///
/// The one that suits sits behind two that do not: a signing key of the same
/// kind, and an encryption key of another. Taking the first and handing it over
/// would be refused by the encrypter, with a fitting key sitting right there.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_fitting_key_is_found_behind_the_ones_that_do_not_fit() {
    let plane = Plane::with_actions(&[]).await;

    let signing = SigningKey::generate_encryption("for-signing");
    let mut first = signing.public_for_encryption();
    first.set_algorithm("RSA-OAEP-256");
    first.set_key_use("sig");

    let elliptic = SigningKey::generate("wrong-kind");
    let mut second = elliptic.public();
    second.set_key_use("enc");

    let key = SigningKey::generate_encryption("the-one");
    plane
        .register_client_encryption(
            support::CONFIDENTIAL,
            serde_json::json!({
                "keys": [first.as_ref(), second.as_ref(), key.public_for_encryption().as_ref()]
            }),
            Some(asking()),
            None,
        )
        .await;

    let code = code_for(&plane).await;
    let (status, answered) = exchanged(&plane, &code).await;
    assert_eq!(status, StatusCode::OK, "{answered}");

    let told = answered["id_token"].as_str().expect("an identity token");
    let (_, header) = opened(&key, told);
    assert_eq!(
        header.key_id(),
        Some("the-one"),
        "the answer named a key other than the one that opens it"
    );
}

/// The userinfo answer is a JWT rather than claims, and opening it gives the
/// claims themselves: nothing was signed, so nothing inside is a signature.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn userinfo_is_wrapped_for_the_client_that_asked() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate_encryption("wrapping");
    plane
        .register_client_encryption(
            support::CONFIDENTIAL,
            serde_json::json!({ "keys": [key.public_for_encryption().as_ref()] }),
            None,
            Some(asking()),
        )
        .await;

    let code = code_for(&plane).await;
    let (_, answered) = exchanged(&plane, &code).await;
    let access = answered["access_token"].as_str().expect("an access token");

    let (status, kind, body) = userinfo_with(&plane, access).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(kind, "application/jwt");
    assert_eq!(body.split('.').count(), 5, "the answer was not encrypted");

    let (inside, header) = opened(&key, &body);
    assert_eq!(
        header.content_type(),
        None,
        "nothing was signed, so nothing inside is a token"
    );
    let claims: Value = serde_json::from_str(&inside).expect("claims");
    assert!(claims["sub"].as_str().is_some(), "{claims}");
    // §5.3.2: named, so an answer cannot be replayed at another client as its
    // own.
    assert_eq!(claims["aud"], support::CONFIDENTIAL);
    assert!(claims["iss"].as_str().is_some(), "{claims}");
}

/// Registered together, the answer is signed and then encrypted.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn userinfo_signed_and_encrypted_is_a_signature_inside_a_wrapper() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate_encryption("wrapping");
    plane
        .register_client_encryption(
            support::CONFIDENTIAL,
            serde_json::json!({ "keys": [key.public_for_encryption().as_ref()] }),
            None,
            Some(asking()),
        )
        .await;
    plane
        .register_userinfo_signature(support::CONFIDENTIAL, crypto::provider::SignAlg::Es256)
        .await;

    let code = code_for(&plane).await;
    let (_, answered) = exchanged(&plane, &code).await;
    let access = answered["access_token"].as_str().expect("an access token");

    let (status, kind, body) = userinfo_with(&plane, access).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(kind, "application/jwt");

    let (inside, header) = opened(&key, &body);
    assert_eq!(header.content_type(), Some("JWT"));
    assert_eq!(
        inside.split('.').count(),
        3,
        "what was inside was not signed"
    );
}
