#[allow(unused_imports)]
use super::support;
use super::support::{Plane, cookie_value, urlencode};
use actix_web::http::StatusCode;
use actix_web::{App, test};
use models::entities::realm::ClientRegistration;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};

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

/// Register a client, and hand back its identifier, secret and redirect.
async fn registered(plane: &Plane, redirect: &str, sector: Option<&str>) -> (String, String) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut body = json!({
        "redirect_uris": [redirect],
        "response_types": ["code"],
        "grant_types": ["authorization_code"],
        "subject_type": "pairwise",
    });
    if let Some(sector) = sector {
        body["sector_identifier_uri"] = json!(sector);
    }
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/register",
                support::REALM
            ))
            .set_json(&body)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let held: Value = test::read_body_json(response).await;
    assert_eq!(held["subject_type"].as_str(), Some("pairwise"), "{held}");
    (
        held["client_id"]
            .as_str()
            .expect("an identifier")
            .to_owned(),
        held["client_secret"].as_str().expect("a secret").to_owned(),
    )
}

/// Sign in for this client and hand back the identity token's subject.
async fn subject_told(plane: &Plane, client_id: &str, secret: &str, redirect: &str) -> String {
    granted_to(plane, client_id, secret, redirect).await.0
}

/// The same, with the access token it came with.
async fn granted_to(
    plane: &Plane,
    client_id: &str,
    secret: &str,
    redirect: &str,
) -> (String, String) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?client_id={client_id}\
                 &redirect_uri={}&scope=openid%20profile&state=s&response_type=code",
                support::REALM,
                urlencode(redirect),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
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
        .expect("somewhere to land")
        .to_owned();
    let code = landing
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/token",
                support::REALM
            ))
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", redirect),
                ("client_id", client_id),
                ("client_secret", secret),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let granted: Value = test::read_body_json(response).await;
    let identity = granted["id_token"].as_str().expect("an identity token");
    (
        plane.claims_of(identity).await["sub"]
            .as_str()
            .expect("a subject")
            .to_owned(),
        granted["access_token"]
            .as_str()
            .expect("an access token")
            .to_owned(),
    )
}

/// §8: one account, two sectors, two identifiers, and neither is the
/// account's own.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn two_sectors_are_told_two_identifiers_for_one_account() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;

    let here = "https://one.example/cb";
    let there = "https://two.example/cb";
    let (first, first_secret) = registered(&plane, here, None).await;
    let (second, second_secret) = registered(&plane, there, None).await;

    let told_here = subject_told(&plane, &first, &first_secret, here).await;
    let told_there = subject_told(&plane, &second, &second_secret, there).await;

    assert_ne!(
        told_here, told_there,
        "two sectors were told the same identifier"
    );
    for told in [&told_here, &told_there] {
        assert_ne!(
            told.as_str(),
            support::SUBJECT,
            "a paired client was told the account's own identifier"
        );
    }

    // The same client is told the same thing every time, or nothing that holds
    // one could recognise the person again.
    assert_eq!(
        subject_told(&plane, &first, &first_secret, here).await,
        told_here
    );
}

/// §5: the document a sector identifier names is fetched and read, and a
/// registration whose document cannot be reached is refused rather than
/// accepted on the client's word.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_sector_document_that_cannot_be_read_refuses_the_registration() {
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
                "redirect_uris": ["https://one.example/cb"],
                "subject_type": "pairwise",
                "sector_identifier_uri": "https://nothing.invalid/uris.json",
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
    // Which check refused, not merely that one did: a document treated as
    // empty rather than as unread refuses for the wrong reason and lets a
    // client registering no redirect through.
    assert!(
        answered["error_description"]
            .as_str()
            .is_some_and(|told| told.contains("could not be read")),
        "{answered}"
    );
}

/// Userinfo answers under the identifier the token carries, §5.3.2, and the
/// person behind it is found from it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn userinfo_answers_under_the_identifier_it_was_asked_with() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let here = "https://one.example/cb";
    let (client_id, secret) = registered(&plane, here, None).await;
    let (told, access) = granted_to(&plane, &client_id, &secret, here).await;

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
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
    assert_eq!(response.status(), StatusCode::OK);
    let claims: Value = test::read_body_json(response).await;
    // §5.3.2: the same identifier the token carried, and the person behind it
    // found from it rather than from anything the request said.
    assert_eq!(claims["sub"].as_str(), Some(told.as_str()), "{claims}");
    assert_eq!(
        claims["preferred_username"].as_str(),
        Some(support::SUBJECT),
        "the account behind the identifier was not found: {claims}"
    );

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
    let types = published["subject_types_supported"]
        .as_array()
        .expect("the subject types");
    assert!(
        types.iter().any(|held| held.as_str() == Some("pairwise")),
        "pairwise is issued and not named: {published}"
    );
}

/// A subject type §8 does not name is refused rather than reshaped.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_subject_type_the_spec_does_not_name_is_refused() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    for named in ["shared", "PAIRWISE", ""] {
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(&format!(
                    "/realms/{}/protocol/openid-connect/register",
                    support::REALM
                ))
                .set_json(json!({
                    "redirect_uris": ["https://app.example/cb"],
                    "subject_type": named,
                }))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{named}");
    }

    // §5: the document is fetched, so it is named somewhere this server can go.
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/register",
                support::REALM
            ))
            .set_json(json!({
                "redirect_uris": ["https://app.example/cb"],
                "subject_type": "pairwise",
                "sector_identifier_uri": "http://sector.example/uris.json",
            }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// A client switched to paired identifiers stops recognising what it was told
/// before. The identifier in an older token stands for nobody here, and
/// standing for itself would be the account's own name coming back.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_identifier_nobody_wears_is_nobody() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let here = "https://one.example/cb";

    // Registered public, so what it is told is the account's own identifier.
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/register",
                support::REALM
            ))
            .set_json(json!({
                "redirect_uris": [here],
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
            }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let held: Value = test::read_body_json(response).await;
    let client_id = held["client_id"].as_str().unwrap().to_owned();
    let secret = held["client_secret"].as_str().unwrap().to_owned();

    let (told, access) = granted_to(&plane, &client_id, &secret, here).await;
    assert_eq!(told, support::SUBJECT);

    plane.pair_subjects(&client_id).await;

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
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "an identifier nobody wears was read as the account it names"
    );
}

/// §5.3.2: a client that registered a signed response is answered with a JWS
/// carrying the issuer and itself, and never with plain JSON.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_that_asked_for_a_signature_is_answered_with_one() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let here = "https://one.example/cb";

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/register",
                support::REALM
            ))
            .set_json(json!({
                "redirect_uris": [here],
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
                "userinfo_signed_response_alg": "ES256",
            }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let held: Value = test::read_body_json(response).await;
    assert_eq!(
        held["userinfo_signed_response_alg"].as_str(),
        Some("ES256"),
        "{held}"
    );
    let client_id = held["client_id"].as_str().unwrap().to_owned();
    let secret = held["client_secret"].as_str().unwrap().to_owned();
    let (_, access) = granted_to(&plane, &client_id, &secret, here).await;

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
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/jwt")
    );
    let told = String::from_utf8_lossy(&test::read_body(response).await).into_owned();
    // Verified against the key the realm published, and read without a token's
    // own checks: §5.3.2 gives this response no lifetime, so it has no expiry.
    let verifier = crypto::jose::jws::ES256
        .verifier_from_jwk(&plane.key.public())
        .expect("a verifier");
    let (payload, header) =
        crypto::jose::jwt::decode_with_verifier(&told, &verifier).expect("a signed response");
    assert_eq!(header.claim("alg").and_then(Value::as_str), Some("ES256"));
    let carried = Value::Object(payload.claims_set().clone());
    assert_eq!(
        carried["iss"].as_str(),
        Some(support::origin().issuer(support::REALM).as_str()),
        "{carried}"
    );
    assert_eq!(
        carried["aud"].as_str(),
        Some(client_id.as_str()),
        "{carried}"
    );
    assert_eq!(
        carried["preferred_username"].as_str(),
        Some(support::SUBJECT),
        "{carried}"
    );

    // Discovery names what a client may register to be answered with.
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
    let named = published["userinfo_signing_alg_values_supported"]
        .as_array()
        .expect("the algorithms");
    assert!(
        named.iter().any(|held| held.as_str() == Some("ES256")),
        "{published}"
    );

    // §5.3.2 again: an algorithm this realm holds no key for is not answered
    // in the clear. A client about to read a signature would get none.
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/register",
                support::REALM
            ))
            .set_json(json!({
                "redirect_uris": [here],
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
                "userinfo_signed_response_alg": "PS512",
            }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let held: Value = test::read_body_json(response).await;
    let unsignable = held["client_id"].as_str().unwrap().to_owned();
    let secret = held["client_secret"].as_str().unwrap().to_owned();
    let (_, access) = granted_to(&plane, &unsignable, &secret, here).await;
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
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "a registered signature was answered without one"
    );
}
