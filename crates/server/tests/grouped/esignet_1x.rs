//! The broker against a real MOSIP eSignet 1.x, the generation MOSIP's Collab
//! environment runs, when one is up. It verifies client assertions in RS256
//! alone, addressed to its token endpoint exactly, and names itself in its
//! tokens with `/v1/esignet` after the issuer its discovery document gives.
//! Every leg is the real one: the person is planted in the mock identity
//! system, the client registered with the key the provider drew, the sign-in
//! walked as eSignet's own page walks it, and the code redeemed by the broker.
use super::broker_login::{asked, mounted_at};
use super::support::{self, Plane};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use config::serving::{Egress, PublicOrigin};
use crypto::provider::{CryptoProvider, HashAlg};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;
/// Where the person comes back: eSignet 1.x will not send anyone to the
/// reserved `.test` domain the rest of the bench lives under.
const ORIGIN: &str = "https://id.example.com";
const CONTEXT: &str = "mosip:idp:acr:generated-code";

/// eSignet's host, when one is up: the root its discovery document names as
/// the issuer. Absent, each journey is skipped rather than failed.
fn find_esignet_address() -> Option<String> {
    std::env::var("SAFFUI_TEST_ESIGNET_1X")
        .ok()
        .filter(|address| !address.is_empty())
}

/// Where the mock identity system takes the people this bench plants.
fn find_identity_system_address() -> String {
    std::env::var("SAFFUI_TEST_ESIGNET_1X_IDENTITY")
        .ok()
        .filter(|address| !address.is_empty())
        .unwrap_or_else(|| "http://localhost:18082/v1/mock-identity-system".to_owned())
}

fn origin() -> PublicOrigin {
    PublicOrigin::parse(ORIGIN).expect("a usable origin")
}

fn draw_hex(bytes: usize) -> String {
    let mut drawn = vec![0u8; bytes];
    support::provider()
        .rand()
        .fill(&mut drawn)
        .expect("random bytes");
    data_encoding::HEXLOWER.encode(&drawn)
}

fn format_request_time() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// eSignet's answer to one call: its status, its body, and the anti-forgery
/// token it set, if it set one.
struct Answered {
    status: u16,
    told: Value,
    xsrf: Option<String>,
}

/// One call to eSignet or its identity system as eSignet's own page makes it:
/// JSON in and out, the anti-forgery token as both cookie and header once one
/// is held, and the headers a step names.
async fn call_as_page(
    method: &'static str,
    url: String,
    body: Option<Value>,
    xsrf: Option<String>,
    headers: Vec<(&'static str, String)>,
) -> Answered {
    tokio::task::spawn_blocking(move || {
        let agent = outbound::egress::outward_agent_reading_refusals(
            Egress::Anywhere,
            std::time::Duration::from_secs(20),
        );
        let mut asking = match method {
            "GET" => agent.get(&url).force_send_body(),
            _ => agent.post(&url),
        };
        if let Some(token) = &xsrf {
            asking = asking
                .header("cookie", format!("XSRF-TOKEN={token}"))
                .header("X-XSRF-TOKEN", token);
        }
        for (name, value) in &headers {
            asking = asking.header(*name, value);
        }
        let mut response = match body {
            Some(body) => asking
                .header("content-type", "application/json")
                .send(body.to_string()),
            None => asking.send_empty(),
        }
        .expect("an answer");
        let xsrf = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|held| held.to_str().ok())
            .find_map(|cookie| {
                cookie
                    .split(';')
                    .next()?
                    .strip_prefix("XSRF-TOKEN=")
                    .map(str::to_owned)
            });
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().unwrap_or_default();
        Answered {
            status,
            told: serde_json::from_str(&text).unwrap_or(Value::Null),
            xsrf,
        }
    })
    .await
    .expect("the call comes back")
}

/// A fresh anti-forgery token from eSignet.
async fn draw_xsrf(api: &str) -> String {
    call_as_page("GET", format!("{api}/csrf/token"), None, None, Vec::new())
        .await
        .xsrf
        .expect("an anti-forgery token")
}

/// A person of this run's own, under a number drawn for it, who signs in with
/// the one-time code the mock identity system always takes.
async fn plant_national_person() -> String {
    let drawn = u64::from_str_radix(&draw_hex(8), 16).expect("a number");
    let individual_id = (1_000_000_000 + drawn % 9_000_000_000).to_string();
    let spoken = |value: &str| json!([{ "language": "eng", "value": value }]);
    let planted = call_as_page(
        "POST",
        format!("{}/identity", find_identity_system_address()),
        Some(json!({
            "requestTime": format_request_time(),
            "request": {
                "individualId": individual_id,
                "pin": "482913",
                "email": "ama.mensah@example.test",
                "phone": "+22890000001",
                "fullName": spoken("Ama Mensah"),
                "givenName": spoken("Ama"),
                "middleName": spoken("Ama"),
                "familyName": spoken("Mensah"),
                "nickName": spoken("Ama"),
                "preferredUsername": spoken("ama"),
                "gender": spoken("Female"),
                "dateOfBirth": "1990/03/14",
                "streetAddress": spoken("Rue du Commerce"),
                "locality": spoken("Lome"),
                "region": spoken("Maritime"),
                "postalCode": "01000",
                "country": spoken("Togo"),
                "zoneInfo": "Africa/Lome",
                "preferredLang": "eng",
                "locale": "en",
                "password": "not-used",
                "encodedPhoto": "data:image/jpeg;base64,/9j/4AAQSkZJRgABAgAAAQABAAD",
            },
        })),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(planted.status, 200, "{}", planted.told);
    assert!(
        planted.told["errors"].as_array().is_none_or(Vec::is_empty),
        "{}",
        planted.told
    );
    individual_id
}

/// What eSignet publishes about itself, read through the admin plane the way
/// the console reads it when an operator names the issuer: the endpoints, and
/// RS256 proposed for assertions, the one algorithm it verifies.
async fn discover_esignet(plane: &Plane, bearer: &str, esignet: &str) -> Value {
    let (status, found) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/provider-discovery"),
        bearer,
        Some(json!({ "issuer": esignet })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{found}");
    assert_eq!(found["assertion_alg"], "RS256", "{found}");
    assert_eq!(found["id_token_algs"], json!(["RS256"]), "{found}");
    assert_eq!(found["iss_parameter"], false, "{found}");
    found
}

/// The provider over the admin plane, its endpoints from eSignet's discovery
/// document, the issuer its tokens name, and `settings` for its assertions;
/// hands back the public key it drew for the operator to register there.
async fn create_provider(
    plane: &Plane,
    bearer: &str,
    found: &Value,
    alias: &str,
    issuer: &str,
    settings: Value,
) -> Value {
    let mut configs = json!({
        "issuer": { "Str": issuer },
        "authorization_endpoint": { "Str": found["authorization_endpoint"] },
        "token_endpoint": { "Str": found["token_endpoint"] },
        "jwks_uri": { "Str": found["jwks_uri"] },
        "client_id": { "Str": alias },
        "token_auth": { "Str": "private_key_jwt" },
        "scope": { "Str": "openid profile" },
        "allowed_algs": { "Str": "RS256" },
        "accepted_acrs": { "Str": format!("{CONTEXT}={}", support::PASSWORD_ACR) },
    });
    for (key, value) in settings.as_object().expect("settings") {
        configs[key] = value.clone();
    }
    let (status, told) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        bearer,
        Some(json!({
            "provider_id": alias,
            "name": alias,
            "display_name": "National ID",
            "description": "",
            "trust_email": false,
            "configs": configs,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let written = told["configs"]["assertion_jwk"]["Str"]
        .as_str()
        .unwrap_or_else(|| panic!("the provider shows no assertion key: {told}"));
    serde_json::from_str(written).expect("a JWK")
}

/// Where the broker takes the person back for `alias`.
fn landing_of(alias: &str) -> String {
    format!(
        "{}/protocol/openid-connect/broker/{alias}/endpoint",
        origin().issuer(REALM)
    )
}

/// The client at eSignet, registered as a partner onboarding would, with the
/// provider's public key and the one context it may sign in by.
async fn register_client(api: &str, alias: &str, assertion_jwk: Value) {
    let xsrf = draw_xsrf(api).await;
    let registered = call_as_page(
        "POST",
        format!("{api}/client-mgmt/client"),
        Some(json!({
            "requestTime": format_request_time(),
            "request": {
                "clientId": alias,
                "clientName": "saffui bench",
                "relyingPartyId": alias,
                "logoUri": "https://id.example.com/logo.png",
                "redirectUris": [landing_of(alias)],
                "publicKey": assertion_jwk,
                "authContextRefs": [CONTEXT],
                "userClaims": ["name", "email", "birthdate", "gender", "phone_number"],
                "grantTypes": ["authorization_code"],
                "clientAuthMethods": ["private_key_jwt"],
                "additionalConfig": { "userinfo_response_type": "JWS", "consent_expire_in_mins": 10 },
            },
        })),
        Some(xsrf),
        Vec::new(),
    )
    .await;
    assert_eq!(registered.status, 200, "{}", registered.told);
    assert_eq!(
        registered.told["response"]["status"], "ACTIVE",
        "{}",
        registered.told
    );
}

/// Open this realm's login under the origin eSignet sends people back to,
/// leave it for eSignet, and hand back the login's cookie and the departure.
async fn leave_for_esignet(plane: &Plane, alias: &str) -> (String, String) {
    let app =
        test::init_service(App::new().configure(register(&mounted_at(plane, origin())))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope=openid&state=s&nonce=n-local",
                support::CONFIDENTIAL,
                support::urlencode(support::REDIRECT),
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
    let cookie = support::cookie_value(&cookies, support::AUTH_SESSION_COOKIE)
        .expect("a login")
        .to_owned();
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/{alias}/login"
            ))
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let departure = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .expect("a departure")
        .to_owned();
    (cookie, departure)
}

/// Walk eSignet's own sign-in as the person, the way its page does from the
/// departure: the transaction the departure opens, the one-time code sent and
/// answered, and the code eSignet hands out. Gives back the code and state.
async fn sign_in_at_esignet(api: &str, departure: &str, individual_id: &str) -> (String, String) {
    let asked_for: std::collections::HashMap<String, String> = url::Url::parse(departure)
        .expect("a departure address")
        .query_pairs()
        .into_owned()
        .collect();
    let named = |name: &str| {
        asked_for
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("the departure names no {name}: {departure}"))
    };
    let mut xsrf = draw_xsrf(api).await;
    let details = call_as_page(
        "POST",
        format!("{api}/authorization/v3/oauth-details"),
        Some(json!({
            "requestTime": format_request_time(),
            "request": {
                "clientId": named("client_id"),
                "scope": named("scope"),
                "responseType": named("response_type"),
                "redirectUri": named("redirect_uri"),
                "display": "page",
                "prompt": "login",
                "acrValues": named("acr_values"),
                "nonce": named("nonce"),
                "state": named("state"),
                "claimsLocales": "en",
                "codeChallenge": named("code_challenge"),
                "codeChallengeMethod": named("code_challenge_method"),
            },
        })),
        Some(xsrf.clone()),
        Vec::new(),
    )
    .await;
    xsrf = details.xsrf.unwrap_or(xsrf);
    let response = &details.told["response"];
    let transaction = response["transactionId"]
        .as_str()
        .unwrap_or_else(|| panic!("no transaction opened: {}", details.told))
        .to_owned();
    // The page proves it read these details by their hash, the answer written
    // back compactly in the order eSignet wrote it.
    let hash = CryptoProvider::digest(&support::provider())
        .hash(
            HashAlg::Sha256,
            serde_json::to_string(response)
                .expect("the details")
                .as_bytes(),
        )
        .expect("a digest");
    let bound = || {
        vec![
            ("oauth-details-key", transaction.clone()),
            (
                "oauth-details-hash",
                data_encoding::BASE64URL_NOPAD.encode(&hash),
            ),
        ]
    };
    for (step, request) in [
        (
            "send-otp",
            json!({
                "transactionId": transaction,
                "individualId": individual_id,
                "otpChannels": ["email"],
                "captchaToken": "bench",
            }),
        ),
        (
            "v3/authenticate",
            json!({
                "transactionId": transaction,
                "individualId": individual_id,
                "challengeList": [{
                    "authFactorType": "OTP",
                    "challenge": "111111",
                    "format": "alpha-numeric",
                }],
            }),
        ),
    ] {
        let done = call_as_page(
            "POST",
            format!("{api}/authorization/{step}"),
            Some(json!({ "requestTime": format_request_time(), "request": request })),
            Some(xsrf.clone()),
            bound(),
        )
        .await;
        assert!(
            done.status == 200 && done.told["errors"].as_array().is_none_or(Vec::is_empty),
            "{step}: {}",
            done.told
        );
        xsrf = done.xsrf.unwrap_or(xsrf);
    }
    let granted = call_as_page(
        "POST",
        format!("{api}/authorization/auth-code"),
        Some(json!({
            "requestTime": format_request_time(),
            "request": {
                "transactionId": transaction,
                "acceptedClaims": [],
                "permittedAuthorizeScopes": [],
            },
        })),
        Some(xsrf),
        bound(),
    )
    .await;
    let given = &granted.told["response"];
    let code = given["code"]
        .as_str()
        .unwrap_or_else(|| panic!("no code handed out: {}", granted.told));
    assert_eq!(
        given["redirectUri"],
        named("redirect_uri"),
        "{}",
        granted.told
    );
    (
        code.to_owned(),
        given["state"].as_str().expect("the state").to_owned(),
    )
}

/// Come back with eSignet's code, in the browser that left.
async fn come_back(
    plane: &Plane,
    alias: &str,
    cookie: &str,
    code: &str,
    state: &str,
) -> (StatusCode, Option<String>) {
    let app =
        test::init_service(App::new().configure(register(&mounted_at(plane, origin())))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/{alias}/endpoint?code={}&state={}",
                support::urlencode(code),
                support::urlencode(state),
            ))
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    let location = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .map(str::to_owned);
    (response.status(), location)
}

/// Who the provider linked, if anyone.
async fn read_linked_person(plane: &Plane, alias: &str) -> Option<String> {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    transaction
        .query_opt(
            "SELECT user_id FROM federated_identities WHERE provider_alias = $1",
            &[&alias],
        )
        .await
        .expect("the links")
        .map(|row| row.get(0))
}

/// One person's sign-in through `alias` from departure to way back.
async fn cross(plane: &Plane, api: &str, alias: &str) -> (StatusCode, Option<String>) {
    let individual_id = plant_national_person().await;
    let (cookie, departure) = leave_for_esignet(plane, alias).await;
    let (code, state) = sign_in_at_esignet(api, &departure, &individual_id).await;
    come_back(plane, alias, &cookie, &code, &state).await
}

/// A person signs in through eSignet 1.x: the broker signs its assertion RS256
/// with the key it drew, addresses it to the token endpoint, reads the identity
/// token under the issuer eSignet names itself by there, and admits the login
/// at the level the realm gives the context eSignet vouched for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG) and an eSignet 1.x (SAFFUI_TEST_ESIGNET_1X)"]
async fn a_person_signs_in_through_esignet_1x_by_an_rs256_assertion() {
    let Some(esignet) = find_esignet_address() else {
        eprintln!("SAFFUI_TEST_ESIGNET_1X unset; the journey has no eSignet 1.x to cross");
        return;
    };
    let api = format!("{esignet}/v1/esignet");
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let found = discover_esignet(&plane, &bearer, &esignet).await;
    let alias = format!("older-{}", draw_hex(4));
    let assertion_jwk = create_provider(
        &plane,
        &bearer,
        &found,
        &alias,
        &api,
        json!({
            "assertion_alg": { "Str": found["assertion_alg"] },
            "assertion_audience": { "Str": "token_endpoint" },
        }),
    )
    .await;
    assert_eq!(
        (&assertion_jwk["kty"], &assertion_jwk["alg"]),
        (&json!("RSA"), &json!("RS256"))
    );
    register_client(&api, &alias, assertion_jwk).await;

    let (status, landing) = cross(&plane, &api, &alias).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{landing:?}");
    let landing = landing.expect("a landing");
    assert!(landing.starts_with(support::REDIRECT), "{landing}");
    let linked = read_linked_person(&plane, &alias)
        .await
        .expect("a link was written");
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    let logins = store::providers::protocol::sessions::load_for_user(&transaction, &linked)
        .await
        .expect("the logins");
    assert!(
        logins.iter().any(|login| login.loa == Some(1)),
        "the login was not admitted at the level the realm gives password: {logins:?}"
    );
}

/// What eSignet 1.x refuses, each at the leg that refuses it: an assertion
/// addressed to its issuer, one signed PS256, and an identity token held to
/// the issuer its discovery document names rather than the one its tokens do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG) and an eSignet 1.x (SAFFUI_TEST_ESIGNET_1X)"]
async fn esignet_1x_refuses_what_it_does_not_verify() {
    let Some(esignet) = find_esignet_address() else {
        eprintln!("SAFFUI_TEST_ESIGNET_1X unset; the journey has no eSignet 1.x to cross");
        return;
    };
    let api = format!("{esignet}/v1/esignet");
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let found = discover_esignet(&plane, &bearer, &esignet).await;
    for (settings, issuer) in [
        (json!({ "assertion_alg": { "Str": "RS256" } }), api.clone()),
        (
            json!({ "assertion_audience": { "Str": "token_endpoint" } }),
            api.clone(),
        ),
        (
            json!({
                "assertion_alg": { "Str": "RS256" },
                "assertion_audience": { "Str": "token_endpoint" },
            }),
            esignet.clone(),
        ),
    ] {
        let alias = format!("refused-{}", draw_hex(4));
        let assertion_jwk =
            create_provider(&plane, &bearer, &found, &alias, &issuer, settings.clone()).await;
        register_client(&api, &alias, assertion_jwk).await;
        let (status, landing) = cross(&plane, &api, &alias).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{settings} {issuer}: {landing:?}"
        );
        assert_eq!(
            read_linked_person(&plane, &alias).await,
            None,
            "{settings} {issuer}"
        );
    }
}
