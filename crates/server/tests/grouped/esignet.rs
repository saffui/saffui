//! The broker against a real MOSIP eSignet, the one `deploy/esignet` runs,
//! when one is up. Every leg is the real one: the person is planted in the mock
//! identity system, the client is registered with the keys the provider drew,
//! the sign-in is walked through eSignet's own flow, and the broker redeems the
//! code, reads the encrypted userinfo and admits the login.
use super::broker_login::{asked, mounted, opened_login, param};
use super::support::{self, Plane};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use config::serving::Egress;
use crypto::provider::CryptoProvider;
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;
const ALIAS: &str = "national";

/// eSignet's issuer, when one is up. Absent, each journey is skipped rather
/// than failed: eSignet is infrastructure, not an assertion.
fn find_esignet_address() -> Option<String> {
    std::env::var("SAFFUI_TEST_ESIGNET")
        .ok()
        .filter(|address| !address.is_empty())
}

/// Where the mock identity system takes the people this bench plants.
fn find_identity_system_address() -> String {
    std::env::var("SAFFUI_TEST_ESIGNET_IDENTITY")
        .ok()
        .filter(|address| !address.is_empty())
        .unwrap_or_else(|| "http://localhost:8082/v1/mock-identity-system".to_owned())
}

/// A person of this run's own, under a number drawn for it, answering the
/// knowledge-based sign-in with their name and date of birth.
struct NationalPerson {
    individual_id: String,
    full_name: &'static str,
    birth_date: &'static str,
}

fn draw_hex(bytes: usize) -> String {
    let mut drawn = vec![0u8; bytes];
    support::provider()
        .rand()
        .fill(&mut drawn)
        .expect("random bytes");
    data_encoding::HEXLOWER.encode(&drawn)
}

/// One call to eSignet or its identity system, on the broker's own agent:
/// every answer is kept whatever its status, and no redirect is followed.
async fn call_json(
    method: &'static str,
    url: String,
    body: Option<Value>,
) -> (u16, Value, Option<String>) {
    tokio::task::spawn_blocking(move || {
        let agent = outbound::egress::outward_agent_reading_refusals(
            Egress::Anywhere,
            std::time::Duration::from_secs(20),
        );
        let mut response = match (method, body) {
            ("GET", _) => agent.get(&url).call(),
            (_, Some(body)) => agent
                .post(&url)
                .header("content-type", "application/json")
                .send(body.to_string()),
            (_, None) => agent.post(&url).send_empty(),
        }
        .expect("an answer");
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get("location")
            .and_then(|held| held.to_str().ok())
            .map(str::to_owned);
        let text = response.body_mut().read_to_string().unwrap_or_default();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::Null),
            location,
        )
    })
    .await
    .expect("the call comes back")
}

fn format_request_time() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

async fn plant_national_person() -> NationalPerson {
    let drawn = u64::from_str_radix(&draw_hex(8), 16).expect("a number");
    let person = NationalPerson {
        individual_id: (1_000_000_000 + drawn % 9_000_000_000).to_string(),
        full_name: "Ama Mensah",
        birth_date: "1990/03/14",
    };
    let spoken = |value: &str| json!([{ "language": "eng", "value": value }]);
    let (status, told, _) = call_json(
        "POST",
        format!("{}/identity", find_identity_system_address()),
        Some(json!({
            "requestTime": format_request_time(),
            "request": {
                "individualId": person.individual_id,
                "pin": "482913",
                "email": "ama.mensah@example.test",
                "phone": "+22890000001",
                "fullName": spoken(person.full_name),
                "givenName": spoken("Ama"),
                "middleName": spoken("Ama"),
                "familyName": spoken("Mensah"),
                "nickName": spoken("Ama"),
                "preferredUsername": spoken("ama"),
                "gender": spoken("Female"),
                "dateOfBirth": person.birth_date,
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
    )
    .await;
    assert_eq!(status, 200, "{told}");
    assert!(
        told["errors"].as_array().is_none_or(Vec::is_empty),
        "{told}"
    );
    person
}

/// What eSignet publishes about itself, read through the admin plane the way
/// the console reads it when an operator names the issuer.
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
    assert_eq!(found["iss_parameter"], true, "{found}");
    assert_eq!(found["gaps"], json!([]), "{found}");
    assert_eq!(found["id_token_algs"], json!(["PS256"]), "{found}");
    found
}

/// The provider over the admin plane, its endpoints from eSignet's discovery
/// document and the rest from what eSignet asks for, and the two public keys
/// it drew for the operator to register there.
async fn create_national_provider(
    plane: &Plane,
    bearer: &str,
    esignet: &str,
    client_id: &str,
    accepted_acrs: &str,
) -> (Value, Value) {
    let found = discover_esignet(plane, bearer, esignet).await;
    let (status, told) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        bearer,
        Some(json!({
            "provider_id": ALIAS,
            "name": ALIAS,
            "display_name": "National ID",
            "description": "",
            "trust_email": false,
            "configs": {
                "issuer": { "Str": found["issuer"] },
                "authorization_endpoint": { "Str": found["authorization_endpoint"] },
                "token_endpoint": { "Str": found["token_endpoint"] },
                "jwks_uri": { "Str": found["jwks_uri"] },
                "userinfo_endpoint": { "Str": found["userinfo_endpoint"] },
                "iss_parameter": { "Str": "required" },
                "client_id": { "Str": client_id },
                "token_auth": { "Str": "private_key_jwt" },
                "scope": { "Str": "openid profile email" },
                "allowed_algs": { "Str": "PS256" },
                "userinfo_response": { "Str": "jwe" },
                "userinfo_algs": { "Str": "RS256 PS256" },
                "claims": { "Str": json!({ "userinfo": {
                    "name": { "essential": true },
                    "email": { "essential": false },
                    "birthdate": { "essential": false },
                }}).to_string() },
                "accepted_acrs": { "Str": accepted_acrs },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let public = |field: &str| -> Value {
        let written = told["configs"][field]["Str"]
            .as_str()
            .unwrap_or_else(|| panic!("the provider shows no {field}: {told}"));
        serde_json::from_str(written).expect("a JWK")
    };
    assert!(
        told["configs"].get("assertion_key_sealed").is_none()
            && told["configs"].get("encryption_key_sealed").is_none(),
        "an answer carried a sealed private key: {told}"
    );
    (public("assertion_jwk"), public("encryption_jwk"))
}

/// The client at eSignet, registered the way a partner onboarding would, with
/// the provider's two public keys and the one context it may sign in by.
async fn register_esignet_client(
    esignet: &str,
    client_id: &str,
    assertion_jwk: Value,
    encryption_jwk: Value,
    registered_acr: &str,
) {
    let landing = format!(
        "{}/protocol/openid-connect/broker/{ALIAS}/endpoint",
        support::origin().issuer(REALM)
    );
    let (status, told, _) = call_json(
        "POST",
        format!("{esignet}/client-mgmt/client"),
        Some(json!({
            "requestTime": format_request_time(),
            "request": {
                "clientId": client_id,
                "clientName": "saffui bench",
                "clientNameLangMap": { "eng": "saffui bench" },
                "relyingPartyId": client_id,
                "logoUri": "https://id.test/logo.png",
                "redirectUris": [landing],
                "publicKey": assertion_jwk,
                "encPublicKey": encryption_jwk,
                "authContextRefs": [registered_acr],
                "userClaims": ["name", "email", "birthdate", "gender", "phone_number"],
                "grantTypes": ["authorization_code"],
                "clientAuthMethods": ["private_key_jwt"],
                "additionalConfig": { "userinfo_response_type": "JWE", "consent_expire_in_mins": 10 },
            },
        })),
    )
    .await;
    assert_eq!(status, 200, "{told}");
    assert_eq!(told["response"]["status"], "ACTIVE", "{told}");
}

/// Leave this realm's login for eSignet, and hand back where the browser goes.
async fn leave_for_esignet(plane: &Plane, cookie: &str) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/{ALIAS}/login"
            ))
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .expect("a departure")
        .to_owned()
}

/// Walk eSignet's own sign-in as the person: the knowledge step, the consent
/// when asked, and the callback that hands the code to the way back.
async fn sign_in_at_esignet(esignet: &str, departure: &str, person: &NationalPerson) -> String {
    let (status, told, location) = call_json("GET", departure.to_owned(), None).await;
    assert_eq!(status, 302, "eSignet did not take the departure: {told}");
    let page = location.expect("eSignet's sign-in page");
    let auth_id = param(&page, "authId").expect("an authorization");
    let execution = param(&page, "executionId").expect("a flow");

    let execute = |body: Value| call_json("POST", format!("{esignet}/flow/execute"), Some(body));
    let (_, mut step, _) = execute(json!({ "executionId": execution })).await;
    let offered: Vec<&str> = step["data"]["actions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|action| action["ref"].as_str())
        .collect();
    assert!(offered.contains(&"submit_kbi_details"), "{step}");
    let (year, month, day) = {
        let mut parts = person.birth_date.split('/');
        (
            parts.next().expect("a year"),
            parts.next().expect("a month"),
            parts.next().expect("a day"),
        )
    };
    (_, step, _) = execute(json!({
        "executionId": execution,
        "challengeToken": step["challengeToken"],
        "action": "submit_kbi_details",
        "inputs": {
            "username": person.individual_id,
            "fullName": person.full_name,
            "dob": format!("{year}-{month}-{day}"),
            "captcha_token": "bench",
        },
    }))
    .await;
    if step["flowStatus"] != "COMPLETE" {
        let prompt: Value = serde_json::from_str(
            step["data"]["additionalData"]["consentPrompt"]
                .as_str()
                .unwrap_or_else(|| panic!("neither complete nor asking consent: {step}")),
        )
        .expect("a consent prompt");
        let purpose = &prompt[0];
        let elements: Vec<Value> = ["essential", "optional"]
            .iter()
            .flat_map(|kind| purpose[kind].as_array().cloned().unwrap_or_default())
            .map(|element| json!({ "approved": true, "name": element["name"] }))
            .collect();
        // The answer as a whole carries its own approval, and a missing one
        // denies every element beneath it.
        let decisions = json!({ "approved": true, "purposes": [{
            "approved": true,
            "elements": elements,
            "purposeName": purpose["purposeName"],
        }]});
        (_, step, _) = execute(json!({
            "executionId": execution,
            "challengeToken": step["challengeToken"],
            "action": "action_allow",
            "inputs": { "consent_decisions": decisions.to_string() },
        }))
        .await;
    }
    assert_eq!(step["flowStatus"], "COMPLETE", "{step}");
    let (status, told, _) = call_json(
        "POST",
        format!("{esignet}/oauth2/auth/callback"),
        Some(json!({ "authId": auth_id, "assertion": step["assertion"] })),
    )
    .await;
    assert_eq!(status, 200, "{told}");
    told["redirect_uri"]
        .as_str()
        .expect("the way back")
        .to_owned()
}

/// Come back through the way eSignet sent the browser, with the login's cookie.
async fn come_back(plane: &Plane, way_back: &str, cookie: &str) -> (StatusCode, Option<String>) {
    let path = way_back
        .strip_prefix(support::ORIGIN)
        .unwrap_or_else(|| panic!("eSignet sent the browser elsewhere: {way_back}"));
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(path)
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

/// Who the provider linked, under its pairwise subject, if anyone.
async fn read_linked_person(plane: &Plane) -> Option<String> {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    transaction
        .query_opt(
            "SELECT user_id FROM federated_identities WHERE provider_alias = $1",
            &[&ALIAS],
        )
        .await
        .expect("the links")
        .map(|row| row.get(0))
}

/// A person signs in through eSignet: the broker proves itself with the key it
/// drew, opens the userinfo encrypted to the other, writes what it says onto
/// the person, and admits the login at the level the realm gives the context
/// eSignet vouched for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG) and an eSignet (SAFFUI_TEST_ESIGNET, see deploy/esignet)"]
async fn a_person_signs_in_through_esignet_at_the_level_it_vouched_for() {
    let Some(esignet) = find_esignet_address() else {
        eprintln!("SAFFUI_TEST_ESIGNET unset; the journey has no eSignet to cross");
        return;
    };
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let person = plant_national_person().await;
    let client_id = format!("saffui-bench-{}", draw_hex(6));
    let (assertion_jwk, encryption_jwk) = create_national_provider(
        &plane,
        &bearer,
        &esignet,
        &client_id,
        "mosip:idp:acr:knowledge=password",
    )
    .await;
    assert_eq!(assertion_jwk["kty"], "RSA");
    assert_eq!(assertion_jwk["alg"], "PS256");
    assert_eq!(encryption_jwk["kty"], "RSA");
    register_esignet_client(
        &esignet,
        &client_id,
        assertion_jwk,
        encryption_jwk,
        "mosip:idp:acr:knowledge",
    )
    .await;
    let rules = format!("/admin/realms/{REALM}/identity-providers/{ALIAS}/mappers");
    for (claim, attribute) in [
        ("name", "national.name"),
        ("birthdate", "national.birthdate"),
    ] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &rules,
            &bearer,
            Some(json!({
                "name": format!("carry-{claim}"),
                "mapper_type": "oidc-user-attribute-idp-mapper",
                "configs": { "claim": { "Str": claim }, "user.attribute": { "Str": attribute } },
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{told}");
    }

    let cookie = opened_login(&plane).await;
    let departure = leave_for_esignet(&plane, &cookie).await;
    assert!(
        departure.starts_with(&format!("{esignet}/oauth2/authorize?")),
        "{departure}"
    );
    assert!(
        departure.contains("acr_values=mosip%3Aidp%3Aacr%3Aknowledge"),
        "{departure}"
    );
    assert!(departure.contains("&claims="), "{departure}");
    let way_back = sign_in_at_esignet(&esignet, &departure, &person).await;
    let (status, landing) = come_back(&plane, &way_back, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{landing:?}");
    let landing = landing.expect("a landing");
    assert!(landing.starts_with(support::REDIRECT), "{landing}");
    assert!(param(&landing, "code").is_some(), "{landing}");

    let linked = read_linked_person(&plane)
        .await
        .expect("a link was written");
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    let person_here = store::providers::directory::users::load(&transaction, &linked)
        .await
        .expect("the directory")
        .expect("the person the link names");
    let attribute = |name: &str| {
        person_here
            .attributes
            .as_ref()
            .and_then(|held| held.get(name))
            .and_then(|value| value.as_str())
            .map(str::to_owned)
    };
    assert_eq!(
        attribute("national.name").as_deref(),
        Some(person.full_name)
    );
    assert_eq!(
        attribute("national.birthdate").as_deref(),
        Some(person.birth_date)
    );
    assert!(
        person_here.email.is_empty(),
        "an address the provider is not trusted for was written: {}",
        person_here.email
    );
    let logins = store::providers::protocol::sessions::load_for_user(&transaction, &linked)
        .await
        .expect("the logins");
    assert!(
        logins.iter().any(|login| login.loa == Some(1)),
        "the login was not admitted at the level the realm gives password: {logins:?}"
    );
}

/// eSignet signs a person in by a context the realm did not accept when none
/// of those asked is registered for the client, and the way back refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG) and an eSignet (SAFFUI_TEST_ESIGNET, see deploy/esignet)"]
async fn a_weaker_context_than_the_realm_accepts_is_refused() {
    let Some(esignet) = find_esignet_address() else {
        eprintln!("SAFFUI_TEST_ESIGNET unset; the journey has no eSignet to cross");
        return;
    };
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let person = plant_national_person().await;
    let client_id = format!("saffui-bench-{}", draw_hex(6));
    let (assertion_jwk, encryption_jwk) = create_national_provider(
        &plane,
        &bearer,
        &esignet,
        &client_id,
        "mosip:idp:acr:biometrics=mfa",
    )
    .await;
    register_esignet_client(
        &esignet,
        &client_id,
        assertion_jwk,
        encryption_jwk,
        "mosip:idp:acr:knowledge",
    )
    .await;

    let cookie = opened_login(&plane).await;
    let departure = leave_for_esignet(&plane, &cookie).await;
    let way_back = sign_in_at_esignet(&esignet, &departure, &person).await;
    let (status, landing) = come_back(&plane, &way_back, &cookie).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a sign-in by knowledge was admitted where biometrics was asked: {landing:?}"
    );
    assert_eq!(
        read_linked_person(&plane).await,
        None,
        "a link was written anyway"
    );
}
