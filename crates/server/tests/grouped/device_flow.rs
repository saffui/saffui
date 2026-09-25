#[allow(unused_imports)]
use super::support;
use super::support::{Plane, cookie_value};
use actix_web::http::StatusCode;
use actix_web::{App, test};
use data_encoding::BASE64;
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        sealing: support::sealing(),
        ceiling: support::ceiling(),
        egress: config::serving::Egress::Outward,
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, REALM)
}

/// Opt the fixture's confidential client into the device grant.
async fn allow_device(plane: &Plane) {
    let transaction = plane.scoped(&within()).await;
    let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
        .await
        .expect("the clients table")
        .expect("a planted client");
    let mut bag = client.configs.take().unwrap_or_default();
    bag.insert(
        services::oidc::device::GRANT_FLAG.to_owned(),
        models::entities::attributes::AttributeValue::Str("enabled".to_owned()),
    );
    client.configs = Some(bag);
    store::providers::clients::update(&transaction, &client)
        .await
        .expect("the clients table");
    transaction.commit().await.expect("the flag kept");
}

async fn posted(plane: &Plane, path: &str, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let request = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect{path}"))
        .insert_header(("authorization", format!("Basic {encoded}")))
        .set_form(form)
        .to_request();
    let response = test::call_service(&app, request).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

async fn polled(plane: &Plane, device_code: &str) -> (StatusCode, Value) {
    posted(
        plane,
        "/token",
        &[
            ("grant_type", services::oidc::device::GRANT),
            ("device_code", device_code),
        ],
    )
    .await
}

/// Rewind the poll stamp, so the bench does not sleep through the interval.
async fn rewind_poll(plane: &Plane) {
    let transaction = plane.scoped(&within()).await;
    transaction
        .execute(
            "UPDATE oidc_device_codes SET last_polled_at = now() - interval '1 minute'",
            &[],
        )
        .await
        .expect("the stamp rewound");
    transaction.commit().await.expect("the stamp kept");
}

/// The person's half: type the code on the device page, sign in on the login
/// page it forwards to, land back told to return to the device.
async fn approved_on_the_second_screen(plane: &Plane, typed: &str) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/device"))
            .set_form([("user_code", typed)])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let binding = cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login opened");

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/login"))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .set_json(
                serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
            )
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let told: Value = test::read_body_json(response).await;
    assert_eq!(told["status"], "admitted", "{told}");
    let landing = told["redirect_to"].as_str().expect("a landing");
    assert!(landing.ends_with("/device#approved"), "{landing}");
}

/// RFC 8628, the whole life: the device opens, the person types the code and
/// signs in on their own screen, the device polls at the pace it was told
/// and collects once, and what it collects renews.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_device_signs_in_by_a_person_somewhere_better() {
    let plane = Plane::with_actions(&[]).await;
    allow_device(&plane).await;

    let (status, opened) = posted(
        &plane,
        "/device-authorization",
        &[("scope", "openid profile")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let device_code = opened["device_code"].as_str().expect("a secret").to_owned();
    let user_code = opened["user_code"].as_str().expect("a code").to_owned();
    assert_eq!(user_code.len(), 9, "{user_code}");
    assert_eq!(&user_code[4..5], "-", "{user_code}");
    assert!(
        opened["verification_uri_complete"]
            .as_str()
            .expect("a link")
            .contains(&format!("user_code={user_code}")),
        "{opened}"
    );
    assert_eq!(opened["interval"], 5, "{opened}");

    // Nobody has decided: pending. Polling again inside the interval is told
    // to slow down, and the refusal still stamps the row.
    let (status, told) = polled(&plane, &device_code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(told["error"], "authorization_pending", "{told}");
    let (_, told) = polled(&plane, &device_code).await;
    assert_eq!(told["error"], "slow_down", "{told}");

    // The device page is there for the person, in the browser's tongue.
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/device"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = String::from_utf8(test::read_body(response).await.to_vec()).expect("a page");
    assert!(page.contains("Connect a device"), "{page:.200}");

    // A code nobody minted lands back saying only that it does not stand.
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/device"))
            .set_form([("user_code", "ZZZZ-ZZZZ")])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let landing = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .expect("a landing");
    assert!(landing.ends_with("#no-such-code"), "{landing}");

    // The person types it the comfortable way: lowercase, with the dash.
    approved_on_the_second_screen(&plane, &user_code.to_lowercase()).await;

    // Approved, at the device's own pace: the poll collects the tokens.
    rewind_poll(&plane).await;
    let (status, granted) = polled(&plane, &device_code).await;
    assert_eq!(status, StatusCode::OK, "{granted}");
    let claims = plane
        .claims_of(granted["access_token"].as_str().expect("a token"))
        .await;
    assert_eq!(claims["azp"], support::CONFIDENTIAL, "{claims}");
    assert_eq!(claims["typ"], "Bearer", "{claims}");
    let identity = plane
        .claims_of(granted["id_token"].as_str().expect("an id token"))
        .await;
    assert!(identity["auth_time"].is_i64(), "{identity}");

    // Once: a second collection is a replay, and says only invalid_grant.
    let (status, told) = polled(&plane, &device_code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(told["error"], "invalid_grant", "{told}");

    // What it collected renews: the grant hangs off the approving login.
    let (status, renewed) = posted(
        &plane,
        "/token",
        &[
            ("grant_type", "refresh_token"),
            (
                "refresh_token",
                granted["refresh_token"].as_str().expect("a refresh token"),
            ),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{renewed}");
}

/// A client that registered encryption for its identity tokens is handed the
/// one a device collects wrapped for it, as the code grant hands it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_device_collects_its_identity_token_wrapped_for_its_client() {
    use crypto::jose::jwe::{RSA_OAEP_256, deserialize_compact};
    use models::entities::client::JweRegistration;
    use models::entities::keys::{JweAlgorithm, JweEncryption};

    let plane = Plane::with_actions(&[]).await;
    allow_device(&plane).await;
    let key = support::SigningKey::generate_encryption("wrapping");
    plane
        .register_client_encryption(
            support::CONFIDENTIAL,
            serde_json::json!({ "keys": [key.public_for_encryption().as_ref()] }),
            Some(JweRegistration::new(
                JweAlgorithm::RsaOaep256,
                Some(JweEncryption::A256Gcm),
            )),
            None,
        )
        .await;

    let (_, opened) = posted(&plane, "/device-authorization", &[("scope", "openid")]).await;
    let device_code = opened["device_code"].as_str().expect("a secret").to_owned();
    let user_code = opened["user_code"].as_str().expect("a code").to_owned();
    approved_on_the_second_screen(&plane, &user_code).await;
    rewind_poll(&plane).await;
    let (status, granted) = polled(&plane, &device_code).await;
    assert_eq!(status, StatusCode::OK, "{granted}");

    let told = granted["id_token"].as_str().expect("an identity token");
    assert_eq!(
        told.split('.').count(),
        5,
        "the identity token was handed out in the clear"
    );
    let decrypter = RSA_OAEP_256
        .decrypter_from_jwk(key.private())
        .expect("a decrypter");
    let (inside, header) = deserialize_compact(told, &decrypter).expect("opened by the client");
    assert_eq!(header.content_type(), Some("JWT"));
    assert_eq!(
        String::from_utf8(inside)
            .expect("a token")
            .split('.')
            .count(),
        3
    );
}

/// The doors hold: a client never opted in cannot open a device sign-in, and
/// a sign-in that ran out answers expired_token to the device and "does not
/// stand" to the person.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_device_doors_refuse_the_unregistered_and_the_expired() {
    let plane = Plane::with_actions(&[]).await;

    let (status, told) = posted(&plane, "/device-authorization", &[("scope", "openid")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "unauthorized_client", "{told}");

    allow_device(&plane).await;
    let (_, opened) = posted(&plane, "/device-authorization", &[("scope", "openid")]).await;
    let device_code = opened["device_code"].as_str().expect("a secret").to_owned();
    let user_code = opened["user_code"].as_str().expect("a code").to_owned();

    {
        let transaction = plane.scoped(&within()).await;
        transaction
            .execute(
                "UPDATE oidc_device_codes SET expires_at = now() - interval '1 minute'",
                &[],
            )
            .await
            .expect("the row expired");
        transaction.commit().await.expect("the expiry kept");
    }

    let (status, told) = polled(&plane, &device_code).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(told["error"], "expired_token", "{told}");

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/device"))
            .set_form([("user_code", user_code.as_str())])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let landing = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .expect("a landing");
    assert!(landing.ends_with("#no-such-code"), "{landing}");

    // The sweep takes what ran out.
    let transaction = plane.scoped(&within()).await;
    let swept = services::realm::housekeeping::drop_expired_rows(&transaction, chrono::Utc::now())
        .await
        .expect("a sweep");
    assert!(swept.device_codes >= 1, "{}", swept.device_codes);
}

/// A whole device sign-in asking for offline access, down to the answer the
/// device collects.
async fn collected_offline(plane: &Plane) -> Value {
    let (status, opened) = posted(
        plane,
        "/device-authorization",
        &[("scope", "openid offline_access")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    let device_code = opened["device_code"].as_str().expect("a secret").to_owned();
    let user_code = opened["user_code"].as_str().expect("a code").to_owned();
    approved_on_the_second_screen(plane, &user_code).await;
    let (status, granted) = polled(plane, &device_code).await;
    assert_eq!(status, StatusCode::OK, "{granted}");
    granted
}

/// The realm's cap on offline grants counts what a device collects too, and
/// ends the older grant.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_device_grant_keeps_to_the_realms_offline_cap() {
    let plane = Plane::with_actions(&[]).await;
    allow_device(&plane).await;
    {
        let transaction = plane.scoped(&within()).await;
        let mut realm = store::providers::realms::load(&transaction, REALM)
            .await
            .expect("the realms table")
            .expect("a planted realm");
        realm.max_offline_grants = 1;
        store::providers::realms::update(&transaction, &realm)
            .await
            .expect("the realms table");
        transaction.commit().await.expect("the cap kept");
    }

    let older = collected_offline(&plane).await;
    // Started a minute back, or the two grants would tie on their start.
    {
        let transaction = plane.scoped(&within()).await;
        transaction
            .execute(
                "UPDATE client_sessions SET started_at = started_at - 60 WHERE offline",
                &[],
            )
            .await
            .expect("an ageing");
        transaction.commit().await.expect("the ageing kept");
    }
    let newer = collected_offline(&plane).await;

    let renewed = |granted: &Value| {
        let refresh_token = granted["refresh_token"]
            .as_str()
            .expect("a refresh token")
            .to_owned();
        let plane = &plane;
        async move {
            posted(
                plane,
                "/token",
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh_token),
                ],
            )
            .await
        }
    };
    let (status, told) = renewed(&older).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the cap left the older grant standing: {told}"
    );
    let (status, told) = renewed(&newer).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the cap ended the newer grant: {told}"
    );
}

/// The realm paces its own device flow: a retuned lifespan and interval
/// reach the next opening, spoken in the answer exactly as stored.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_realm_paces_its_device_flow() {
    let plane = Plane::with_actions(&[models::entities::authz::AdminAction::RealmWrite]).await;
    allow_device(&plane).await;

    {
        let transaction = plane
            .tenancy()
            .begin(&store::tenancy::TenantContext::new(
                support::TENANT,
                support::REALM,
            ))
            .await
            .expect("a scoped unit of work");
        let mut realm = store::providers::realms::load(&transaction, support::REALM)
            .await
            .unwrap()
            .expect("the realm");
        realm.device_code_lifespan = Some(120);
        realm.device_poll_interval = Some(9);
        store::providers::realms::update(&transaction, &realm)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }

    let (status, opened) = posted(&plane, "/device-authorization", &[("scope", "openid")]).await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    assert_eq!(opened["expires_in"], 120, "{opened}");
    assert_eq!(opened["interval"], 9, "{opened}");
}

/// Type `code` at the device page from `peer`: where the browser lands, and
/// whether a login opened for it.
async fn typed_from(plane: &Plane, peer: &str, code: &str) -> (String, bool) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/device"))
            .peer_addr(peer.parse().expect("an address"))
            .set_form([("user_code", code)])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let landing = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .expect("a landing")
        .to_owned();
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    (
        landing,
        cookie_value(&cookies, support::AUTH_SESSION_COOKIE).is_some(),
    )
}

/// What is counted against `source`: on its own, and under any other key.
async fn counted_against(plane: &Plane, source: &str) -> (i64, i64) {
    let transaction = plane.scoped(&within()).await;
    let row = transaction
        .query_one(
            "SELECT COALESCE(SUM(failures) FILTER (WHERE named = ''), 0)::bigint, \
                    COALESCE(SUM(failures) FILTER (WHERE named <> ''), 0)::bigint \
             FROM source_failures WHERE source = $1",
            &[&source],
        )
        .await
        .expect("the failures table");
    (row.get(0), row.get(1))
}

/// Every code that does not stand counts against the address typing it, and
/// once it has missed as often as the realm lets a name be missed, it is
/// turned away before any code is looked up, the live one included. Another
/// address still opens the login with that code.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn codes_guessed_from_one_address_turn_it_away() {
    const GUESSER: &str = "203.0.113.7:40000";
    const ELSEWHERE: &str = "198.51.100.2:40000";
    let plane = Plane::with_actions(&[]).await;
    allow_device(&plane).await;
    plane
        .throttle_sources(models::entities::realm::SourceThrottle {
            throttled: true,
            max_failures: 100,
            max_name_failures: 3,
            window_seconds: 900,
        })
        .await;
    let (_, opened) = posted(&plane, "/device-authorization", &[("scope", "openid")]).await;
    let user_code = opened["user_code"].as_str().expect("a code").to_owned();

    // Vowels are never drawn, so none of these is anybody's code.
    for guess in ["AAAA-AAAA", "EEEE-EEEE", "IIII-IIII"] {
        let (landing, opened) = typed_from(&plane, GUESSER, guess).await;
        assert!(landing.ends_with("#no-such-code"), "{landing}");
        assert!(!opened, "a login opened for a code nobody minted");
    }
    assert_eq!(
        counted_against(&plane, "203.0.113.7").await,
        (3, 3),
        "a miss was not counted, or not kept"
    );

    let (landing, opened) = typed_from(&plane, GUESSER, &user_code).await;
    assert!(
        landing.ends_with("#throttled"),
        "an address past its misses had its code looked up: {landing}"
    );
    assert!(!opened, "a login opened for an address turned away");
    assert_eq!(
        counted_against(&plane, "203.0.113.7").await,
        (3, 3),
        "the refusal to look counted as a miss"
    );
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let page = test::call_and_read_body(
        &app,
        test::TestRequest::get()
            .uri(landing.split('#').next().expect("a path"))
            .to_request(),
    )
    .await;
    let page = String::from_utf8(page.to_vec()).expect("a page");
    assert!(
        page.contains(r#"<p id="throttled" class="flash" role="alert">Too many failed attempts"#),
        "the page has no words for an address turned away"
    );

    let (landing, opened) = typed_from(&plane, ELSEWHERE, &user_code).await;
    assert!(
        opened,
        "another address was turned away with the guesser: {landing}"
    );
    assert_eq!(counted_against(&plane, "198.51.100.2").await, (0, 0));
}
