mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use data_encoding::BASE64;
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;
use support::{Plane, cookie_value};

const REALM: &str = support::REALM;

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
        sealing: support::sealing(),
        egress: config::serving::Egress::Outward,
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, REALM)
}

/// Opt the fixture's confidential client into the device grant.
async fn allow_device(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
        .await
        .expect("the clients table")
        .expect("a planted client");
    let mut bag = client.configs.take().unwrap_or_default();
    bag.insert(
        services::device::GRANT_FLAG.to_owned(),
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
            ("grant_type", services::device::GRANT),
            ("device_code", device_code),
        ],
    )
    .await
}

/// Rewind the poll stamp, so the bench does not sleep through the interval.
async fn rewind_poll(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
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
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
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
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let swept = services::housekeeping::drop_expired_rows(&transaction, chrono::Utc::now())
        .await
        .expect("a sweep");
    assert!(swept.device_codes >= 1, "{}", swept.device_codes);
}
