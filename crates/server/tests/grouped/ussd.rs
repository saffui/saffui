#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use data_encoding::BASE64;
use serde_json::Value;
use server::api::config::register;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;
const GRANT: &str = "urn:openid:params:grant-type:ciba";
const SECRET: &str = "a-gateway-secret-of-length";

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
        ceiling: support::ceiling(),
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, REALM)
}

/// A CIBA client, a proven phone, and a gateway that knows the secret.
async fn arranged(plane: &Plane) {
    use models::entities::attributes::AttributeValue;
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
        .await
        .unwrap()
        .expect("the client");
    client.configs.get_or_insert_with(Default::default).insert(
        "ciba.delivery_mode".to_owned(),
        AttributeValue::Str("poll".to_owned()),
    );
    assert!(
        store::providers::clients::update(&transaction, &client)
            .await
            .unwrap()
    );
    store::providers::users::set_phone(&transaction, support::SUBJECT, Some("+22890123456"), true)
        .await
        .expect("the phone proven");
    let sealing = support::sealing();
    let ring = store::keyring::load(&transaction, &sealing.envelope, support::TENANT, REALM)
        .await
        .expect("a keyring");
    store::providers::ussd::keep_secret(
        &transaction,
        &ring,
        &sealing.envelope,
        &secrecy::SecretBox::new(Box::new(SECRET.to_owned())),
    )
    .await
    .expect("the secret kept");
    transaction.commit().await.expect("the arrangement kept");
}

async fn opened(plane: &Plane, binding_message: &str) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/bc-authorize"
            ))
            .insert_header(("authorization", format!("Basic {encoded}")))
            .set_form([
                ("login_hint", support::SUBJECT),
                ("scope", "openid"),
                ("binding_message", binding_message),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = test::read_body_json(response).await;
    body["auth_req_id"].as_str().expect("an id").to_owned()
}

async fn dialled(
    plane: &Plane,
    bearer: Option<&str>,
    session: &str,
    phone: &str,
    text: &str,
) -> (StatusCode, String) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asking = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/ussd/callback"))
        .set_form([
            ("sessionId", session),
            ("phoneNumber", phone),
            ("text", text),
        ]);
    if let Some(bearer) = bearer {
        asking = asking.insert_header(("authorization", format!("Bearer {bearer}")));
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = String::from_utf8_lossy(&test::read_body(response).await).into_owned();
    (status, body)
}

async fn polled(plane: &Plane, auth_req_id: &str) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
            .insert_header(("authorization", format!("Basic {encoded}")))
            .set_form([("grant_type", GRANT), ("auth_req_id", auth_req_id)])
            .to_request(),
    )
    .await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_gateway_proves_itself_or_hears_nothing() {
    let plane = Plane::with_actions(&[]).await;

    // No gateway named: the door does not exist.
    let (status, _) = dialled(&plane, Some(SECRET), "s1", "+22890123456", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    arranged(&plane).await;
    let (status, _) = dialled(&plane, None, "s1", "+22890123456", "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = dialled(
        &plane,
        Some("not-the-secret-at-all"),
        "s1",
        "+22890123456",
        "",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_unknown_number_hears_the_empty_doorbell_exactly() {
    let plane = Plane::with_actions(&[]).await;
    arranged(&plane).await;

    let (status, stranger) = dialled(&plane, Some(SECRET), "s1", "+99900000001", "").await;
    assert_eq!(status, StatusCode::OK);
    let (_, known_but_quiet) = dialled(&plane, Some(SECRET), "s2", "+22890123456", "").await;
    assert_eq!(
        stranger, known_but_quiet,
        "a stranger and a quiet doorbell must read alike"
    );
    assert!(stranger.starts_with("END "), "{stranger}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_dialled_doorbell_decides_the_request_it_was_shown() {
    let plane = Plane::with_actions(&[]).await;
    arranged(&plane).await;
    let first = opened(&plane, "M-42").await;

    let (status, screen) = dialled(&plane, Some(SECRET), "s1", "+228 90 12 34 56", "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(screen.starts_with("CON "), "{screen}");
    assert!(
        screen.contains("M-42"),
        "the binding message is unsaid: {screen}"
    );
    assert!(screen.contains('1') && screen.contains('2'), "{screen}");

    // A second request arrives between the screen and the answer; the
    // answer decides what was shown, never what came after.
    let second = opened(&plane, "M-43").await;
    let (_, told) = dialled(&plane, Some(SECRET), "s1", "+22890123456", "1").await;
    assert!(told.starts_with("END "), "{told}");

    let (status, minted) = polled(&plane, &first).await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    assert!(minted["access_token"].is_string(), "{minted}");
    let (_, waiting) = polled(&plane, &second).await;
    assert_eq!(
        waiting["error"], "authorization_pending",
        "the later request was decided by an answer it was never shown to: {waiting}"
    );

    // The screen was spent with its answer: another digit on the same
    // session decides nothing more, and the later request keeps waiting.
    let (_, told) = dialled(&plane, Some(SECRET), "s1", "+22890123456", "1*1").await;
    assert!(told.starts_with("END "), "{told}");
    let (_, waiting) = polled(&plane, &second).await;
    // Pending, or the poll throttle: either way, undecided.
    assert!(
        matches!(
            waiting["error"].as_str(),
            Some("authorization_pending" | "slow_down")
        ),
        "{waiting}"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_unanchored_answer_buys_nothing_and_a_refusal_lands() {
    let plane = Plane::with_actions(&[]).await;
    arranged(&plane).await;
    let auth_req = opened(&plane, "M-1").await;

    // "1" with no screen behind it: nothing is decided.
    let (_, told) = dialled(&plane, Some(SECRET), "fresh", "+22890123456", "1").await;
    assert!(
        told.contains("expired") || told.contains("expiree"),
        "{told}"
    );
    let (_, waiting) = polled(&plane, &auth_req).await;
    assert_eq!(waiting["error"], "authorization_pending", "{waiting}");

    // Shown, then refused.
    dialled(&plane, Some(SECRET), "s9", "+22890123456", "").await;
    let (_, told) = dialled(&plane, Some(SECRET), "s9", "+22890123456", "2").await;
    assert!(told.starts_with("END "), "{told}");
    let (_, denied) = polled(&plane, &auth_req).await;
    assert_eq!(denied["error"], "access_denied", "{denied}");

    // The screen's request dies while the answer is in flight, and another
    // arrives: the answer must decide nothing, never the newcomer it was
    // never shown to.
    let _shown = opened(&plane, "M-2").await;
    dialled(&plane, Some(SECRET), "s10", "+22890123456", "").await;
    {
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
        transaction
            .execute(
                "UPDATE backchannel_requests SET expires_at = now() - interval '1 second' \
                 WHERE state = 'pending'",
                &[],
            )
            .await
            .expect("the shown one expired");
        transaction.commit().await.expect("the expiry kept");
    }
    let newcomer = opened(&plane, "M-3").await;
    let (_, told) = dialled(&plane, Some(SECRET), "s10", "+22890123456", "1").await;
    assert!(told.starts_with("END "), "{told}");
    let (_, waiting) = polled(&plane, &newcomer).await;
    assert!(
        matches!(
            waiting["error"].as_str(),
            Some("authorization_pending" | "slow_down")
        ),
        "the newcomer was decided by an answer it was never shown to: {waiting}"
    );
}
