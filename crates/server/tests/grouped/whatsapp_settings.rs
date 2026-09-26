#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use secrecy::ExposeSecret;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;

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
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
        ceiling: support::ceiling(),
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, support::REALM)
}

/// One request to the realm's WhatsApp settings, and what came back.
async fn asked(
    plane: &Plane,
    bearer: &str,
    method: Method,
    tail: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut request = test::TestRequest::default()
        .method(method)
        .uri(&format!("/admin/realms/{}/whatsapp{tail}", support::REALM))
        .insert_header(("authorization", format!("Bearer {bearer}")));
    if let Some(body) = body {
        request = request.set_json(body);
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

fn wanted(token: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "phone_number_id": "106540352242922",
        "template": "sign_in_code",
        "languages": ["en_US", " fr ", "en_US"],
    });
    if let Some(token) = token {
        body["token"] = serde_json::json!(token);
    }
    body
}

async fn held_token(plane: &Plane) -> Option<String> {
    let transaction = plane.scoped(&within()).await;
    let sealing = support::sealing();
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        support::TENANT,
        support::REALM,
    )
    .await
    .expect("a keyring");
    store::providers::realms::whatsapp::load(&transaction, &ring, &sealing.envelope)
        .await
        .expect("the settings read")
        .map(|held| held.token.expose_secret().clone())
}

/// The token is sealed in its column, never answered with, kept when an edit
/// leaves it out, and the languages are kept once each as Meta spells them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_whatsapp_token_is_sealed_kept_and_never_answered_with() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());

    let (status, told) = asked(
        &plane,
        &bearer,
        Method::PUT,
        "",
        Some(wanted(Some("a-system-user-token"))),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    {
        let transaction = plane.scoped(&within()).await;
        let sealed: Vec<u8> = transaction
            .query_one("SELECT sealed_token FROM realm_whatsapp", &[])
            .await
            .expect("the settings")
            .get(0);
        assert!(
            !String::from_utf8_lossy(&sealed).contains("a-system-user-token"),
            "the token is readable in the column"
        );
    }

    let (status, told) = asked(&plane, &bearer, Method::GET, "", None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        told,
        serde_json::json!({
            "phone_number_id": "106540352242922",
            "template": "sign_in_code",
            "languages": ["en_US", "fr"],
        }),
        "the plane answered with more, or less, than the settings"
    );

    let mut edited = wanted(None);
    edited["template"] = serde_json::json!("another_code");
    let (status, told) = asked(&plane, &bearer, Method::PUT, "", Some(edited)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    assert_eq!(
        held_token(&plane).await.as_deref(),
        Some("a-system-user-token"),
        "an edit leaving the token out lost it"
    );
}

/// Every setting Meta could not use is refused in words, and a first write
/// with no token is one of them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_setting_meta_could_not_use_is_refused_in_words() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());

    let mut refusals = Vec::new();
    for (field, value, said) in [
        (
            "phone_number_id",
            serde_json::json!("+22890123456"),
            "digits",
        ),
        ("template", serde_json::json!("Sign In"), "lowercase"),
        ("languages", serde_json::json!(["en-US"]), "en_US"),
        ("languages", serde_json::json!([]), "en_US"),
        ("token", serde_json::json!(" "), "token"),
    ] {
        let mut body = wanted(Some("a-system-user-token"));
        body[field] = value;
        refusals.push((
            field,
            asked(&plane, &bearer, Method::PUT, "", Some(body)).await,
            said,
        ));
    }
    refusals.push((
        "a first write with no token",
        asked(&plane, &bearer, Method::PUT, "", Some(wanted(None))).await,
        "token",
    ));
    for (field, (status, told), said) in refusals {
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{field}: {told}");
        assert!(
            told["message"]
                .as_str()
                .is_some_and(|held| held.contains(said)),
            "{field}: refused in other words: {told}"
        );
    }
    assert_eq!(
        held_token(&plane).await,
        None,
        "a refused write kept something"
    );
}

/// Forgetting forgets everything, and asking for settings that are not there
/// says so in the catalogue's words, the test send included.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn forgotten_settings_are_named_missing_everywhere() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let missing = |told: &serde_json::Value| told["error_code"] == "realm.whatsapp.not_found";

    let (status, told) = asked(
        &plane,
        &bearer,
        Method::POST,
        "/test",
        Some(serde_json::json!({ "to": "+22890123456" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert!(missing(&told), "{told}");

    asked(
        &plane,
        &bearer,
        Method::PUT,
        "",
        Some(wanted(Some("a-system-user-token"))),
    )
    .await;
    let (status, told) = asked(
        &plane,
        &bearer,
        Method::POST,
        "/test",
        Some(serde_json::json!({ "to": "0022890123456" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let (status, told) = asked(
        &plane,
        &bearer,
        Method::POST,
        "/test",
        Some(serde_json::json!({ "to": "+22890123456", "language": "de" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, _) = asked(&plane, &bearer, Method::DELETE, "", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, told) = asked(&plane, &bearer, Method::GET, "", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert!(missing(&told), "{told}");
    let (status, told) = asked(&plane, &bearer, Method::DELETE, "", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert!(missing(&told), "{told}");
}
