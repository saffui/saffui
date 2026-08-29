mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use data_encoding::BASE64;
use models::entities::authz::AdminAction;
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use support::{Plane, REDIRECT};

const REALM: &str = support::REALM;
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

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

/// Post a form at the token endpoint, optionally with client authentication.
async fn asking(
    plane: &Plane,
    form: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut request = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
        .set_form(form);
    if let Some((client_id, secret)) = basic {
        let encoded = BASE64.encode(format!("{client_id}:{secret}").as_bytes());
        request = request.insert_header(("authorization", format!("Basic {encoded}")));
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

/// A user's token in hand, the way a client gets one.
async fn subject_tokens(plane: &Plane, scope: &str) -> Value {
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, scope, None)
        .await;
    let (status, body) = asking(
        plane,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

/// Opt the client into exchanging, the way an operator flips its bag.
async fn opted_in(plane: &Plane, client_id: &str) {
    use models::entities::attributes::AttributeValue;
    use store::tenancy::TenantContext;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let mut client = store::providers::clients::load(&transaction, client_id)
        .await
        .unwrap()
        .expect("the client");
    client.configs.get_or_insert_with(Default::default).insert(
        "token.exchange.enabled".to_owned(),
        AttributeValue::Bool(true),
    );
    assert!(
        store::providers::clients::update(&transaction, &client)
            .await
            .unwrap()
    );
    transaction.commit().await.unwrap();
}

/// A user's token is exchanged for one that acts on their behalf: the
/// subject stays, the actor is named, the scope only narrows, and nothing
/// renewable comes back. Off by default, per client, and never for a
/// refresh token.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_is_exchanged_for_delegation() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead]).await;
    let minted = subject_tokens(&plane, "openid profile").await;
    let subject_token = minted["access_token"].as_str().expect("an access token");
    let original = plane.claims_of(subject_token).await;

    // Nothing opted in yet: the power is granted by name, not assumed.
    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TYPE),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "unauthorized_client");

    opted_in(&plane, support::CONFIDENTIAL).await;

    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TYPE),
            ("scope", "openid"),
            ("audience", "resource-server"),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["issued_token_type"], ACCESS_TYPE);
    assert_eq!(told["token_type"], "Bearer");
    assert_eq!(told["scope"], "openid");
    assert!(
        told.get("refresh_token").is_none(),
        "an exchange minted something renewable: {told}"
    );

    let exchanged = plane
        .claims_of(told["access_token"].as_str().expect("a token"))
        .await;
    assert_eq!(exchanged["sub"], original["sub"], "the subject moved");
    assert_eq!(exchanged["act"]["sub"], support::CONFIDENTIAL);
    assert_eq!(exchanged["azp"], support::CONFIDENTIAL);
    assert_eq!(exchanged["aud"], "resource-server");
    assert_eq!(
        exchanged["sid"], original["sid"],
        "the session did not carry"
    );
    assert_eq!(exchanged["typ"], "Bearer");

    // Asked wider than the subject held: narrowed, never widened.
    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TYPE),
            ("scope", "openid profile email offline_access"),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["scope"], "openid profile");
    let widened = plane
        .claims_of(told["access_token"].as_str().expect("a token"))
        .await;
    assert_eq!(
        widened["aud"],
        support::CONFIDENTIAL,
        "nothing asked lands on the actor itself"
    );

    // A refresh token renews; it does not say what a person may do, so it is
    // not a subject here.
    let refresh = minted["refresh_token"].as_str().expect("a refresh token");
    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", refresh),
            ("subject_token_type", ACCESS_TYPE),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "invalid_grant");

    // A kind this build does not exchange is told at the door.
    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", subject_token),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:saml2",
            ),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "invalid_request");
}

/// A public client cannot exchange, opted in or not: acting for somebody is
/// a confidential power.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_public_client_cannot_exchange() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead]).await;
    let minted = subject_tokens(&plane, "openid").await;
    let subject_token = minted["access_token"].as_str().expect("an access token");
    opted_in(&plane, support::PUBLIC).await;

    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TYPE),
            ("client_id", support::PUBLIC),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "unauthorized_client");
}
