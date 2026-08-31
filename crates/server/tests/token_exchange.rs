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

/// A subject token re-signed with extra claims, standing in for one minted
/// by a fussier issuer. Same shape the plane accepts everywhere else.
fn resigned_with(plane: &Plane, original: &Value, extra: &[(&str, Value)]) -> String {
    use crypto::jose::jwt::JwtPayload;
    let mut payload = JwtPayload::new();
    for (name, value) in original.as_object().expect("claims") {
        if name == "exp" || name == "iat" {
            continue;
        }
        payload
            .set_claim(name, Some(value.clone()))
            .expect("a carried claim");
    }
    payload.set_expires_at(&(std::time::SystemTime::now() + std::time::Duration::from_secs(600)));
    for (name, value) in extra {
        payload
            .set_claim(name, Some(value.clone()))
            .expect("an added claim");
    }
    plane.token(&payload)
}

/// An actor token names who acts, and a subject's may_act is the narrowest
/// authority in the room.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_actor_is_named_and_may_act_gates_the_room() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead]).await;
    opted_in(&plane, support::CONFIDENTIAL).await;
    let minted = subject_tokens(&plane, "openid profile").await;
    let subject_token = minted["access_token"].as_str().expect("an access token");

    // The actor's own machine token: its subject is nobody, so the party it
    // was minted for is who acts.
    let (status, machine) = asking(
        &plane,
        &[("grant_type", "client_credentials")],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{machine}");
    let actor_token = machine["access_token"].as_str().expect("a machine token");

    // The type must ride the token, and ride it correctly.
    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TYPE),
            ("actor_token_type", ACCESS_TYPE),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TYPE),
            ("actor_token", actor_token),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");

    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TYPE),
            ("actor_token", actor_token),
            ("actor_token_type", ACCESS_TYPE),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let exchanged = plane
        .claims_of(told["access_token"].as_str().expect("a token"))
        .await;
    // The machine token's own subject is the realm's service account, and
    // that, not the calling client, is who the act claim names.
    assert_eq!(
        exchanged["act"]["sub"], "service-account-app",
        "{exchanged}"
    );

    // A subject token that names who may act refuses everybody else, and
    // admits exactly who it names.
    let original = plane.claims_of(subject_token).await;
    let closed = resigned_with(
        &plane,
        &original,
        &[("may_act", serde_json::json!({ "sub": "somebody-else" }))],
    );
    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", &closed),
            ("subject_token_type", ACCESS_TYPE),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "unauthorized_client", "{told}");

    let open = resigned_with(
        &plane,
        &original,
        &[(
            "may_act",
            serde_json::json!({ "sub": support::CONFIDENTIAL }),
        )],
    );
    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", &open),
            ("subject_token_type", ACCESS_TYPE),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
}

/// A pairwise identifier is undone at the exchange and re-spoken for the
/// audience, so one audience's identifier never travels to another.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_pairwise_subject_is_respoken_for_the_audience() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead]).await;
    plane.pair_subjects(support::CONFIDENTIAL).await;
    opted_in(&plane, support::CONFIDENTIAL).await;

    let minted = subject_tokens(&plane, "openid profile").await;
    let subject_token = minted["access_token"].as_str().expect("an access token");
    let original = plane.claims_of(subject_token).await;
    let worn = original["sub"].as_str().expect("a subject");
    assert_ne!(worn, support::SUBJECT, "the subject token was not pairwise");

    // Toward a public-subject client of this realm, the person is spoken
    // plainly, not in the presenting client's dialect.
    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TYPE),
            ("audience", support::PARTY),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let exchanged = plane
        .claims_of(told["access_token"].as_str().expect("a token"))
        .await;
    assert_eq!(exchanged["sub"], support::SUBJECT, "{exchanged}");

    // Toward an audience that is no client of this realm, the actor's own
    // policy speaks, which for a pairwise actor is its own dialect.
    let (status, told) = asking(
        &plane,
        &[
            ("grant_type", EXCHANGE),
            ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TYPE),
            ("audience", "resource-server"),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let kept = plane
        .claims_of(told["access_token"].as_str().expect("a token"))
        .await;
    assert_eq!(kept["sub"], worn, "{kept}");
}

/// The operator can bound where a client points an exchange; the client
/// itself always stands, and the refusal wears the unauthorized face.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_exchange_points_only_where_the_operator_said() {
    use models::entities::attributes::AttributeValue;
    use store::tenancy::TenantContext;

    let plane = Plane::with_actions(&[AdminAction::RealmRead]).await;
    opted_in(&plane, support::CONFIDENTIAL).await;
    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
            .await
            .unwrap()
            .expect("the client");
        client.configs.get_or_insert_with(Default::default).insert(
            "token.exchange.audiences".to_owned(),
            AttributeValue::Str("billing reports".to_owned()),
        );
        assert!(
            store::providers::clients::update(&transaction, &client)
                .await
                .unwrap()
        );
        transaction.commit().await.unwrap();
    }
    let minted = subject_tokens(&plane, "openid").await;
    let subject_token = minted["access_token"].as_str().expect("an access token");

    for (audience, admitted) in [
        ("billing", true),
        ("reports", true),
        ("elsewhere", false),
        (support::CONFIDENTIAL, true),
    ] {
        let (status, told) = asking(
            &plane,
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", subject_token),
                ("subject_token_type", ACCESS_TYPE),
                ("audience", audience),
            ],
            Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
        )
        .await;
        if admitted {
            assert_eq!(status, StatusCode::OK, "{audience}: {told}");
        } else {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{audience}: {told}");
            assert_eq!(told["error"], "unauthorized_client", "{told}");
        }
    }
}
