//! A client registering itself: RFC 7591, RFC 7592 and OpenID Connect Dynamic
//! Client Registration 1.0.

mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use models::entities::realm::ClientRegistration;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};
use support::Plane;

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

fn path(rest: &str) -> String {
    format!(
        "/realms/{}/protocol/openid-connect/register{rest}",
        support::REALM
    )
}

/// Post a registration and hand back what came of it.
async fn registering(plane: &Plane, body: &Value, token: Option<&str>) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asked = test::TestRequest::post().uri(&path("")).set_json(body);
    if let Some(token) = token {
        asked = asked.insert_header(("authorization", format!("Bearer {token}")));
    }
    let response = test::call_service(&app, asked.to_request()).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

fn a_client() -> Value {
    json!({
        "client_name": "an application",
        "redirect_uris": ["https://app.example/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    })
}

/// A realm registers nothing until it says so, and says nothing about an
/// endpoint it does not answer.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_closed_realm_answers_nothing_and_advertises_nothing() {
    let plane = Plane::with_actions(&[]).await;
    let (status, _) = registering(&plane, &a_client(), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
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
    assert!(
        published.get("registration_endpoint").is_none(),
        "a closed realm named the endpoint: {published}"
    );

    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
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
    assert_eq!(
        published["registration_endpoint"].as_str(),
        Some(
            format!(
                "{}/protocol/openid-connect/register",
                support::origin().issuer(support::REALM)
            )
            .as_str()
        )
    );
}

/// §3.2.1: the response carries the identifier, the credentials, and where the
/// registration is managed.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn registering_hands_back_an_identity_and_the_way_to_manage_it() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;

    let (status, registered) = registering(&plane, &a_client(), None).await;
    assert_eq!(status, StatusCode::CREATED, "{registered}");
    let client_id = registered["client_id"].as_str().expect("an identifier");
    assert!(!client_id.is_empty());
    assert!(
        registered["client_id_issued_at"].is_number(),
        "{registered}"
    );
    assert!(
        registered["client_secret"]
            .as_str()
            .is_some_and(|held| !held.is_empty()),
        "{registered}"
    );
    // Zero is never, and a secret with an end unstated is one a client cannot
    // plan around.
    assert_eq!(registered["client_secret_expires_at"].as_i64(), Some(0));
    assert!(
        registered["registration_access_token"].as_str().is_some(),
        "{registered}"
    );
    assert_eq!(
        registered["registration_client_uri"].as_str(),
        Some(
            format!(
                "{}/protocol/openid-connect/register/{client_id}",
                support::origin().issuer(support::REALM)
            )
            .as_str()
        )
    );
    assert_eq!(registered["client_name"].as_str(), Some("an application"));
    assert_eq!(
        registered["token_endpoint_auth_method"].as_str(),
        Some("client_secret_basic")
    );
    assert_eq!(registered["response_types"], json!(["code"]));
    assert_eq!(registered["application_type"].as_str(), Some("web"));
    assert_eq!(registered["subject_type"].as_str(), Some("public"));

    // A client that authenticates with nothing keeps nothing to authenticate
    // with. A secret handed to it would be one nobody ever checks.
    let mut asked = a_client();
    asked["token_endpoint_auth_method"] = json!("none");
    let (status, public) = registering(&plane, &asked, None).await;
    assert_eq!(status, StatusCode::CREATED, "{public}");
    assert!(public.get("client_secret").is_none(), "{public}");
    assert!(public.get("client_secret_expires_at").is_none(), "{public}");
    assert_eq!(
        public["token_endpoint_auth_method"].as_str(),
        Some("none"),
        "{public}"
    );
}

/// RFC 7592 §2: the registration is reachable, replaceable and withdrawable by
/// whoever holds the access token, and by nobody else.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_the_access_token_manages_the_registration() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let (_, registered) = registering(&plane, &a_client(), None).await;
    let client_id = registered["client_id"].as_str().unwrap().to_owned();
    let token = registered["registration_access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let at = path(&format!("/{client_id}"));

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    for (named, presented, expected) in [
        ("nothing", None, StatusCode::UNAUTHORIZED),
        (
            "another token",
            Some("not-the-token"),
            StatusCode::UNAUTHORIZED,
        ),
        ("the token", Some(token.as_str()), StatusCode::OK),
    ] {
        let mut asked = test::TestRequest::get().uri(&at);
        if let Some(presented) = presented {
            asked = asked.insert_header(("authorization", format!("Bearer {presented}")));
        }
        let response = test::call_service(&app, asked.to_request()).await;
        assert_eq!(response.status(), expected, "presenting {named}");
    }

    // §2.2: what the amendment leaves out is cleared, not kept.
    let response = test::call_service(
        &app,
        test::TestRequest::put()
            .uri(&at)
            .insert_header(("authorization", format!("Bearer {token}")))
            .set_json(json!({
                "client_id": client_id,
                "client_name": "renamed",
                "redirect_uris": ["https://app.example/other"],
                "response_types": ["code"],
            }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let amended: Value = test::read_body_json(response).await;
    assert_eq!(amended["client_name"].as_str(), Some("renamed"));
    assert_eq!(
        amended["redirect_uris"],
        json!(["https://app.example/other"])
    );
    assert_eq!(amended["client_id"].as_str(), Some(client_id.as_str()));

    let response = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri(&at)
            .insert_header(("authorization", format!("Bearer {token}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&at)
            .insert_header(("authorization", format!("Bearer {token}")))
            .to_request(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a withdrawn registration still answered"
    );
}

/// §3: a protected realm registers for whoever holds the initial access token,
/// and for nobody else.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_protected_realm_asks_for_the_initial_access_token() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Protected, Some("the-initial-token"))
        .await;

    for (named, presented, expected) in [
        ("nothing", None, StatusCode::UNAUTHORIZED),
        ("another token", Some("not-it"), StatusCode::UNAUTHORIZED),
        ("the token", Some("the-initial-token"), StatusCode::CREATED),
    ] {
        let (status, body) = registering(&plane, &a_client(), presented).await;
        assert_eq!(status, expected, "presenting {named}: {body}");
    }
}

/// §3.3: metadata this provider cannot honour is refused as such, with the
/// error the spec names.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn metadata_this_provider_cannot_honour_is_refused() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;

    for (named, body) in [
        (
            "a response type nothing answers",
            json!({"redirect_uris": ["https://app.example/cb"], "response_types": ["token"]}),
        ),
        (
            "an unsigned identity token",
            json!({"redirect_uris": ["https://app.example/cb"], "id_token_signed_response_alg": "none"}),
        ),
        (
            "a login initiated over plain http",
            json!({
                "redirect_uris": ["https://app.example/cb"],
                "initiate_login_uri": "http://app.example/start",
            }),
        ),
        (
            "a subject type §8 does not name",
            json!({"redirect_uris": ["https://app.example/cb"], "subject_type": "shared"}),
        ),
        (
            "keys published two ways",
            json!({
                "redirect_uris": ["https://app.example/cb"],
                "jwks": {"keys": []},
                "jwks_uri": "https://app.example/jwks",
            }),
        ),
        (
            "a redirect that is not absolute",
            json!({"redirect_uris": ["/callback"]}),
        ),
        (
            "a redirect carrying a fragment",
            json!({"redirect_uris": ["https://app.example/cb#here"]}),
        ),
        (
            "grant types that disagree with the response types",
            json!({
                "redirect_uris": ["https://app.example/cb"],
                "response_types": ["code"],
                "grant_types": ["implicit"],
            }),
        ),
        (
            "a web client minting over plain http",
            json!({
                "redirect_uris": ["http://app.example/cb"],
                "response_types": ["id_token"],
                "grant_types": ["implicit"],
            }),
        ),
    ] {
        let (status, answered) = registering(&plane, &body, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{named}: {answered}");
        assert_eq!(
            answered["error"].as_str(),
            Some("invalid_client_metadata"),
            "{named}: {answered}"
        );
    }
}

/// What a client registered bounds what it may ask the authorization endpoint
/// for. Registering one set is not being allowed the others.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_registered_set_is_the_only_set_this_client_may_ask_for() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let (status, registered) = registering(
        &plane,
        &json!({
            "redirect_uris": ["https://app.example/callback"],
            "response_types": ["code id_token"],
            "grant_types": ["authorization_code", "implicit"],
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{registered}");
    let client_id = registered["client_id"].as_str().unwrap();

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    for (asked, allowed) in [
        ("code id_token", true),
        ("code", false),
        ("id_token", false),
    ] {
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!(
                    "/realms/{}/protocol/openid-connect/auth?client_id={client_id}\
                     &redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid\
                     &state=s&nonce=n&response_type={}",
                    support::REALM,
                    asked.replace(' ', "%20")
                ))
                .to_request(),
        )
        .await;
        let landing = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert_eq!(
            !landing.contains("error=unauthorized_client"),
            allowed,
            "{asked}: {landing}"
        );
    }
}

/// OIDC Core §4: where a third party sends a person to have this client start
/// a login is registered, given back, and given back again by the endpoint
/// that manages the registration.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn where_a_third_party_starts_a_login_is_kept_and_given_back() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .allow_registration(ClientRegistration::Open, None)
        .await;
    let starting = "https://app.example/start";

    let mut asked = a_client();
    asked["initiate_login_uri"] = json!(starting);
    let (status, registered) = registering(&plane, &asked, None).await;
    assert_eq!(status, StatusCode::CREATED, "{registered}");
    assert_eq!(
        registered["initiate_login_uri"].as_str(),
        Some(starting),
        "{registered}"
    );

    let token = registered["registration_access_token"].as_str().unwrap();
    let client_id = registered["client_id"].as_str().unwrap();
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&path(&format!("/{client_id}")))
            .insert_header(("authorization", format!("Bearer {token}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(|held| held.starts_with("application/json")),
        Some(true)
    );
    let held: Value = test::read_body_json(response).await;
    assert_eq!(
        held["initiate_login_uri"].as_str(),
        Some(starting),
        "{held}"
    );
}
