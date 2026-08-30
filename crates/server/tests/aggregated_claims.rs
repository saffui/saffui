mod support;

use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use data_encoding::BASE64;
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};
use support::{Plane, REDIRECT};

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
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    }
}

async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asking = test::TestRequest::default()
        .method(method)
        .uri(path)
        .insert_header(("authorization", format!("Bearer {bearer}")));
    if let Some(body) = body {
        asking = asking.set_json(body);
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    let told = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, told)
}

/// A user's access token, and the userinfo answer it opens.
async fn told_of(plane: &Plane, scope: &str) -> Value {
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, scope, None)
        .await;
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
            ])
            .insert_header(("authorization", format!("Basic {encoded}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let minted: Value = test::read_body_json(response).await;
    let access = minted["access_token"].as_str().expect("an access token");
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/userinfo"))
            .insert_header(("authorization", format!("Bearer {access}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    test::read_body_json(response).await
}

const CARRIED_JWT: &str = "eyJhbGciOiJSUzI1NiJ9.eyJhZGRyZXNzIjoiZWxzZXdoZXJlIn0.c2lnbmVk";

/// What another provider asserts is carried as theirs, only where this
/// realm is silent and the client is entitled, exactly in the 5.6.2.1
/// shape; and the plane refuses a source the release would skip over.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn another_providers_claims_are_carried_as_theirs() {
    let plane = Plane::with_actions(&[AdminAction::UserRead, AdminAction::UserWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!(
        "/admin/realms/{REALM}/users/{}/claim-sources",
        support::SUBJECT
    );

    // Refused at the door, each with its reason.
    for (body, holds) in [
        (
            json!({ "claims": [], "kind": "jwt", "jwt": CARRIED_JWT }),
            "at least one",
        ),
        (
            json!({ "claims": ["address"], "kind": "jwt" }),
            "signed document",
        ),
        (
            json!({ "claims": ["address"], "kind": "jwt", "jwt": "one.two" }),
            "three parts",
        ),
        (
            json!({ "claims": ["address"], "kind": "endpoint", "endpoint": "http://plain" }),
            "https",
        ),
    ] {
        let (status, told) = asked(&plane, Method::POST, &base, &bearer, Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert!(
            told["message"]
                .as_str()
                .is_some_and(|why| why.contains(holds)),
            "the refusal does not say {holds}: {told}"
        );
    }
    let (status, _) = asked(
        &plane,
        Method::POST,
        "/admin/realms/main/users/nobody/claim-sources",
        &bearer,
        Some(json!({ "claims": ["address"], "kind": "jwt", "jwt": CARRIED_JWT })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // One source carrying the address, one pointing at employment records,
    // and a third naming email, which the realm answers itself.
    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "claims": ["address"], "kind": "jwt", "jwt": CARRIED_JWT })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let address_source = born["source_id"].as_str().expect("an identity").to_owned();
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "claims": ["address"], "kind": "jwt", "jwt": CARRIED_JWT })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|why| why.contains("already answered")),
        "{told}"
    );
    let (status, _) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "claims": ["email"], "kind": "jwt", "jwt": CARRIED_JWT })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, pointed) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "claims": ["employment"], "kind": "endpoint",
                     "endpoint": "https://records.example/ada",
                     "endpoint_token": "carry-me" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{pointed}");

    // The living answer: address is spoken for by its source, email stays
    // the realm's own, and employment is not entitled, so its source stays
    // unsaid.
    let answer = told_of(&plane, "openid email address").await;
    assert_eq!(answer["email"], support::SUBJECT_EMAIL, "{answer}");
    assert_eq!(
        answer["_claim_names"]["address"], address_source,
        "{answer}"
    );
    assert!(
        answer["_claim_names"].get("email").is_none(),
        "a source re-pointed what the realm answers itself: {answer}"
    );
    assert!(
        answer["_claim_names"].get("employment").is_none(),
        "an unentitled claim was pointed at: {answer}"
    );
    assert_eq!(
        answer["_claim_sources"][&address_source],
        json!({ "JWT": CARRIED_JWT }),
        "{answer}"
    );

    // Without the address scope, the source has nothing it may say, and the
    // whole block goes rather than standing empty.
    let answer = told_of(&plane, "openid email").await;
    assert!(
        answer.get("_claim_names").is_none() && answer.get("_claim_sources").is_none(),
        "an unentitled release still spoke: {answer}"
    );

    // Removed, the source stops speaking at the very next answer.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{address_source}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{address_source}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "claims.source.not_found");
    let answer = told_of(&plane, "openid email address").await;
    assert!(
        answer["_claim_names"].get("address").is_none(),
        "a removed source kept speaking: {answer}"
    );
}

/// Reading a person's sources does not grant writing them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_source_capabilities_split_where_they_should() {
    let plane = Plane::with_actions(&[AdminAction::UserRead]).await;
    let bearer = plane.token(&support::claims());
    let base = format!(
        "/admin/realms/{REALM}/users/{}/claim-sources",
        support::SUBJECT
    );

    let (status, told) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let (status, _) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "claims": ["address"], "kind": "jwt", "jwt": CARRIED_JWT })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The identity token's claims request gets the same 5.6.2 release: what
/// was asked by name and another provider answers for is pointed at that
/// provider, and what the realm holds itself is released as its own.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_identity_token_points_at_sources_too() {
    let plane = Plane::with_actions(&[AdminAction::UserRead, AdminAction::UserWrite]).await;
    let bearer = plane.token(&support::claims());

    let (status, born) = asked(
        &plane,
        Method::POST,
        &format!(
            "/admin/realms/{REALM}/users/{}/claim-sources",
            support::SUBJECT
        ),
        &bearer,
        Some(json!({ "claims": ["address"], "kind": "jwt", "jwt": CARRIED_JWT })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let source_id = born["source_id"].as_str().expect("an identity").to_owned();

    let code = plane
        .mint_code_claimed(
            support::CONFIDENTIAL,
            REDIRECT,
            "openid",
            None,
            "n-once",
            Some(json!({ "id_token": { "address": null, "given_name": null } })),
        )
        .await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
            ])
            .insert_header(("authorization", format!("Basic {encoded}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let minted: Value = test::read_body_json(response).await;
    let identity = plane
        .claims_of(minted["id_token"].as_str().expect("an id token"))
        .await;

    assert_eq!(identity["_claim_names"]["address"], source_id, "{identity}");
    assert_eq!(
        identity["_claim_sources"][&source_id],
        json!({ "JWT": CARRIED_JWT }),
        "{identity}"
    );
    assert!(
        identity["given_name"].is_string(),
        "the asked claim the realm holds itself is its own: {identity}"
    );
    assert!(
        identity["_claim_names"].get("given_name").is_none(),
        "a source re-pointed what the realm answers itself: {identity}"
    );
}
