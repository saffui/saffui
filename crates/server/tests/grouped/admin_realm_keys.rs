
#[allow(unused_imports)]
use super::support;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use super::support::Plane;

const REALM: &str = support::REALM;

/// Ask the plane, with a body or without one.
async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    use actix_web::{App, test};
    use server::api::config::register;
    use server::middleware::admin_policy::AdminPolicy;
    let app = test::init_service(App::new().configure(register(&server::api::config::Plane {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    })))
    .await;
    let mut asking = test::TestRequest::default().method(method).uri(path);
    if let Some(bearer) = bearer {
        asking = asking.insert_header(("authorization", format!("Bearer {bearer}")));
    }
    if let Some(body) = body {
        asking = asking.set_json(body);
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    let told = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, told)
}

/// The signing entries of a GET /keys answer, as (kid, algorithm, status).
fn signing_of(told: &Value) -> Vec<(String, String, String)> {
    told["signing"]
        .as_array()
        .expect("a signing set")
        .iter()
        .map(|key| {
            (
                key["kid"].as_str().expect("a kid").to_owned(),
                key["algorithm"].as_str().expect("an algorithm").to_owned(),
                key["status"].as_str().expect("a status").to_owned(),
            )
        })
        .collect()
}

/// The kids the realm's public JWKS carries.
async fn published_kids(plane: &Plane) -> Vec<String> {
    let (status, told) = asked(
        plane,
        Method::GET,
        &format!("/realms/{REALM}/protocol/openid-connect/certs"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    told["keys"]
        .as_array()
        .expect("a key set")
        .iter()
        .map(|key| key["kid"].as_str().expect("a kid").to_owned())
        .collect()
}

/// A signing key's whole turn of service: minted as a successor, signing while
/// its predecessor still verifies, then disabled once retired. The realm's
/// other algorithm never moves.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_signing_key_turns_over_the_plane() {
    let plane =
        Plane::with_actions(&[AdminAction::RealmKeysRead, AdminAction::RealmKeysWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/keys");

    // The planted world: an active ES256, a passive ES256, one encryption key.
    let (status, told) = asked(&plane, Method::GET, &base, Some(&bearer), None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let before = signing_of(&told);
    assert_eq!(before.len(), 2);
    assert!(before.iter().all(|(_, algorithm, _)| algorithm == "ES256"));
    assert_eq!(told["encryption"].as_array().expect("encryption").len(), 1);

    // An algorithm the realm never signed with gains its first key; nothing
    // steps down for it.
    let (status, first) = asked(
        &plane,
        Method::POST,
        &base,
        Some(&bearer),
        Some(json!({ "algorithm": "RS256" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    assert_eq!(first["algorithm"], "RS256");
    assert_eq!(first["status"], "active");
    assert_eq!(first["priority"], 11);
    let first_kid = first["kid"].as_str().expect("a kid").to_owned();

    // Rotating RS256 retires RS256 alone. The ES256 that signs this very
    // bearer token must not move, or every registered ES256 client would lose
    // its signer to another algorithm's rotation.
    let (status, second) = asked(
        &plane,
        Method::POST,
        &base,
        Some(&bearer),
        Some(json!({ "algorithm": "RS256" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    assert_eq!(second["priority"], 12);
    let second_kid = second["kid"].as_str().expect("a kid").to_owned();
    assert_ne!(first_kid, second_kid);

    let (status, told) = asked(&plane, Method::GET, &base, Some(&bearer), None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let after = signing_of(&told);
    assert_eq!(after.len(), 4);
    let of = |kid: &str| {
        after
            .iter()
            .find(|(named, _, _)| named == kid)
            .map(|(_, _, status)| status.as_str())
    };
    assert_eq!(of(&first_kid), Some("passive"));
    assert_eq!(of(&second_kid), Some("active"));
    assert_eq!(
        after
            .iter()
            .filter(|(_, algorithm, status)| algorithm == "ES256" && status == "active")
            .count(),
        1,
        "rotating RS256 moved an ES256 key"
    );

    // Both RS256 keys are published: the passive one still verifies what it
    // signed.
    let published = published_kids(&plane).await;
    assert!(published.contains(&first_kid));
    assert!(published.contains(&second_kid));

    // A retired key leaves publication only when told to, and the plane still
    // sees it afterwards.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{first_kid}"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let published = published_kids(&plane).await;
    assert!(!published.contains(&first_kid));
    assert!(published.contains(&second_kid));
    let (status, told) = asked(&plane, Method::GET, &base, Some(&bearer), None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        signing_of(&told)
            .iter()
            .find(|(kid, _, _)| kid == &first_kid)
            .map(|(_, _, status)| status.clone()),
        Some("disabled".to_owned())
    );

    // The encryption key is found in its own set, and refused for the same
    // reason: it is active, and nothing over the plane retires one yet.
    let enc_kid = told["encryption"][0]["kid"]
        .as_str()
        .expect("an encryption kid")
        .to_owned();
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{enc_kid}"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "realm.key.still_active");

    // The key that signs is refused: rotation is the way out of service.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{second_kid}"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "realm.key.still_active");

    // A name the realm never held.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/nobody"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "realm.key.not_found");

    // Disabling twice changes nothing and is not an error.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{first_kid}"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// Reading the key set does not grant turning it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_key_capabilities_split_where_they_should() {
    let plane = Plane::with_actions(&[AdminAction::RealmKeysRead]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/keys");

    let (status, told) = asked(&plane, Method::GET, &base, Some(&bearer), None).await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let (status, _) = asked(
        &plane,
        Method::POST,
        &base,
        Some(&bearer),
        Some(json!({ "algorithm": "ES256" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/anything"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
