#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};

const REALM: &str = support::REALM;

async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    use actix_web::{App, test};
    use server::api::config::register;
    use server::middleware::admin_policy::AdminPolicy;
    let app = test::init_service(App::new().configure(register(&server::api::config::Plane {
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
        ceiling: support::ceiling(),
    })))
    .await;
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
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// The wallet verifier is experimental and off unless the process runs it, so
/// every case in this binary turns it on before anything reads what the
/// process runs: the first call decides for the whole binary.
pub(crate) fn verifier_running() {
    server::api::config::install_features(
        commons::feature::FeatureSet::resolve("+wallet-verifier", |_| false)
            .expect("a set that resolves"),
    );
    assert!(
        server::api::config::features().is_enabled(commons::feature::Feature::WalletVerifier),
        "the process does not run the wallet verifier"
    );
}

/// The authorities say the verifier runs where the process runs it, and not
/// in a realm that closed it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_anchors_say_whether_the_verifier_runs() {
    verifier_running();
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::FeatureWrite]).await;
    let bearer = plane.token(&support::claims());
    let anchors = format!("/admin/realms/{REALM}/trust-anchors");

    let (status, listed) = asked(&plane, Method::GET, &anchors, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["running"], true, "{listed}");

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/features/wallet-verifier"),
        &bearer,
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (_, listed) = asked(&plane, Method::GET, &anchors, &bearer, None).await;
    assert_eq!(
        listed["running"], false,
        "a realm that closed it still runs it: {listed}"
    );
}

/// The realm's DID document names its Ed25519 key, for a wallet to verify the
/// realm's requests against. There is none while the realm holds no such key,
/// nor once the realm closes the verifier.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_realm_publishes_its_did_document() {
    verifier_running();
    let plane =
        Plane::with_actions(&[AdminAction::RealmKeysWrite, AdminAction::FeatureWrite]).await;
    let bearer = plane.token(&support::claims());
    let document = format!("/realms/{REALM}/did.json");

    let (status, told) = asked(&plane, Method::GET, &document, &bearer, None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a realm with no Ed25519 key has no key to sign a request with: {told}"
    );

    let (status, minted) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/keys"),
        &bearer,
        Some(json!({ "algorithm": "EdDSA" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{minted}");
    let kid = minted["kid"].as_str().expect("a key identifier").to_owned();

    let (status, told) = asked(&plane, Method::GET, &document, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let did = told["id"].as_str().expect("an identifier").to_owned();
    assert!(
        did.starts_with("did:web:") && did.ends_with(&format!(":realms:{REALM}")),
        "{told}"
    );
    let methods = told["verificationMethod"].as_array().expect("methods");
    assert_eq!(methods.len(), 1, "{told}");
    assert_eq!(methods[0]["id"], format!("{did}#{kid}"));
    assert_eq!(methods[0]["type"], "Ed25519VerificationKey2020");
    assert!(
        methods[0]["publicKeyMultibase"]
            .as_str()
            .is_some_and(|held| held.starts_with("z6Mk")),
        "not an Ed25519 key written as multibase: {told}"
    );
    assert_eq!(told["assertionMethod"], json!([format!("{did}#{kid}")]));

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/features/wallet-verifier"),
        &bearer,
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (status, _) = asked(&plane, Method::GET, &document, &bearer, None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a realm that closed the verifier still names one"
    );
}
