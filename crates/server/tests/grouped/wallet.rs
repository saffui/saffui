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
