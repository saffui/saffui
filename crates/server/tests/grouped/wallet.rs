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
    asked_under(
        plane,
        config::serving::Egress::Outward,
        method,
        path,
        bearer,
        body,
    )
    .await
}

/// The same request, from a server that may dial where the egress policy says.
async fn asked_under(
    plane: &Plane,
    egress: config::serving::Egress,
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
        egress,
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

/// Issuers on a real socket, each publishing what its name says: keys in its
/// metadata, keys at an address its metadata names, metadata speaking for
/// another issuer, and a key set holding a private key.
fn serve_issuers() -> String {
    use actix_web::{App, HttpResponse, HttpServer, web};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let base = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    let served = base.clone();
    let key = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
        "kid": "registry-1"
    });
    let server = HttpServer::new(move || {
        let base = served.clone();
        let key = key.clone();
        App::new()
            .route("/.well-known/jwt-vc-issuer/registry", {
                let (base, key) = (base.clone(), key.clone());
                web::get().to(move || {
                    let document = json!({ "issuer": format!("{base}/registry"), "jwks": { "keys": [key.clone()] } });
                    async move { HttpResponse::Ok().json(document) }
                })
            })
            .route("/.well-known/jwt-vc-issuer/health", {
                let base = base.clone();
                web::get().to(move || {
                    let document = json!({ "issuer": format!("{base}/health"), "jwks_uri": format!("{base}/health-keys") });
                    async move { HttpResponse::Ok().json(document) }
                })
            })
            .route("/health-keys", {
                let key = key.clone();
                web::get().to(move || {
                    let document = json!({ "keys": [key.clone()] });
                    async move { HttpResponse::Ok().json(document) }
                })
            })
            .route("/.well-known/jwt-vc-issuer/liar", {
                let key = key.clone();
                web::get().to(move || {
                    let document = json!({ "issuer": "https://elsewhere.example", "jwks": { "keys": [key.clone()] } });
                    async move { HttpResponse::Ok().json(document) }
                })
            })
            .route("/.well-known/jwt-vc-issuer/leaky", {
                let base = base.clone();
                let mut leaked = key.clone();
                leaked["d"] = json!("O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik");
                web::get().to(move || {
                    let document = json!({ "issuer": format!("{base}/leaky"), "jwks": { "keys": [leaked.clone()] } });
                    async move { HttpResponse::Ok().json(document) }
                })
            })
    })
    .listen(listener)
    .expect("a listener")
    .workers(1)
    .disable_signals()
    .run();
    tokio::spawn(server);
    base
}

/// An issuer is named with the keys it publishes, read then and kept, and read
/// again on demand; metadata may point at the key set elsewhere. Metadata for
/// another issuer, a published private key, an issuer named twice and an
/// address that is no issuer are refused in words.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_issuer_is_named_with_the_keys_it_publishes() {
    use config::serving::Egress;
    verifier_running();
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = serve_issuers();
    let issuers = format!("/admin/realms/{REALM}/credential-issuers");
    let name = |label: &str, issuer: String| json!({ "name": label, "issuer": issuer });

    let (status, registry) = asked_under(
        &plane,
        Egress::Anywhere,
        Method::POST,
        &issuers,
        &bearer,
        Some(name("Civil registry", format!("{base}/registry"))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{registry}");
    assert_eq!(
        registry["keys"],
        json!([{ "kty": "OKP", "crv": "Ed25519", "x": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik", "kid": "registry-1" }])
    );
    assert_eq!(
        registry["read_from"],
        format!("{base}/.well-known/jwt-vc-issuer/registry")
    );

    let (status, health) = asked_under(
        &plane,
        Egress::Anywhere,
        Method::POST,
        &issuers,
        &bearer,
        Some(name("Health", format!("{base}/health"))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{health}");
    assert_eq!(health["read_from"], format!("{base}/health-keys"));

    for (issuer, says) in [
        (format!("{base}/liar"), "another issuer"),
        (format!("{base}/leaky"), "private key material"),
        ("ftp://registry.example".to_owned(), "is not an issuer"),
    ] {
        let (status, told) = asked_under(
            &plane,
            Egress::Anywhere,
            Method::POST,
            &issuers,
            &bearer,
            Some(name("Refused", issuer.clone())),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{issuer}: {told}");
        assert!(
            told["message"]
                .as_str()
                .is_some_and(|held| held.contains(says)),
            "{issuer}: {told}"
        );
    }
    let (status, told) = asked_under(
        &plane,
        Egress::Anywhere,
        Method::POST,
        &issuers,
        &bearer,
        Some(name("Twice", format!("{base}/registry"))),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "realm.credential_issuer.already_named");

    // A server that may only dial https reads nothing from a plain address.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &issuers,
        &bearer,
        Some(name("Plain", format!("{base}/health"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, listed) = asked(&plane, Method::GET, &issuers, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["running"], true);
    assert_eq!(
        listed["items"].as_array().map(Vec::len),
        Some(2),
        "{listed}"
    );

    let id = registry["id"].as_str().expect("an identity");
    let (status, again) = asked_under(
        &plane,
        Egress::Anywhere,
        Method::POST,
        &format!("{issuers}/{id}/keys"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert!(
        again["read_at"].as_str() >= registry["read_at"].as_str(),
        "{again}"
    );

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{issuers}/{id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{issuers}/{id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "realm.credential_issuer.not_found");
}
