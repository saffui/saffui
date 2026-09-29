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

/// The server under test, dialling where the egress policy says.
fn served(plane: &Plane, egress: config::serving::Egress) -> server::api::config::Plane {
    use server::middleware::admin_policy::AdminPolicy;
    server::api::config::Plane {
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
    }
}

/// A public door asked as a wallet asks it: no bearer, a form when posting,
/// and the body kept as it came.
async fn fetched(
    plane: &Plane,
    method: Method,
    path: &str,
    form: Option<&[(&str, &str)]>,
) -> (StatusCode, String) {
    use actix_web::{App, test};
    use server::api::config::register;
    let app = test::init_service(
        App::new().configure(register(&served(plane, config::serving::Egress::Outward))),
    )
    .await;
    let mut asking = test::TestRequest::default().method(method).uri(path);
    if let Some(form) = form {
        asking = asking.set_form(form);
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, String::from_utf8_lossy(&body).into_owned())
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
    let app = test::init_service(App::new().configure(register(&served(plane, egress)))).await;
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

/// Contexts on a real socket: one whose document the test rewrites, one with a
/// vocabulary mapping, one naming another, that other, a page that is no JSON,
/// and as many small ones as a count needs.
fn serve_contexts(insurance: std::sync::Arc<std::sync::Mutex<String>>) -> String {
    use actix_web::{App, HttpResponse, HttpServer, web};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let base = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    let served = base.clone();
    let server = HttpServer::new(move || {
        let base = served.clone();
        let insurance = insurance.clone();
        let document = |held: Value| {
            web::get().to(move || {
                let held = held.clone();
                async move { HttpResponse::Ok().json(held) }
            })
        };
        App::new()
            .route(
                "/insurance",
                web::get().to(move || {
                    let now = insurance.lock().expect("the document").clone();
                    async move { HttpResponse::Ok().content_type("application/ld+json").body(now) }
                }),
            )
            .route(
                "/vocabulary",
                document(json!({ "@context": { "@vocab": "https://example.com/terms#" } })),
            )
            .route(
                "/naming",
                document(json!({ "@context": [format!("{base}/terms"), { "a": "https://example.com/a" }] })),
            )
            .route(
                "/terms",
                document(json!({ "@context": { "b": "https://example.com/b" } })),
            )
            .route(
                "/page",
                web::get().to(|| async { HttpResponse::Ok().body("<html>no context</html>") }),
            )
            .route(
                "/small/{n}",
                document(json!({ "@context": { "c": "https://example.com/c" } })),
            )
    })
    .listen(listener)
    .expect("a listener")
    .workers(1)
    .disable_signals()
    .run();
    tokio::spawn(server);
    base
}

fn sha256_hex(text: &str) -> String {
    use crypto::provider::{CryptoConfig, CryptoProvider, HashAlg};
    let provider = crypto::provider::openssl::OpenSslProvider::new(&CryptoConfig::default())
        .expect("a provider");
    data_encoding::HEXLOWER.encode(
        &provider
            .digest()
            .hash(HashAlg::Sha256, text.as_bytes())
            .expect("a digest"),
    )
}

/// A realm pins a context with the document read then, kept with its digest,
/// and read again on demand. Built-in contexts, other addresses, documents that
/// would not read, a context pinned twice and one past the bound are refused in
/// words; a context naming another waits until that other is pinned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_pins_the_contexts_its_credentials_name() {
    use config::serving::Egress;
    verifier_running();
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let insurance = std::sync::Arc::new(std::sync::Mutex::new(
        json!({ "@context": { "@version": 1.1, "@protected": true, "policyNumber": "https://schema.org/Text" } })
            .to_string(),
    ));
    let base = serve_contexts(insurance.clone());
    let contexts = format!("/admin/realms/{REALM}/jsonld-contexts");
    let pin = |url: String| json!({ "url": url });

    let (status, pinned) = asked_under(
        &plane,
        Egress::Anywhere,
        Method::POST,
        &contexts,
        &bearer,
        Some(pin(format!("{base}/insurance"))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{pinned}");
    assert_eq!(pinned["url"], format!("{base}/insurance"));
    let first_digest = pinned["digest"].as_str().expect("a digest").to_owned();
    let served = insurance.lock().expect("the document").clone();
    assert_eq!(first_digest, sha256_hex(&served), "{pinned}");
    assert_eq!(pinned["octets"], served.len(), "{pinned}");

    // The bad addresses come before the built-in one: a server that skipped its
    // check would otherwise go out and read w3.org.
    for (url, says) in [
        (
            "ftp://contexts.example/v1".to_owned(),
            "absolute http or https",
        ),
        (
            format!("{base}/small/{}", "a".repeat(2048)),
            "at most 2048 characters",
        ),
        (
            "https://www.w3.org/2018/credentials/v1".to_owned(),
            "built in",
        ),
        (format!("{base}/vocabulary"), "a vocabulary mapping"),
        (format!("{base}/naming"), "is not one held here"),
        (format!("{base}/page"), "not one JSON document"),
    ] {
        let (status, told) = asked_under(
            &plane,
            Egress::Anywhere,
            Method::POST,
            &contexts,
            &bearer,
            Some(pin(url.clone())),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{url}: {told}");
        assert!(
            told["message"]
                .as_str()
                .is_some_and(|held| held.contains(says)),
            "{url}: {told}"
        );
    }
    for url in [format!("{base}/terms"), format!("{base}/naming")] {
        let (status, told) = asked_under(
            &plane,
            Egress::Anywhere,
            Method::POST,
            &contexts,
            &bearer,
            Some(pin(url.clone())),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{url}: {told}");
    }
    let (status, told) = asked_under(
        &plane,
        Egress::Anywhere,
        Method::POST,
        &contexts,
        &bearer,
        Some(pin(format!("{base}/insurance"))),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "realm.jsonld_context.already_pinned");

    // A server that may only dial https reads nothing from a plain address.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &contexts,
        &bearer,
        Some(pin(format!("{base}/small/0"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, listed) = asked(&plane, Method::GET, &contexts, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["running"], true);
    assert_eq!(
        listed["built_in"].as_array().map(Vec::len),
        Some(3),
        "{listed}"
    );
    assert_eq!(
        listed["items"].as_array().map(Vec::len),
        Some(3),
        "{listed}"
    );

    let id = pinned["id"].as_str().expect("an identity");
    *insurance.lock().expect("the document") =
        json!({ "@context": { "@vocab": "https://example.com/terms#" } }).to_string();
    let (status, told) = asked_under(
        &plane,
        Egress::Anywhere,
        Method::POST,
        &format!("{contexts}/{id}/document"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let (_, listed) = asked(&plane, Method::GET, &contexts, &bearer, None).await;
    assert_eq!(
        listed["items"][0]["digest"], first_digest,
        "a document that does not read replaced the one kept: {listed}"
    );
    *insurance.lock().expect("the document") =
        json!({ "@context": { "policyName": "https://schema.org/name" } }).to_string();
    let (status, again) = asked_under(
        &plane,
        Egress::Anywhere,
        Method::POST,
        &format!("{contexts}/{id}/document"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    let served = insurance.lock().expect("the document").clone();
    assert_eq!(again["digest"], sha256_hex(&served), "{again}");
    assert_ne!(again["digest"], first_digest, "{again}");
    assert!(
        again["read_at"].as_str() >= pinned["read_at"].as_str(),
        "{again}"
    );

    for n in 3..services::admin::jsonld_contexts::MAX_CONTEXTS {
        let (status, told) = asked_under(
            &plane,
            Egress::Anywhere,
            Method::POST,
            &contexts,
            &bearer,
            Some(pin(format!("{base}/small/{n}"))),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{n}: {told}");
    }
    let (status, told) = asked_under(
        &plane,
        Egress::Anywhere,
        Method::POST,
        &contexts,
        &bearer,
        Some(pin(format!("{base}/small/past"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|held| held.contains("at most 50")),
        "{told}"
    );

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{contexts}/{id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{contexts}/{id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "realm.jsonld_context.not_found");
}

/// A PID issuer on a real socket, publishing one key in its JWT VC metadata.
fn serve_pid_issuer(key: Value) -> String {
    use actix_web::{App, HttpResponse, HttpServer, web};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let base = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    let served = base.clone();
    let server = HttpServer::new(move || {
        let (base, key) = (served.clone(), key.clone());
        App::new().route(
            "/.well-known/jwt-vc-issuer/pid",
            web::get().to(move || {
                let document =
                    json!({ "issuer": format!("{base}/pid"), "jwks": { "keys": [key.clone()] } });
                async move { HttpResponse::Ok().json(document) }
            }),
        )
    })
    .listen(listener)
    .expect("a listener")
    .workers(1)
    .disable_signals()
    .run();
    tokio::spawn(server);
    base
}

/// What a wallet holds and does, played the way Inji's library plays it.
#[derive(Clone)]
struct Wallet {
    issuer: String,
    issuer_key: crypto::jose::jwk::alg::ed::EdKeyPair,
    holder_key: crypto::jose::jwk::alg::ec::EcKeyPair,
    vct: &'static str,
}

impl Wallet {
    fn new(issuer: String, issuer_key: crypto::jose::jwk::alg::ed::EdKeyPair) -> Self {
        Self {
            issuer,
            issuer_key,
            holder_key: crypto::jose::jwk::alg::ec::EcKeyPair::generate(
                crypto::jose::jwk::alg::ec::EcCurve::P256,
            )
            .expect("a holder key"),
            vct: "urn:eudi:pid:1",
        }
    }

    /// A PID the issuer signed, every personal claim concealed.
    fn issued(&self) -> String {
        use crypto::jose::jwk::KeyPair;
        use crypto::jose::jws::{EdDSA, JwsHeader};
        use crypto::sd_jwt::{Concealed, conceal_claims};
        let now = chrono::Utc::now().timestamp();
        let Value::Object(claims) = json!({
            "iss": format!("{}/pid", self.issuer),
            "vct": self.vct,
            "iat": now,
            "exp": now + 3600,
            "cnf": { "jwk": self.holder_key.to_jwk_public_key().as_ref() },
            "given_name": "Ada",
            "family_name": "Lovelace",
            "birthdate": "1815-12-10",
            "address": { "locality": "London", "country": "GB" },
        }) else {
            unreachable!()
        };
        let concealment = conceal_claims(
            &support::provider(),
            claims,
            &[
                Concealed::Property(&["given_name"]),
                Concealed::Property(&["family_name"]),
                Concealed::Property(&["birthdate"]),
                Concealed::Property(&["address", "locality"]),
                Concealed::Property(&["address", "country"]),
            ],
            2,
        )
        .expect("concealed");
        let mut header = JwsHeader::new();
        header.set_token_type("dc+sd-jwt");
        header.set_key_id("pid-2026");
        let signer = EdDSA
            .signer_from_pem(self.issuer_key.to_pem_private_key())
            .expect("an issuer signer");
        let signed = crypto::jose::jws::serialize_compact(
            Value::Object(concealment.payload.clone())
                .to_string()
                .as_bytes(),
            &header,
            &signer,
        )
        .expect("signed");
        concealment.issued(&signed)
    }

    /// A presentation disclosing the claims named, bound to one request.
    fn presented_disclosing(&self, audience: &str, nonce: &str, names: &[&str]) -> String {
        use crypto::jose::jwk::KeyPair;
        use crypto::jose::jws::ES256;
        let presentation = crypto::sd_jwt::select_disclosures(&self.issued(), |disclosure| {
            disclosure
                .name
                .as_deref()
                .is_some_and(|name| names.contains(&name))
        })
        .expect("selected");
        let holder = ES256
            .signer_from_pem(self.holder_key.to_pem_private_key())
            .expect("a holder signer");
        crypto::sd_jwt::bind_presentation(
            &support::provider(),
            &presentation,
            &holder,
            audience,
            nonce,
            chrono::Utc::now().timestamp(),
        )
        .expect("bound")
    }

    /// The presentation the PID query asks for.
    fn presented(&self, audience: &str, nonce: &str) -> String {
        self.presented_disclosing(audience, nonce, &["given_name", "family_name", "locality"])
    }
}

/// The path part of an address the realm wrote, for the server under test.
fn path_of(address: &str) -> String {
    let parsed = url::Url::parse(address).expect("an address");
    match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_owned(),
    }
}

/// Read a request the way a wallet does: fetch it at the address the link
/// gives, find the signing key in the realm's DID document by the `kid`, and
/// verify it.
async fn read_request(plane: &Plane, link: &str) -> serde_json::Map<String, Value> {
    use crypto::jose::jws::EdDSA;
    let link = url::Url::parse(link).expect("an openid4vp link");
    assert_eq!(link.scheme(), "openid4vp");
    assert_eq!(
        link.host_str(),
        Some("authorize"),
        "Inji's wallets take no other link"
    );
    let given = |name: &str| {
        link.query_pairs()
            .find(|(held, _)| held == name)
            .map(|(_, value)| value.into_owned())
            .unwrap_or_else(|| panic!("a link without {name}"))
    };
    let (status, signed) = fetched(plane, Method::GET, &path_of(&given("request_uri")), None).await;
    assert_eq!(status, StatusCode::OK, "{signed}");

    let header: Value = serde_json::from_slice(
        &data_encoding::BASE64URL_NOPAD
            .decode(signed.split('.').next().expect("a header").as_bytes())
            .expect("base64url"),
    )
    .expect("a JSON header");
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "oauth-authz-req+jwt");
    let kid = header["kid"].as_str().expect("a kid");

    let (status, document) = fetched(
        plane,
        Method::GET,
        &format!("/realms/{REALM}/did.json"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{document}");
    let document: Value = serde_json::from_str(&document).expect("a DID document");
    let method = document["verificationMethod"]
        .as_array()
        .expect("methods")
        .iter()
        .find(|method| method["id"] == kid)
        .expect("the request's kid names a method of the realm's DID");
    let multibase = method["publicKeyMultibase"]
        .as_str()
        .expect("a multibase key");
    let decoded =
        services::verifier::base58::decode(&multibase[1..]).expect("base58 after the `z`");
    assert_eq!(decoded[..2], [0xed, 0x01], "an Ed25519 multicodec prefix");
    let key = crypto::jose::jwk::Jwk::from_map(
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": data_encoding::BASE64URL_NOPAD.encode(&decoded[2..]),
        })
        .as_object()
        .expect("a JWK")
        .clone(),
    )
    .expect("a key");
    let verifier = EdDSA.verifier_from_jwk(&key).expect("a verifier");
    let (payload, _) = crypto::jose::jws::deserialize_compact(&signed, &verifier)
        .expect("a request the realm signed");
    let Value::Object(request) = serde_json::from_slice(&payload).expect("a JSON request") else {
        panic!("a request that is not an object")
    };
    assert_eq!(request["client_id"], given("client_id").as_str());
    assert_eq!(
        format!("{}#", document["id"].as_str().expect("a DID")),
        kid[..kid.find('#').expect("a fragment") + 1],
        "the request is signed under another DID"
    );
    assert_eq!(
        request["response_uri"], document["service"][0]["serviceEndpoint"],
        "the answer's address is not the one the DID declares"
    );
    request
}

/// Encrypt an answer to the key the request drew, as `direct_post.jwt` asks.
fn encrypted(request: &serde_json::Map<String, Value>, answer: &Value) -> String {
    use crypto::jose::jwe::{ECDH_ES, JweHeader};
    let key = crypto::jose::jwk::Jwk::from_map(
        request["client_metadata"]["jwks"]["keys"][0]
            .as_object()
            .expect("the answer's key")
            .clone(),
    )
    .expect("a JWK");
    let mut header = JweHeader::new();
    header.set_content_encryption("A256GCM");
    header.set_key_id(key.key_id().expect("a kid"));
    let encrypter = ECDH_ES.encrypter_from_jwk(&key).expect("an encrypter");
    crypto::jose::jwe::serialize_compact(answer.to_string().as_bytes(), &header, &encrypter)
        .expect("encrypted")
}

/// Set a realm up to verify: the verifier running, an Ed25519 key, and a PID
/// issuer named. Hands back the wallet that holds that issuer's credential.
async fn realm_ready_to_verify(plane: &Plane, bearer: &str) -> Wallet {
    use crypto::jose::jwk::KeyPair;
    verifier_running();
    let issuer_key = crypto::jose::jwk::alg::ed::EdKeyPair::generate(crypto::jose::jwk::Ed25519)
        .expect("an issuer key");
    let mut public = issuer_key.to_jwk_public_key();
    public.set_key_id("pid-2026");
    let base = serve_pid_issuer(Value::Object(public.as_ref().clone()));
    let (status, told) = asked_under(
        plane,
        config::serving::Egress::Anywhere,
        Method::POST,
        &format!("/admin/realms/{REALM}/credential-issuers"),
        bearer,
        Some(json!({ "name": "PID", "issuer": format!("{base}/pid") })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let (status, told) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/keys"),
        bearer,
        Some(json!({ "algorithm": "EdDSA" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    Wallet::new(base, issuer_key)
}

fn pid_query() -> Value {
    json!({
        "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:1"] },
            "claims": [
                { "path": ["given_name"] },
                { "path": ["family_name"] },
                { "path": ["address", "locality"] }
            ]
        }]
    })
}

/// Ask the realm for a PID, and read the request as the wallet reads it.
async fn ask_for_pid(plane: &Plane, bearer: &str) -> (Value, serde_json::Map<String, Value>) {
    ask_for(plane, bearer, &pid_query()).await
}

/// Ask the realm for what `query` names, and read the request as the wallet
/// reads it.
async fn ask_for(
    plane: &Plane,
    bearer: &str,
    query: &Value,
) -> (Value, serde_json::Map<String, Value>) {
    let (status, asked_for) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/presentations"),
        bearer,
        Some(json!({ "dcql_query": query })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{asked_for}");
    let request = read_request(plane, asked_for["uri"].as_str().expect("a link")).await;
    (asked_for, request)
}

/// Post to the address the request names, as a wallet does.
async fn answered(
    plane: &Plane,
    request: &serde_json::Map<String, Value>,
    form: &[(&str, &str)],
) -> (StatusCode, String) {
    let at = path_of(request["response_uri"].as_str().expect("a response_uri"));
    fetched(plane, Method::POST, &at, Some(form)).await
}

/// Where a request stands, read by the administrator who asked.
async fn standing_of(plane: &Plane, bearer: &str, id: &Value) -> Value {
    let id = id.as_str().expect("an id");
    let (status, standing) = asked(
        plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/presentations/{id}"),
        bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{standing}");
    standing
}

async fn plane_that_verifies() -> (Plane, String) {
    let plane = Plane::with_actions(&[
        AdminAction::RealmRead,
        AdminAction::RealmWrite,
        AdminAction::RealmKeysWrite,
        AdminAction::FeatureWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    (plane, bearer)
}

/// The whole door, against a wallet that does what Inji's library does: the
/// realm asks, the wallet verifies the request by the realm's DID, presents a
/// PID bound to the request and encrypted to the key it drew, and the realm
/// verifies it against the issuer it names. What it keeps names the claims,
/// never their values, and the same answer does not settle it twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_wallet_answers_a_presentation_request() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_ready_to_verify(&plane, &bearer).await;

    let (asked_for, request) = ask_for_pid(&plane, &bearer).await;
    assert_eq!(
        asked_for["qr"].as_str(),
        commons::qr::draw_qr_svg(asked_for["uri"].as_str().expect("a link")).as_deref(),
        "the QR code draws the link a wallet opens"
    );
    let client_id = request["client_id"].as_str().expect("a client_id");
    assert!(
        client_id.starts_with("decentralized_identifier:did:web:id.test:realms:"),
        "{client_id}"
    );
    assert_eq!(request["response_type"], "vp_token");
    assert_eq!(request["response_mode"], "direct_post.jwt");
    assert_eq!(request["state"], asked_for["id"]);
    assert_eq!(request["dcql_query"], pid_query());
    let key = &request["client_metadata"]["jwks"]["keys"][0];
    assert_eq!(
        (key["alg"].as_str(), key["use"].as_str()),
        (Some("ECDH-ES"), Some("enc"))
    );
    assert!(
        key.get("d").is_none(),
        "the answer's private key left the realm"
    );
    let standing = standing_of(&plane, &bearer, &asked_for["id"]).await;
    assert_eq!(standing["status"], "pending", "{standing}");

    let nonce = request["nonce"].as_str().expect("a nonce");
    let answer = json!({
        "vp_token": { "pid": [wallet.presented(client_id, nonce)] },
        "state": request["state"],
    });
    let response = encrypted(&request, &answer);
    let (status, told) = answered(&plane, &request, &[("response", &response)]).await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let standing = standing_of(&plane, &bearer, &asked_for["id"]).await;
    assert_eq!(standing["status"], "verified", "{standing}");
    assert_eq!(
        standing["outcome"]["credentials"],
        json!([{
            "id": "pid",
            "issuer": format!("{}/pid", wallet.issuer),
            "vct": "urn:eudi:pid:1",
            "claims": ["given_name", "family_name", "address.locality"],
        }])
    );
    let kept = standing.to_string();
    for value in ["Ada", "Lovelace", "London"] {
        assert!(!kept.contains(value), "a disclosed value was kept: {kept}");
    }

    let (status, told) = answered(&plane, &request, &[("response", &response)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert!(told.contains("no request is waiting"), "{told}");
    let (status, _) = fetched(
        &plane,
        Method::GET,
        &format!(
            "/realms/{REALM}/vp/request/{}",
            request["state"].as_str().expect("an id")
        ),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an answered request is still served"
    );

    // A realm that closes the verifier serves no request, takes no answer and
    // asks for nothing more.
    let (_, pending) = ask_for_pid(&plane, &bearer).await;
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/features/wallet-verifier"),
        &bearer,
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let state = pending["state"].as_str().expect("a state");
    let (status, _) = fetched(
        &plane,
        Method::GET,
        &format!("/realms/{REALM}/vp/request/{state}"),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a closed verifier serves a request"
    );
    let (status, _) = answered(
        &plane,
        &pending,
        &[("error", "access_denied"), ("state", state)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a closed verifier takes an answer"
    );
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/presentations"),
        &bearer,
        Some(json!({ "dcql_query": pid_query() })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
}

/// Ask for a PID, answer with what `answer` makes of the request, and check
/// the request failed, once, for the reason given.
async fn answer_fails(
    plane: &Plane,
    bearer: &str,
    reason: &str,
    answer: impl FnOnce(&serde_json::Map<String, Value>) -> Value,
) {
    answer_to_fails(plane, bearer, &pid_query(), reason, answer).await;
}

/// Ask for what `query` names, answer with what `answer` makes of the request,
/// and check the request failed, once, for the reason given.
async fn answer_to_fails(
    plane: &Plane,
    bearer: &str,
    query: &Value,
    reason: &str,
    answer: impl FnOnce(&serde_json::Map<String, Value>) -> Value,
) {
    let (asked_for, request) = ask_for(plane, bearer, query).await;
    let response = encrypted(&request, &answer(&request));
    let (status, told) = answered(plane, &request, &[("response", &response)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reason}: {told}");
    let told: Value = serde_json::from_str(&told).expect("a JSON error");
    assert_eq!(told["error_description"], reason);
    let standing = standing_of(plane, bearer, &asked_for["id"]).await;
    assert_eq!(standing["status"], "failed", "{standing}");
    assert_eq!(standing["outcome"]["reason"], reason);
}

fn client_id_and_nonce(request: &serde_json::Map<String, Value>) -> (&str, &str) {
    (
        request["client_id"].as_str().expect("a client_id"),
        request["nonce"].as_str().expect("a nonce"),
    )
}

/// Each check a presentation must pass fails its request on its own, in the
/// realm's words: a refusal the wallet sends settles it as refused, and a
/// state no request holds is not an answer to anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_answer_that_does_not_hold_settles_its_request_once() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_ready_to_verify(&plane, &bearer).await;
    let (plane, bearer) = (&plane, bearer.as_str());
    let pid = |presented: String, request: &serde_json::Map<String, Value>| json!({ "vp_token": { "pid": [presented] }, "state": request["state"] });

    answer_fails(
        plane,
        bearer,
        "a credential's disclosures, key binding or time claims do not hold",
        |request| {
            let (client_id, _) = client_id_and_nonce(request);
            pid(wallet.presented(client_id, "another-nonce"), request)
        },
    )
    .await;
    answer_fails(
        plane,
        bearer,
        "a credential's issuer is not one this realm names",
        |request| {
            let (client_id, nonce) = client_id_and_nonce(request);
            let impostor = Wallet {
                issuer: "https://elsewhere.example".to_owned(),
                ..wallet.clone()
            };
            pid(impostor.presented(client_id, nonce), request)
        },
    )
    .await;
    answer_fails(
        plane,
        bearer,
        "a credential's signature is not its issuer's",
        |request| {
            let (client_id, nonce) = client_id_and_nonce(request);
            let forger = Wallet {
                issuer_key: crypto::jose::jwk::alg::ed::EdKeyPair::generate(
                    crypto::jose::jwk::Ed25519,
                )
                .expect("a key"),
                ..wallet.clone()
            };
            pid(forger.presented(client_id, nonce), request)
        },
    )
    .await;
    answer_fails(
        plane,
        bearer,
        "a credential is of a type the query did not accept",
        |request| {
            let (client_id, nonce) = client_id_and_nonce(request);
            let student = Wallet {
                vct: "urn:example:student:1",
                ..wallet.clone()
            };
            pid(student.presented(client_id, nonce), request)
        },
    )
    .await;
    answer_fails(
        plane,
        bearer,
        "a credential lacks a claim the query asked for",
        |request| {
            let (client_id, nonce) = client_id_and_nonce(request);
            let presented =
                wallet.presented_disclosing(client_id, nonce, &["given_name", "family_name"]);
            pid(presented, request)
        },
    )
    .await;
    answer_fails(
        plane,
        bearer,
        "each credential asked for is presented once",
        |request| json!({ "vp_token": { "pid": [] }, "state": request["state"] }),
    )
    .await;
    answer_fails(
        plane,
        bearer,
        "each credential asked for is presented once",
        |request| {
            let (client_id, nonce) = client_id_and_nonce(request);
            let presented = wallet.presented(client_id, nonce);
            json!({ "vp_token": { "pid": [presented.clone(), presented] }, "state": request["state"] })
        },
    )
    .await;
    answer_fails(
        plane,
        bearer,
        "the answer carries a credential the query did not ask for",
        |request| {
            let (client_id, nonce) = client_id_and_nonce(request);
            let presented = wallet.presented(client_id, nonce);
            json!({
                "vp_token": { "pid": [presented.clone()], "mdl": [presented] },
                "state": request["state"],
            })
        },
    )
    .await;
    answer_fails(
        plane,
        bearer,
        "the answer names another request",
        |request| {
            let (client_id, nonce) = client_id_and_nonce(request);
            json!({
                "vp_token": { "pid": [wallet.presented(client_id, nonce)] },
                "state": "another-request",
            })
        },
    )
    .await;
    answer_fails(
        plane,
        bearer,
        "the answer carries no vp_token object",
        |request| {
            let (client_id, nonce) = client_id_and_nonce(request);
            json!({ "vp_token": [wallet.presented(client_id, nonce)], "state": request["state"] })
        },
    )
    .await;

    let (asked_for, request) = ask_for_pid(plane, bearer).await;
    let state = request["state"].as_str().expect("a state");
    let (status, told) = answered(
        plane,
        &request,
        &[("error", "access_denied"), ("state", state)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let standing = standing_of(plane, bearer, &asked_for["id"]).await;
    assert_eq!(standing["status"], "refused", "{standing}");
    assert_eq!(standing["outcome"]["error"], "access_denied");

    let (status, told) = answered(
        plane,
        &request,
        &[("error", "access_denied"), ("state", "no-such-request")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");

    // The sweep keeps every request a day past its window, then takes it.
    use services::realm::housekeeping::{PRESENTATIONS_KEPT_HOURS, drop_expired_rows};
    let transaction = plane
        .scoped(&store::tenancy::TenantContext::new(support::TENANT, REALM))
        .await;
    let closed = chrono::Utc::now()
        + chrono::Duration::seconds(services::verifier::presentation::LIFETIME_SECONDS)
        + chrono::Duration::minutes(1);
    let swept = drop_expired_rows(&transaction, closed)
        .await
        .expect("a sweep");
    assert_eq!(swept.presentation_requests, 0);
    let swept = drop_expired_rows(
        &transaction,
        closed + chrono::Duration::hours(PRESENTATIONS_KEPT_HOURS),
    )
    .await
    .expect("a sweep");
    assert_eq!(swept.presentation_requests, 11);
}

/// The type the scripted issuer's identity credentials hold, expanded.
const IDENTITY_TYPE: &str = "https://issuer.example/vocab#IdentityCredential";
const CREDENTIAL_TYPE: &str = "https://www.w3.org/2018/credentials#VerifiableCredential";

/// The context the identity credentials name: their type and claims MOSIP's
/// identity credentials hold; two claims written to one property, as issuers'
/// contexts write them; terms naming again the issuer, the subject and the
/// expiry the credentials context names; and an index map.
fn identity_context() -> Value {
    json!({ "@context": {
        "@version": 1.1,
        "IdentityCredential": IDENTITY_TYPE,
        "fullName": "https://schema.org/name",
        "dateOfBirth": "https://schema.org/birthDate",
        "policyName": "https://schema.org/Text",
        "policyNumber": "https://schema.org/Text",
        "issuedBy": { "@id": "https://www.w3.org/2018/credentials#issuer", "@type": "@id" },
        "holderSubject": {
            "@id": "https://www.w3.org/2018/credentials#credentialSubject",
            "@type": "@id"
        },
        "validity": {
            "@id": "https://www.w3.org/2018/credentials#expirationDate",
            "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "identifiers": {
            "@id": "https://issuer.example/vocab#identifiers",
            "@container": "@index"
        }
    } })
}

/// A context the issuer's credentials may name and the realm never pins.
const UNPINNED_CONTEXT: &str = "https://issuer.example/contexts/unpinned.jsonld";

/// An issuer of JSON-LD credentials on a real socket: its JWT VC issuer
/// metadata, each key named by the absolute method identifier a proof names it
/// with, and the context its credentials name.
fn serve_identity_issuer(keys: Vec<(&'static str, Value)>) -> String {
    use actix_web::{App, HttpResponse, HttpServer, web};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let base = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    let served = base.clone();
    let server = HttpServer::new(move || {
        let (base, keys) = (served.clone(), keys.clone());
        App::new()
            .route(
                "/.well-known/jwt-vc-issuer/identity",
                web::get().to(move || {
                    let keys: Vec<Value> = keys
                        .iter()
                        .map(|(fragment, key)| {
                            let mut key = key.clone();
                            key["kid"] = json!(format!("{base}/identity#{fragment}"));
                            key
                        })
                        .collect();
                    let document = json!({
                        "issuer": format!("{base}/identity"),
                        "jwks": { "keys": keys },
                    });
                    async move { HttpResponse::Ok().json(document) }
                }),
            )
            .route(
                "/contexts/identity.jsonld",
                web::get().to(|| async { HttpResponse::Ok().json(identity_context()) }),
            )
    })
    .listen(listener)
    .expect("a listener")
    .workers(1)
    .disable_signals()
    .run();
    tokio::spawn(server);
    base
}

/// A holder of a JSON-LD identity credential, presenting it the way Inji's
/// wallets do: the credential alone in a presentation, signed with a detached
/// JWS by the `did:jwk` key the credential binds, for one request.
#[derive(Clone)]
struct IdentityWallet {
    base: String,
    issuer_key: crypto::jose::jwk::alg::ed::EdKeyPair,
    holder_key: crypto::jose::jwk::alg::ec::EcKeyPair,
}

impl IdentityWallet {
    fn issuer(&self) -> String {
        format!("{}/identity", self.base)
    }

    fn context_url(&self) -> String {
        format!("{}/contexts/identity.jsonld", self.base)
    }

    /// The holder's DID, its key base64url-encoded: padded, as MOSIP's issuers
    /// write it in a credential, or not, as Inji's wallets sign with it.
    fn holder_did(&self, padded: bool) -> String {
        use crypto::jose::jwk::KeyPair;
        let jwk = Value::Object(self.holder_key.to_jwk_public_key().as_ref().clone()).to_string();
        let encoding = if padded {
            data_encoding::BASE64URL
        } else {
            data_encoding::BASE64URL_NOPAD
        };
        format!("did:jwk:{}", encoding.encode(jwk.as_bytes()))
    }

    /// The SHA-256 of a document's dataset in canonical form, read under the
    /// contexts the issuer and the wallet hold, within bounds far above the
    /// realm's: what the issuer signs, the realm may still refuse to read.
    fn hash_canonical(&self, document: &Value) -> Vec<u8> {
        use crypto::provider::{CryptoProvider, HashAlg};
        let held = std::collections::HashMap::from([
            (self.context_url(), identity_context()),
            (
                UNPINNED_CONTEXT.to_owned(),
                json!({ "@context": { "nickname": "https://schema.org/alternateName" } }),
            ),
        ]);
        let contexts = jsonld::built_in::HeldContexts::new(&held);
        let quads = jsonld::to_rdf(document, &contexts, 100_000).expect("a dataset");
        let provider = support::provider();
        let canonical = jsonld::canon::canonicalize(&provider, HashAlg::Sha256, &quads, 100_000)
            .expect("a canonical form");
        provider
            .digest()
            .hash(HashAlg::Sha256, canonical.nquads.as_bytes())
            .expect("a digest")
    }

    /// The credential the issuer signs, `change` made to it and to its proof's
    /// options first.
    fn issued_as(&self, change: impl FnOnce(&mut Value, &mut Value)) -> Value {
        use crypto::jose::jws::EdDSA;
        let now = chrono::Utc::now();
        let written = |at: chrono::DateTime<chrono::Utc>| {
            at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        };
        let mut credential = json!({
            "@context": [
                jsonld::built_in::CREDENTIALS_V1,
                self.context_url(),
                jsonld::built_in::ED25519_2020_V1,
            ],
            "id": "urn:uuid:0f5b4a52-6a0f-4b8e-9a51-6f3c4d2e1b7a",
            "type": ["VerifiableCredential", "IdentityCredential"],
            "issuer": self.issuer(),
            "issuanceDate": written(now - chrono::Duration::hours(1)),
            "expirationDate": written(now + chrono::Duration::days(365)),
            "credentialSubject": {
                "id": self.holder_did(true),
                "fullName": "Ama Mensah",
                "dateOfBirth": "1990-04-15",
                "policyName": "Family",
                "policyNumber": "5555",
            },
        });
        let mut options = json!({
            "type": "Ed25519Signature2020",
            "created": written(now),
            "verificationMethod": format!("{}#key-1", self.issuer()),
            "proofPurpose": "assertionMethod",
        });
        change(&mut credential, &mut options);
        options["@context"] = credential["@context"].clone();
        let signed = [
            self.hash_canonical(&options),
            self.hash_canonical(&credential),
        ]
        .concat();
        let signer = EdDSA
            .signer_from_pem(self.issuer_key.to_pem_private_key())
            .expect("an issuer signer");
        let signature = signer.sign(&signed).expect("a signature");
        let proof = options.as_object_mut().expect("an object");
        proof.remove("@context");
        proof.insert(
            "proofValue".to_owned(),
            json!(format!("z{}", jsonld::base58::encode(&signature))),
        );
        credential["proof"] = options;
        credential
    }

    /// The credential the issuer signs, `change` made to it first.
    fn issued_with(&self, change: impl FnOnce(&mut Value)) -> Value {
        self.issued_as(|credential, _| change(credential))
    }

    fn issued(&self) -> Value {
        self.issued_with(|_| {})
    }

    /// A presentation of `credentials` for the request `client_id` and `nonce`
    /// name, `change` made to it and to its proof's options before the holder
    /// signs.
    fn presented_as(
        &self,
        credentials: Vec<Value>,
        client_id: &str,
        nonce: &str,
        change: impl FnOnce(&mut Value, &mut Value),
    ) -> Value {
        use crypto::jose::jws::ES256;
        let holder = format!("{}#0", self.holder_did(false));
        let mut presentation = json!({
            "@context": [jsonld::built_in::CREDENTIALS_V1, jsonld::built_in::JWS_2020_V1],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": credentials,
            "id": "urn:uuid:9c1d7e2a-4b3f-4d6e-8a2b-1c0f5e6d7a8b",
            "holder": holder,
        });
        let mut options = json!({
            "type": "JsonWebSignature2020",
            "challenge": nonce,
            "domain": client_id,
            "verificationMethod": holder,
        });
        change(&mut presentation, &mut options);
        options["@context"] = presentation["@context"].clone();
        let signed = [
            self.hash_canonical(&options),
            self.hash_canonical(&presentation),
        ]
        .concat();
        let header = data_encoding::BASE64URL_NOPAD.encode(
            json!({ "alg": "ES256", "b64": false, "crit": ["b64"] })
                .to_string()
                .as_bytes(),
        );
        let signer = ES256
            .signer_from_pem(self.holder_key.to_pem_private_key())
            .expect("a holder signer");
        let signature = signer
            .sign(&[header.as_bytes(), b".", &signed].concat())
            .expect("a signature");
        let proof = options.as_object_mut().expect("an object");
        proof.remove("@context");
        proof.insert(
            "jws".to_owned(),
            json!(format!(
                "{header}..{}",
                data_encoding::BASE64URL_NOPAD.encode(&signature)
            )),
        );
        presentation["proof"] = options;
        presentation
    }

    fn presented(&self, credential: Value, client_id: &str, nonce: &str) -> Value {
        self.presented_as(vec![credential], client_id, nonce, |_, _| {})
    }
}

/// Set a realm up to verify identity credentials in JSON-LD: the verifier
/// running, an Ed25519 key, the issuer named with an Ed25519 key and an RSA
/// one, and its context pinned. Hands back the wallet that holds that issuer's
/// credential.
async fn realm_ready_for_identity(plane: &Plane, bearer: &str) -> IdentityWallet {
    use crypto::jose::jwk::KeyPair;
    verifier_running();
    let issuer_key = crypto::jose::jwk::alg::ed::EdKeyPair::generate(crypto::jose::jwk::Ed25519)
        .expect("an issuer key");
    let rsa = crypto::jose::jws::RS256
        .generate_key_pair(2048)
        .expect("an RSA key");
    let base = serve_identity_issuer(vec![
        (
            "key-1",
            Value::Object(issuer_key.to_jwk_public_key().as_ref().clone()),
        ),
        (
            "rsa",
            Value::Object(rsa.to_jwk_public_key().as_ref().clone()),
        ),
    ]);
    let wallet = IdentityWallet {
        base,
        issuer_key,
        holder_key: crypto::jose::jwk::alg::ec::EcKeyPair::generate(
            crypto::jose::jwk::alg::ec::EcCurve::P256,
        )
        .expect("a holder key"),
    };
    for (path, body) in [
        (
            "credential-issuers",
            json!({ "name": "Identity", "issuer": wallet.issuer() }),
        ),
        ("jsonld-contexts", json!({ "url": wallet.context_url() })),
    ] {
        let (status, told) = asked_under(
            plane,
            config::serving::Egress::Anywhere,
            Method::POST,
            &format!("/admin/realms/{REALM}/{path}"),
            bearer,
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{told}");
    }
    let (status, told) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/keys"),
        bearer,
        Some(json!({ "algorithm": "EdDSA" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    wallet
}

/// A query for the identity credential, and the claims `claims` names.
fn identity_query(claims: &[&[&str]]) -> Value {
    json!({
        "credentials": [{
            "id": "identity",
            "format": "ldp_vc",
            "meta": { "type_values": [[CREDENTIAL_TYPE, IDENTITY_TYPE]] },
            "claims": claims.iter().map(|path| json!({ "path": path })).collect::<Vec<_>>(),
        }]
    })
}

fn identity_answer(presentation: Value, request: &serde_json::Map<String, Value>) -> Value {
    json!({ "vp_token": { "identity": [presentation] }, "state": request["state"] })
}

/// The whole door for a JSON-LD credential, against a wallet that does what
/// Inji's wallets do: the realm asks by the credential's expanded types, the
/// wallet presents it in a presentation bound to the request, and the realm
/// verifies both proofs under the contexts it pinned and the key it read from
/// the issuer it names. What it keeps names the types and the claims, never a
/// value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_wallet_presents_a_json_ld_credential() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_ready_for_identity(&plane, &bearer).await;
    let query = identity_query(&[
        &["credentialSubject", "fullName"],
        &["credentialSubject", "dateOfBirth"],
    ]);
    let (asked_for, request) = ask_for(&plane, &bearer, &query).await;
    assert_eq!(request["dcql_query"], query);
    assert_eq!(
        request["client_metadata"]["vp_formats_supported"]["ldp_vc"]["proof_type_values"],
        json!(["Ed25519Signature2020", "JsonWebSignature2020"])
    );

    let (client_id, nonce) = client_id_and_nonce(&request);
    let answer = identity_answer(
        wallet.presented(wallet.issued(), client_id, nonce),
        &request,
    );
    let response = encrypted(&request, &answer);
    let (status, told) = answered(&plane, &request, &[("response", &response)]).await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let standing = standing_of(&plane, &bearer, &asked_for["id"]).await;
    assert_eq!(standing["status"], "verified", "{standing}");
    assert_eq!(
        standing["outcome"]["credentials"],
        json!([{
            "id": "identity",
            "issuer": wallet.issuer(),
            "types": [CREDENTIAL_TYPE, IDENTITY_TYPE],
            "claims": ["credentialSubject.fullName", "credentialSubject.dateOfBirth"],
        }])
    );
    let kept = standing.to_string();
    for value in ["Ama", "Mensah", "1990-04-15", "5555"] {
        assert!(!kept.contains(value), "a presented value was kept: {kept}");
    }

    // A proof naming the issuer's key under another identifier, as MOSIP's
    // issuers write one, is the issuer's all the same: the key decides.
    let (asked_for, request) = ask_for(&plane, &bearer, &query).await;
    let (client_id, nonce) = client_id_and_nonce(&request);
    let elsewhere = wallet.issued_as(|_, options| {
        options["verificationMethod"] = json!("did:web:keys.issuer.example#key-1");
    });
    let answer = identity_answer(wallet.presented(elsewhere, client_id, nonce), &request);
    let response = encrypted(&request, &answer);
    let (status, told) = answered(&plane, &request, &[("response", &response)]).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let standing = standing_of(&plane, &bearer, &asked_for["id"]).await;
    assert_eq!(standing["status"], "verified", "{standing}");
}

/// Each check a JSON-LD presentation must pass fails its request on its own,
/// in the realm's words.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_json_ld_presentation_that_does_not_hold_settles_its_request_once() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_ready_for_identity(&plane, &bearer).await;
    let (plane, bearer) = (&plane, bearer.as_str());
    let query = identity_query(&[&["credentialSubject", "fullName"]]);
    let present = |credential: Value, request: &serde_json::Map<String, Value>| {
        let (client_id, nonce) = client_id_and_nonce(request);
        identity_answer(wallet.presented(credential, client_id, nonce), request)
    };
    let present_as = |request: &serde_json::Map<String, Value>,
                      change: &dyn Fn(&mut Value, &mut Value)| {
        let (client_id, nonce) = client_id_and_nonce(request);
        identity_answer(
            wallet.presented_as(vec![wallet.issued()], client_id, nonce, change),
            request,
        )
    };
    // What the answer holds as the presentation, once the holder has signed.
    let signed_then = |request: &serde_json::Map<String, Value>,
                       change: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut answer = present(wallet.issued(), request);
        change(
            answer["vp_token"]["identity"][0]
                .as_object_mut()
                .expect("a presentation"),
        );
        answer
    };
    let refused = |query: &Value, reason: &'static str| (query.clone(), reason);

    // The presentation: its proof, its binding to the request and its holder.
    for (reason, answer) in [
        (
            "a presentation is not bound to this request",
            Box::new(|request: &serde_json::Map<String, Value>| {
                let (client_id, _) = client_id_and_nonce(request);
                identity_answer(
                    wallet.presented(wallet.issued(), client_id, "another-nonce"),
                    request,
                )
            }) as Box<dyn Fn(&serde_json::Map<String, Value>) -> Value>,
        ),
        (
            "a presentation is not bound to this request",
            Box::new(|request| {
                let (_, nonce) = client_id_and_nonce(request);
                identity_answer(
                    wallet.presented(
                        wallet.issued(),
                        "decentralized_identifier:did:web:elsewhere.example",
                        nonce,
                    ),
                    request,
                )
            }),
        ),
        (
            "a presentation's proof is not for authentication",
            Box::new(|request| {
                present_as(request, &|_, options| {
                    options["proofPurpose"] = json!("assertionMethod");
                })
            }),
        ),
        (
            "a presentation is not signed by a did:jwk key",
            Box::new(|request| {
                present_as(request, &|presentation, options| {
                    let method = format!("{}#key-1", wallet.holder_did(false));
                    presentation["holder"] = json!(method);
                    options["verificationMethod"] = json!(method);
                })
            }),
        ),
        (
            "a presentation names another holder than its signer",
            Box::new(|request| {
                present_as(request, &|presentation, _| {
                    presentation["holder"] = json!("did:example:someone-else");
                })
            }),
        ),
        (
            "a presentation's proof is missing or malformed",
            Box::new(|request| {
                signed_then(request, &|presentation| {
                    presentation.remove("proof");
                })
            }),
        ),
        (
            "a presentation's signature is not its holder's",
            Box::new(|request| {
                signed_then(request, &|presentation| {
                    presentation["verifiableCredential"][0]["credentialSubject"]["fullName"] =
                        json!("Kofi Owusu");
                })
            }),
        ),
        (
            "a presentation holds what its proofs would not sign",
            Box::new(|request| {
                signed_then(request, &|presentation| {
                    presentation["verifiableCredential"][0]["credentialSubject"]["nickname"] =
                        json!("Ama");
                })
            }),
        ),
        (
            "a presentation's proofs are malformed",
            Box::new(|request| {
                signed_then(request, &|presentation| {
                    presentation.remove("@context");
                })
            }),
        ),
        (
            "a presentation names a JSON-LD context this realm does not pin",
            Box::new(|request| {
                present(
                    wallet.issued_with(|credential| {
                        credential["@context"]
                            .as_array_mut()
                            .expect("contexts")
                            .push(json!(UNPINNED_CONTEXT));
                    }),
                    request,
                )
            }),
        ),
        (
            "a presentation is too large or too complex to verify",
            Box::new(|request| {
                present(
                    wallet.issued_with(|credential| {
                        credential["credentialSubject"]["policyName"] = json!(
                            (0..1_000)
                                .map(|at| format!("policy {at}"))
                                .collect::<Vec<_>>()
                        );
                    }),
                    request,
                )
            }),
        ),
        (
            "a presentation carries one credential",
            Box::new(|request| {
                let (client_id, nonce) = client_id_and_nonce(request);
                identity_answer(
                    wallet.presented_as(
                        vec![wallet.issued(), wallet.issued()],
                        client_id,
                        nonce,
                        |_, _| {},
                    ),
                    request,
                )
            }),
        ),
        (
            "a credential is not presented in the form its format takes",
            Box::new(|request| identity_answer(json!(wallet.issued().to_string()), request)),
        ),
    ] {
        answer_to_fails(plane, bearer, &query, reason, answer).await;
    }

    // The credential: its issuer, its proof, its binding, its dates, its type
    // and its claims.
    for ((query, reason), credential) in [
        (
            refused(&query, "a credential names no issuer"),
            wallet.issued_with(|credential| {
                credential
                    .as_object_mut()
                    .expect("a credential")
                    .remove("issuer");
            }),
        ),
        (
            refused(&query, "a credential's issuer is not one this realm names"),
            wallet.issued_with(|credential| {
                credential["issuer"] = json!("https://elsewhere.example/identity");
            }),
        ),
        (
            refused(&query, "a credential's proof is missing or malformed"),
            {
                let mut unproven = wallet.issued();
                unproven
                    .as_object_mut()
                    .expect("a credential")
                    .remove("proof");
                unproven
            },
        ),
        (
            refused(&query, "a credential's proof is not an assertion"),
            wallet.issued_as(|_, options| {
                options["proofPurpose"] = json!("authentication");
            }),
        ),
        (
            refused(&query, "a credential's signature is not its issuer's"),
            IdentityWallet {
                issuer_key: crypto::jose::jwk::alg::ed::EdKeyPair::generate(
                    crypto::jose::jwk::Ed25519,
                )
                .expect("a key"),
                ..wallet.clone()
            }
            .issued_as(|_, options| {
                options["verificationMethod"] = json!(format!("{}#key-2", wallet.issuer()));
            }),
        ),
        (
            refused(
                &query,
                "a credential is signed by a key this verifier does not read",
            ),
            wallet.issued_as(|_, options| {
                options["verificationMethod"] = json!(format!("{}#rsa", wallet.issuer()));
            }),
        ),
        (
            refused(&query, "a credential's signature is not its issuer's"),
            {
                let mut altered = wallet.issued();
                altered["credentialSubject"]["fullName"] = json!("Kofi Owusu");
                altered
            },
        ),
        (
            refused(
                &query,
                "a credential's issuer or holder rests on a member its proof does not tell apart",
            ),
            wallet.issued_with(|credential| {
                credential["issuedBy"] = json!("https://elsewhere.example/identity");
            }),
        ),
        (
            refused(
                &query,
                "a credential's issuer or holder rests on a member its proof does not tell apart",
            ),
            wallet.issued_with(|credential| {
                credential["holderSubject"] = json!({ "id": "did:example:someone-else" });
            }),
        ),
        (
            refused(&query, "a credential binds no did:jwk key"),
            wallet.issued_with(|credential| {
                credential["credentialSubject"]["id"] = json!("did:example:holder");
            }),
        ),
        (
            refused(
                &query,
                "a credential's dates are not RFC 3339 date-times its proof tells apart",
            ),
            wallet.issued_with(|credential| {
                credential["validity"] = json!("2026-01-01T00:00:00Z");
            }),
        ),
        (
            refused(&query, "a credential has expired"),
            wallet.issued_with(|credential| {
                credential["expirationDate"] = json!("2026-01-01T00:00:00Z");
            }),
        ),
        (
            refused(&query, "a credential is of a type the query did not accept"),
            wallet.issued_with(|credential| {
                credential["type"] = json!(["VerifiableCredential"]);
            }),
        ),
        (
            refused(&query, "a credential lacks a claim the query asked for"),
            wallet.issued_with(|credential| {
                credential["credentialSubject"]
                    .as_object_mut()
                    .expect("a subject")
                    .remove("fullName");
            }),
        ),
        (
            refused(
                &identity_query(&[&["credentialSubject", "policyNumber"]]),
                "a claim the query asked for shares its property with another member, so the proof does not tell them apart",
            ),
            wallet.issued(),
        ),
        (
            refused(
                &identity_query(&[&["credentialSubject", "identifiers"]]),
                "a claim the query asked for stands under an index map, whose keys the proof does not sign",
            ),
            wallet.issued_with(|credential| {
                credential["credentialSubject"]["identifiers"] = json!({ "uin": "4123456789" });
            }),
        ),
        (
            refused(
                &identity_query(&[&["credentialSubject", "fullName", "first"]]),
                "a claim the query asked for is not a property of a node",
            ),
            wallet.issued(),
        ),
    ] {
        answer_to_fails(plane, bearer, &query, reason, |request| {
            present(credential, request)
        })
        .await;
    }

    // Presented by another holder, a credential proves nothing of them.
    answer_to_fails(
        plane,
        bearer,
        &query,
        "a credential is not bound to the key that presents it",
        |request| {
            let (client_id, nonce) = client_id_and_nonce(request);
            let thief = IdentityWallet {
                holder_key: crypto::jose::jwk::alg::ec::EcKeyPair::generate(
                    crypto::jose::jwk::alg::ec::EcCurve::P256,
                )
                .expect("a key"),
                ..wallet.clone()
            };
            identity_answer(thief.presented(wallet.issued(), client_id, nonce), request)
        },
    )
    .await;
}
