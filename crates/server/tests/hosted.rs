//! A request object the client hosts, OIDC Core §6.2.

mod support;

use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::{App, HttpResponse, HttpServer, test, web};
use config::serving::Egress;
use crypto::jose::jwt::JwtPayload;
use crypto::provider::SignAlg;
use server::api::config::{Plane as Mounted, register};
use support::{Plane, SigningKey, urlencode};

const REDIRECT: &str = "https://app.example/callback";

fn mounted(plane: &Plane, egress: Egress) -> Mounted {
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
        egress,
        sealing: support::sealing(),
    }
}

/// A server standing in for the client's own, holding one object.
struct Hosting {
    port: u16,
    handle: actix_web::dev::ServerHandle,
}

impl Hosting {
    /// The same object at two paths. Only one of them is ever registered, so
    /// a check that stopped bounding where this server dials would be caught
    /// by the other answering just as well.
    async fn holding(object: String) -> Self {
        let held = Arc::new(object);
        let server = HttpServer::new(move || {
            let held = Arc::clone(&held);
            let answering = move || {
                let held = Arc::clone(&held);
                async move {
                    HttpResponse::Ok()
                        .content_type("application/oauth-authz-req+jwt")
                        .body(held.as_str().to_owned())
                }
            };
            App::new()
                .route("/object", web::get().to(answering.clone()))
                .route("/elsewhere", web::get().to(answering.clone()))
                .route("/object/deeper", web::get().to(answering))
        })
        .bind(("127.0.0.1", 0))
        .expect("a port");
        let port = server.addrs().first().expect("an address").port();
        let running = server.run();
        let handle = running.handle();
        tokio::spawn(running);
        Hosting { port, handle }
    }

    fn at(&self) -> String {
        format!("http://127.0.0.1:{}/object", self.port)
    }
}

/// Ask, and hand back where the browser was sent.
async fn asking(plane: &Plane, egress: Egress, uri: &str) -> (StatusCode, String) {
    let app = test::init_service(App::new().configure(register(&mounted(plane, egress)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?client_id={}&request_uri={}",
                support::REALM,
                support::CONFIDENTIAL,
                urlencode(uri),
            ))
            .to_request(),
    )
    .await;
    let status = response.status();
    let body = String::from_utf8_lossy(&test::read_body(response).await).into_owned();
    (status, body)
}

fn an_object(key: &SigningKey) -> String {
    let mut payload = JwtPayload::new();
    for (named, value) in [
        ("iss", support::CONFIDENTIAL),
        ("aud", &support::origin().issuer(support::REALM)),
        ("client_id", support::CONFIDENTIAL),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("state", "hosted-state"),
        ("nonce", "hosted-nonce"),
    ] {
        payload
            .set_claim(named, Some(serde_json::json!(value)))
            .expect("a claim");
    }
    key.sign(&payload, "client-key")
}

/// The object the client hosts governs the request, exactly as an inline one
/// does, and only where the client registered the place it is hosted at.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_hosted_object_is_read_where_it_was_registered() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("client-key");
    plane
        .register_client_keys(support::CONFIDENTIAL, &key, SignAlg::Es256)
        .await;
    let hosting = Hosting::holding(an_object(&key)).await;
    plane
        .register_request_uris(support::CONFIDENTIAL, &[hosting.at()])
        .await;

    let (status, body) = asking(&plane, Egress::Anywhere, &hosting.at()).await;
    assert_eq!(status, StatusCode::FOUND, "{body}");

    // A place this client never registered is one this server will not fetch,
    // whatever it holds.
    let (status, _) = asking(
        &plane,
        Egress::Anywhere,
        &format!("http://127.0.0.1:{}/elsewhere", hosting.port),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::FOUND,
        "an unregistered place was fetched"
    );

    hosting.handle.stop(true).await;
}

/// Where a deployment dials is its own choice, and the default is outward: an
/// address inside it is how a server is made to fetch on somebody else's
/// behalf.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_deployment_decides_where_it_will_dial() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("client-key");
    plane
        .register_client_keys(support::CONFIDENTIAL, &key, SignAlg::Es256)
        .await;
    let hosting = Hosting::holding(an_object(&key)).await;
    plane
        .register_request_uris(support::CONFIDENTIAL, &[hosting.at()])
        .await;

    let (status, _) = asking(&plane, Egress::Outward, &hosting.at()).await;
    assert_ne!(
        status,
        StatusCode::FOUND,
        "a loopback address was dialled by a deployment that dials outward"
    );
    hosting.handle.stop(true).await;
}

/// Nothing is read that is not there, and nothing is read over a connection
/// anything on the path could have written.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_is_not_there_is_not_a_request() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("client-key");
    plane
        .register_client_keys(support::CONFIDENTIAL, &key, SignAlg::Es256)
        .await;
    let hosting = Hosting::holding(an_object(&key)).await;
    let missing = format!("http://127.0.0.1:{}/nothing", hosting.port);
    let plain = hosting.at();
    plane
        .register_request_uris(support::CONFIDENTIAL, &[missing.clone(), plain.clone()])
        .await;

    // Registered and answered with nothing.
    let (status, _) = asking(&plane, Egress::Anywhere, &missing).await;
    assert_ne!(status, StatusCode::FOUND);

    hosting.handle.stop(true).await;
}
