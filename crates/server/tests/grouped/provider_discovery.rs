//! An operator names an issuer and the provider's endpoints follow from the
//! discovery document it publishes, read through the admin plane.
use super::broker_login::asked;
use super::support::{self, Plane};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, HttpResponse, HttpServer, web};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};

const REALM: &str = support::REALM;

/// What a national provider at `issuer` publishes, shaped as eSignet 2.0.0's.
fn publish_document(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "jwks_uri": format!("{issuer}/oauth2/jwks"),
        "userinfo_endpoint": format!("{issuer}/oauth2/userinfo"),
        "response_types_supported": ["code"],
        "id_token_signing_alg_values_supported": ["PS256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["PS256", "ES256"],
        "userinfo_encryption_alg_values_supported": ["RSA-OAEP-256"],
        "userinfo_encryption_enc_values_supported": ["A256GCM"],
        "claims_parameter_supported": true,
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
        "acr_values_supported": ["mosip:idp:acr:biometrics", "mosip:idp:acr:knowledge"],
    })
}

/// Issuers on a real socket, each publishing what its name says: the truth,
/// a document for another issuer, a redirect, or more than a document holds.
fn serve_issuers() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let base = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    let served = base.clone();
    let server = HttpServer::new(move || {
        let good = format!("{served}/good");
        App::new()
            .route(
                "/good/.well-known/openid-configuration",
                web::get().to(move || {
                    let document = publish_document(&good);
                    async move { HttpResponse::Ok().json(document) }
                }),
            )
            .route(
                "/liar/.well-known/openid-configuration",
                web::get().to(|| async {
                    HttpResponse::Ok().json(publish_document("https://elsewhere.example"))
                }),
            )
            .route(
                "/moved/.well-known/openid-configuration",
                web::get().to(|| async {
                    HttpResponse::Found()
                        .insert_header(("location", "/good/.well-known/openid-configuration"))
                        .finish()
                }),
            )
            .route(
                "/huge/.well-known/openid-configuration",
                web::get().to(|| async {
                    let mut document = publish_document("https://huge.example");
                    document["padding"] = json!("x".repeat(80 * 1024));
                    HttpResponse::Ok().json(document)
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

async fn discover_provider(plane: &Plane, bearer: &str, issuer: &str) -> (StatusCode, Value) {
    asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/provider-discovery"),
        bearer,
        Some(json!({ "issuer": issuer })),
    )
    .await
}

/// The endpoints, the algorithms, the contexts and the issuer parameter come
/// from the document the issuer publishes, and a provider written from them is
/// taken; a document for another issuer, one reached by a redirect, one past
/// what a document holds and an issuer that is not one are refused in words.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_provider_s_endpoints_follow_from_its_issuer() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = serve_issuers();
    let issuer = format!("{base}/good");

    let (status, found) = discover_provider(&plane, &bearer, &issuer).await;
    assert_eq!(status, StatusCode::OK, "{found}");
    assert_eq!(found["issuer"], issuer);
    assert_eq!(found["token_endpoint"], format!("{issuer}/oauth2/token"));
    assert_eq!(
        found["userinfo_endpoint"],
        format!("{issuer}/oauth2/userinfo")
    );
    assert_eq!(found["id_token_algs"], json!(["PS256"]));
    assert_eq!(
        found["acr_values"],
        json!(["mosip:idp:acr:biometrics", "mosip:idp:acr:knowledge"])
    );
    assert_eq!(found["iss_parameter"], true);
    assert_eq!(found["gaps"], json!([]));

    for (named, refusal) in [
        (
            format!("{base}/liar"),
            "the discovery document names another issuer: https://elsewhere.example".to_owned(),
        ),
        (
            format!("{base}/moved"),
            format!(
                "the discovery document at {base}/moved/.well-known/openid-configuration could not be read"
            ),
        ),
        (
            format!("{base}/huge"),
            format!(
                "the discovery document at {base}/huge/.well-known/openid-configuration could not be read"
            ),
        ),
        (
            "http://idp.example".to_owned(),
            "http://idp.example is not an issuer: an https address with no query or fragment"
                .to_owned(),
        ),
    ] {
        let (status, told) = discover_provider(&plane, &bearer, &named).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{named}: {told}");
        assert_eq!(told["message"], refusal, "{named}");
    }

    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        Some(json!({
            "provider_id": "discovered",
            "name": "discovered",
            "display_name": "Discovered",
            "description": "",
            "trust_email": false,
            "configs": {
                "issuer": { "Str": found["issuer"] },
                "authorization_endpoint": { "Str": found["authorization_endpoint"] },
                "token_endpoint": { "Str": found["token_endpoint"] },
                "jwks_uri": { "Str": found["jwks_uri"] },
                "allowed_algs": { "Str": "PS256" },
                "client_id": { "Str": "saffui" },
                "client_secret": { "Str": "a-shared-secret" },
                "iss_parameter": { "Str": "required" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
}

/// Reading the providers does not let a caller make the server fetch an
/// address of its choosing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn discovery_costs_the_right_to_write_providers() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead]).await;
    let bearer = plane.token(&support::claims());
    let base = serve_issuers();
    let (status, told) = discover_provider(&plane, &bearer, &format!("{base}/good")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{told}");
}

/// A deployment reaching outward only does not dial its own network for a
/// discovery document, whatever answers there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_issuer_inside_the_deployment_is_not_dialled() {
    use actix_web::test;
    use server::api::config::{Plane as Mounted, register};
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = serve_issuers();
    let outward = Mounted {
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
        ceiling: support::ceiling(),
    };
    let app = test::init_service(App::new().configure(register(&outward))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/admin/realms/{REALM}/provider-discovery"))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .set_json(json!({ "issuer": format!("{base}/good") }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let told: Value = test::read_body_json(response).await;
    assert_eq!(
        told["message"],
        format!(
            "the discovery document at {base}/good/.well-known/openid-configuration could not be read"
        )
    );
}
