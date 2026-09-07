#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;

const REALM: &str = support::REALM;
const GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const AUDIENCE: &str = "https://id.test/realms/main";

/// The bench's platform is this very realm, served over a real socket so
/// the JWKS fetch is a real fetch.
async fn platform_base(plane: &Plane) -> String {
    let served = mounted(plane);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let upstream = actix_web::HttpServer::new(move || App::new().configure(register(&served)))
        .listen(listener)
        .expect("a listener")
        .workers(1)
        .disable_signals()
        .run();
    tokio::spawn(upstream);
    format!("http://127.0.0.1:{port}/realms/{REALM}")
}

fn mounted(plane: &Plane) -> server::api::config::Plane {
    server::api::config::Plane {
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
        egress: config::serving::Egress::Anywhere,
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
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn exchanged(plane: &Plane, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
            .set_form(form)
            .to_request(),
    )
    .await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// A platform token the way GitHub mints one, signed by this realm's own
/// key: the bench's platform is the realm itself, jwks and all.
fn platform_token(plane: &Plane, issuer: &str, sub: &str, audience: &str) -> String {
    use crypto::jose::jwt::JwtPayload;
    let mut payload = JwtPayload::new();
    payload.set_issuer(issuer);
    payload.set_subject(sub);
    payload.set_audience(vec![audience]);
    payload.set_expires_at(&(std::time::SystemTime::now() + std::time::Duration::from_secs(300)));
    plane.token(&payload)
}

/// The trusted-platform row, spelled through the ordinary IdP admin door.
async fn trusted(plane: &Plane, bearer: &str, base: &str, patterns: &str) -> StatusCode {
    let (status, told) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        bearer,
        Some(json!({
            "provider_id": "the-forge",
            "name": "the-forge",
            "display_name": "The forge",
            "description": "",
            "trust_email": false,
            "configs": {
                "kind": { "Str": "workload" },
                "issuer": { "Str": base },
                "jwks_uri": { "Str": format!("{base}/protocol/openid-connect/certs") },
                "audience": { "Str": AUDIENCE },
                "subject_patterns": { "Str": patterns },
                "client_id": { "Str": support::CONFIDENTIAL },
                "allowed_algs": { "Str": "ES256" },
            },
        })),
    )
    .await;
    assert!(told.is_object() || told.is_null(), "{told}");
    status
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_pipeline_signs_in_with_no_secret_anywhere() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = platform_base(&plane).await;

    // Before any trust is declared, the grant answers one flat way.
    let token = platform_token(&plane, &base, "repo:acme/api:ref:refs/heads/main", AUDIENCE);
    let (status, told) = exchanged(&plane, &[("grant_type", GRANT), ("assertion", &token)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "invalid_grant", "{told}");

    // A bag missing its border is refused at the plane, not at a pipeline's
    // 2am deploy.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        Some(json!({
            "provider_id": "half-a-forge",
            "name": "half-a-forge",
            "display_name": "", "description": "", "trust_email": false,
            "configs": { "kind": { "Str": "workload" }, "issuer": { "Str": "https://somewhere" } },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    assert_eq!(
        trusted(
            &plane,
            &bearer,
            &base,
            "repo:acme/api:ref:refs/heads/main repo:acme/tools:*"
        )
        .await,
        StatusCode::CREATED
    );

    // The exchange: platform token in, realm access token out, no client
    // secret in sight.
    let (status, minted) = exchanged(&plane, &[("grant_type", GRANT), ("assertion", &token)]).await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    assert!(
        minted["refresh_token"].is_null(),
        "something renewable: {minted}"
    );
    let claims = plane
        .claims_of(minted["access_token"].as_str().expect("a token"))
        .await;
    assert_eq!(claims["sub"], "service-account-app", "{claims}");
    assert_eq!(
        claims["act"]["sub"], "repo:acme/api:ref:refs/heads/main",
        "{claims}"
    );
    assert_eq!(claims["azp"], support::CONFIDENTIAL, "{claims}");

    // The border holds: a fork, a feature branch, somebody else's audience,
    // an unknown issuer.
    for (sub, audience) in [
        ("repo:fork/api:ref:refs/heads/main", AUDIENCE),
        ("repo:acme/api:ref:refs/heads/feature", AUDIENCE),
        ("repo:acme/api:ref:refs/heads/main", "sts.amazonaws.com"),
    ] {
        let stray = platform_token(&plane, &base, sub, audience);
        let (status, told) =
            exchanged(&plane, &[("grant_type", GRANT), ("assertion", &stray)]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{sub} {audience}: {told}");
        assert_eq!(told["error"], "invalid_grant", "{told}");
    }
    let (status, told) = exchanged(
        &plane,
        &[("grant_type", GRANT), ("assertion", "not.a.token")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "invalid_grant", "{told}");

    // The prefix pattern admits the tag build.
    let tagged = platform_token(&plane, &base, "repo:acme/tools:ref:refs/tags/v1", AUDIENCE);
    let (status, _) = exchanged(&plane, &[("grant_type", GRANT), ("assertion", &tagged)]).await;
    assert_eq!(status, StatusCode::OK);

    // Switching the provider off closes the door with the same face.
    let (status, providers) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let alias = providers[0]["provider_id"]
        .as_str()
        .expect("an alias")
        .to_owned();
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/identity-providers/{alias}"),
        &bearer,
        Some(json!({
            "provider_id": alias,
            "name": alias,
            "display_name": "", "description": "", "trust_email": false,
            "enabled": false,
            "configs": {
                "kind": { "Str": "workload" },
                "issuer": { "Str": base },
                "jwks_uri": { "Str": format!("{base}/protocol/openid-connect/certs") },
                "audience": { "Str": AUDIENCE },
                "subject_patterns": { "Str": "repo:acme/api:ref:refs/heads/main" },
                "client_id": { "Str": support::CONFIDENTIAL },
                "allowed_algs": { "Str": "ES256" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, told) = exchanged(&plane, &[("grant_type", GRANT), ("assertion", &token)]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "invalid_grant", "{told}");
}

/// Only what a platform spells rides: the named claims are carried into
/// the minted token exactly as the platform spoke them, an unnamed one is
/// not, and naming a claim the minting itself owns is refused at the
/// write door, in words.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_the_spelled_platform_claims_ride_along() {
    use models::entities::authz::AdminAction;
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = platform_base(&plane).await;

    // A reserved name is a rewriting of the token's own grammar.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        Some(json!({
            "provider_id": "the-forge",
            "name": "the-forge",
            "display_name": "", "description": "", "trust_email": false,
            "configs": {
                "kind": { "Str": "workload" },
                "issuer": { "Str": base },
                "jwks_uri": { "Str": format!("{base}/protocol/openid-connect/certs") },
                "audience": { "Str": AUDIENCE },
                "subject_patterns": { "Str": "spiffe://forge/*" },
                "client_id": { "Str": support::CONFIDENTIAL },
                "allowed_algs": { "Str": "ES256" },
                "carried_claims": { "Str": "region sub" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .unwrap_or_default()
            .contains("the minting itself owns"),
        "{told}"
    );

    // Spelled honestly, the named claims ride and the rest stay home.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        Some(json!({
            "provider_id": "the-forge",
            "name": "the-forge",
            "display_name": "", "description": "", "trust_email": false,
            "configs": {
                "kind": { "Str": "workload" },
                "issuer": { "Str": base },
                "jwks_uri": { "Str": format!("{base}/protocol/openid-connect/certs") },
                "audience": { "Str": AUDIENCE },
                "subject_patterns": { "Str": "spiffe://forge/*" },
                "client_id": { "Str": support::CONFIDENTIAL },
                "allowed_algs": { "Str": "ES256" },
                "carried_claims": { "Str": "region cluster" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");

    let token = {
        use crypto::jose::jwt::JwtPayload;
        let mut payload = JwtPayload::new();
        payload.set_issuer(&base);
        payload.set_subject("spiffe://forge/billing");
        payload.set_audience(vec![AUDIENCE]);
        payload
            .set_expires_at(&(std::time::SystemTime::now() + std::time::Duration::from_secs(300)));
        payload.set_claim("region", Some(json!("eu-west"))).unwrap();
        payload.set_claim("cluster", Some(json!("blue"))).unwrap();
        payload
            .set_claim("stray", Some(json!("stays-home")))
            .unwrap();
        plane.token(&payload)
    };
    let (status, minted) = exchanged(&plane, &[("grant_type", GRANT), ("assertion", &token)]).await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    let access = minted["access_token"].as_str().expect("a token");
    let body: Value = {
        let middle = access.split('.').nth(1).expect("a JWT");
        use data_encoding::BASE64URL_NOPAD;
        serde_json::from_slice(&BASE64URL_NOPAD.decode(middle.as_bytes()).unwrap()).unwrap()
    };
    assert_eq!(body["region"], "eu-west", "{body}");
    assert_eq!(body["cluster"], "blue", "{body}");
    assert_eq!(
        body.get("stray"),
        None,
        "an unspelled platform claim rode along: {body}"
    );
    assert_eq!(
        body["act"]["sub"], "spiffe://forge/billing",
        "the acting chain was lost: {body}"
    );
}
