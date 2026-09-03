
#[allow(unused_imports)]
use super::support;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use super::support::{Plane, SigningKey, cookie_value, urlencode};

const REDIRECT: &str = "https://app.example/callback";

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

fn at(path: &str) -> String {
    format!(
        "{}/realms/{}/protocol/openid-connect/{path}",
        support::origin().as_str(),
        support::REALM
    )
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Sign in and hand back a code to exchange.
async fn code_for(plane: &Plane) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope=openid&state=s&nonce=n-0S6",
                support::REALM,
                support::CONFIDENTIAL,
                urlencode(REDIRECT),
            ))
            .to_request(),
    )
    .await;
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let binding = cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login");

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/login",
                support::REALM
            ))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .set_form([
                ("username", support::SUBJECT),
                ("password", support::PASSWORD),
            ])
            .to_request(),
    )
    .await;
    let landing = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .expect("a landing")
        .to_owned();
    landing
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .expect("a code")
        .to_owned()
}

/// Exchange a code, with or without a proof.
async fn exchanged(plane: &Plane, code: &str, proof: Option<&str>) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asked = test::TestRequest::post()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/token",
            support::REALM
        ))
        .set_form([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("client_id", support::CONFIDENTIAL),
            ("client_secret", support::CLIENT_SECRET),
        ]);
    if let Some(proof) = proof {
        asked = asked.insert_header(("dpop", proof.to_owned()));
    }
    let response = test::call_service(&app, asked.to_request()).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

/// Ask userinfo, with or without a proof.
async fn userinfo(plane: &Plane, access: &str, proof: Option<&str>) -> StatusCode {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asked = test::TestRequest::get()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/userinfo",
            support::REALM
        ))
        .insert_header(("authorization", format!("Bearer {access}")));
    if let Some(proof) = proof {
        asked = asked.insert_header(("dpop", proof.to_owned()));
    }
    test::call_service(&app, asked.to_request()).await.status()
}

/// A caller that proves a key gets a token naming it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_proven_key_is_named_by_the_token_it_earns() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("holder");
    let proof = key.proof("POST", &at("token"), None, "one", now());

    let (status, granted) = exchanged(&plane, &code_for(&plane).await, Some(&proof)).await;
    assert_eq!(status, StatusCode::OK, "{granted}");

    let access = granted["access_token"].as_str().expect("an access token");
    let claims = plane.claims_of(access).await;
    assert_eq!(
        claims["cnf"]["jkt"],
        key.thumbprint(),
        "the token names another key, or none: {claims}"
    );
}

/// The whole point: the token is worth nothing to whoever takes it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_bound_token_is_refused_to_a_caller_that_cannot_prove_the_key() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("holder");
    let proof = key.proof("POST", &at("token"), None, "one", now());
    let (_, granted) = exchanged(&plane, &code_for(&plane).await, Some(&proof)).await;
    let access = granted["access_token"].as_str().expect("an access token");

    // Presented as a bearer token, which is what a thief has.
    assert_eq!(
        userinfo(&plane, access, None).await,
        StatusCode::UNAUTHORIZED,
        "a bound token was read as a bearer token"
    );

    // And with a proof over another key, which is what a thief can make.
    let theirs = SigningKey::generate("thief");
    let forged = theirs.proof("GET", &at("userinfo"), Some(access), "two", now());
    assert_eq!(
        userinfo(&plane, access, Some(&forged)).await,
        StatusCode::UNAUTHORIZED,
        "a token was accepted on a key it is not bound to"
    );
}

/// And it is worth everything to the holder.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_holder_of_the_key_is_let_through() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("holder");
    let proof = key.proof("POST", &at("token"), None, "one", now());
    let (_, granted) = exchanged(&plane, &code_for(&plane).await, Some(&proof)).await;
    let access = granted["access_token"].as_str().expect("an access token");

    let held = key.proof("GET", &at("userinfo"), Some(access), "two", now());
    assert_eq!(userinfo(&plane, access, Some(&held)).await, StatusCode::OK);
}

/// A caller that proves nothing still gets what it always got.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_caller_that_proves_nothing_is_answered_as_before() {
    let plane = Plane::with_actions(&[]).await;
    let (status, granted) = exchanged(&plane, &code_for(&plane).await, None).await;
    assert_eq!(status, StatusCode::OK, "{granted}");

    let access = granted["access_token"].as_str().expect("an access token");
    assert_eq!(plane.claims_of(access).await["cnf"], Value::Null);
    assert_eq!(userinfo(&plane, access, None).await, StatusCode::OK);
}

/// §11.1: a proof read off the wire and sent again is the replay this exists
/// to stop.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_proof_is_accepted_once() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("holder");
    let proof = key.proof("POST", &at("token"), None, "same-one", now());

    let (status, _) = exchanged(&plane, &code_for(&plane).await, Some(&proof)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, told) = exchanged(&plane, &code_for(&plane).await, Some(&proof)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "invalid_dpop_proof", "{told}");
}

/// §4.3: a proof made for one call does not bind another.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_proof_made_for_another_call_binds_nothing() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("holder");

    for (named, proof) in [
        (
            "another address",
            key.proof("POST", &at("userinfo"), None, "a", now()),
        ),
        (
            "another method",
            key.proof("GET", &at("token"), None, "b", now()),
        ),
        (
            "an instant outside the window",
            key.proof("POST", &at("token"), None, "c", now() - 3_600),
        ),
    ] {
        let (status, told) = exchanged(&plane, &code_for(&plane).await, Some(&proof)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{named}: {told}");
        assert_eq!(told["error"], "invalid_dpop_proof", "{named}: {told}");
    }
}

/// §4.3: on a request carrying a token, the proof says which one.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_proof_that_names_another_token_binds_nothing() {
    let plane = Plane::with_actions(&[]).await;
    let key = SigningKey::generate("holder");
    let proof = key.proof("POST", &at("token"), None, "one", now());
    let (_, granted) = exchanged(&plane, &code_for(&plane).await, Some(&proof)).await;
    let access = granted["access_token"].as_str().expect("an access token");

    // The right key, the right call, and `ath` over something else.
    let misnamed = key.proof("GET", &at("userinfo"), Some("another-token"), "two", now());
    assert_eq!(
        userinfo(&plane, access, Some(&misnamed)).await,
        StatusCode::UNAUTHORIZED
    );

    // And with no `ath` at all.
    let silent = key.proof("GET", &at("userinfo"), None, "three", now());
    assert_eq!(
        userinfo(&plane, access, Some(&silent)).await,
        StatusCode::UNAUTHORIZED
    );
}

/// A plane that stands behind a proxy which terminates TLS and forwards what
/// the client presented.
fn behind_a_terminating_proxy(plane: &Plane) -> Mounted {
    Mounted {
        hops: config::proxying::Proxying::behind_terminating_peers(
            config::proxying::ProxyHeader::XForwardedFor,
            CERT_HEADER,
            vec![config::proxying::Peer::parse("10.0.0.0/8").expect("a peer")],
        ),
        ..mounted(plane)
    }
}

const CERT_HEADER: &str = "x-ssl-client-cert";
const A_CERTIFICATE: &str = "MIIBCgIBATANBgkqhkiG9w0BAQsFADAA";

/// Exchange a code from behind the proxy, saying what the caller presented and
/// which address the proxy dialled from.
async fn exchanged_behind(
    plane: &Plane,
    code: &str,
    certificate: Option<&str>,
    from: &str,
) -> (StatusCode, Value) {
    let app =
        test::init_service(App::new().configure(register(&behind_a_terminating_proxy(plane))))
            .await;
    let mut asked = test::TestRequest::post()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/token",
            support::REALM
        ))
        .peer_addr(format!("{from}:5000").parse().expect("an address"))
        .set_form([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("client_id", support::CONFIDENTIAL),
            ("client_secret", support::CLIENT_SECRET),
        ]);
    if let Some(certificate) = certificate {
        asked = asked.insert_header((CERT_HEADER, certificate.to_owned()));
    }
    let response = test::call_service(&app, asked.to_request()).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

async fn userinfo_behind(
    plane: &Plane,
    access: &str,
    certificate: Option<&str>,
    from: &str,
) -> StatusCode {
    let app =
        test::init_service(App::new().configure(register(&behind_a_terminating_proxy(plane))))
            .await;
    let mut asked = test::TestRequest::get()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/userinfo",
            support::REALM
        ))
        .peer_addr(format!("{from}:5000").parse().expect("an address"))
        .insert_header(("authorization", format!("Bearer {access}")));
    if let Some(certificate) = certificate {
        asked = asked.insert_header((CERT_HEADER, certificate.to_owned()));
    }
    test::call_service(&app, asked.to_request()).await.status()
}

/// A certificate a named proxy forwarded is what the token is bound to.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_forwarded_certificate_is_named_by_the_token_it_earns() {
    let plane = Plane::with_actions(&[]).await;
    let (status, granted) = exchanged_behind(
        &plane,
        &code_for(&plane).await,
        Some(A_CERTIFICATE),
        "10.1.2.3",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{granted}");

    let access = granted["access_token"].as_str().expect("an access token");
    let claims = plane.claims_of(access).await;
    assert!(
        claims["cnf"]["x5t#S256"].as_str().is_some(),
        "the token names no certificate: {claims}"
    );
}

/// The guard, seen from the protocol: a caller that writes the header itself
/// binds nothing, because it did not reach here through a named proxy.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_certificate_claimed_by_an_unnamed_caller_binds_nothing() {
    let plane = Plane::with_actions(&[]).await;
    let (status, granted) = exchanged_behind(
        &plane,
        &code_for(&plane).await,
        Some(A_CERTIFICATE),
        // Not inside 10.0.0.0/8, so this is the client writing its own header.
        "203.0.113.7",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{granted}");

    let access = granted["access_token"].as_str().expect("an access token");
    assert_eq!(
        plane.claims_of(access).await["cnf"],
        Value::Null,
        "a header written by the caller bound the token"
    );
}

/// A token bound to a certificate is worth nothing to whoever takes it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_certificate_bound_token_is_refused_to_another_certificate() {
    let plane = Plane::with_actions(&[]).await;
    let (_, granted) = exchanged_behind(
        &plane,
        &code_for(&plane).await,
        Some(A_CERTIFICATE),
        "10.1.2.3",
    )
    .await;
    let access = granted["access_token"].as_str().expect("an access token");

    // The holder, through the proxy.
    assert_eq!(
        userinfo_behind(&plane, access, Some(A_CERTIFICATE), "10.1.2.3").await,
        StatusCode::OK
    );

    // Somebody else's certificate.
    assert_eq!(
        userinfo_behind(
            &plane,
            access,
            Some("MIIBCgIBAjANBgkqhkiG9w0BAQsFADAA"),
            "10.1.2.3"
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "a token was accepted on a certificate it is not bound to"
    );

    // And none at all, which is what a thief presents.
    assert_eq!(
        userinfo_behind(&plane, access, None, "10.1.2.3").await,
        StatusCode::UNAUTHORIZED,
        "a bound token was read as a bearer token"
    );
}
