#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use crypto::jose::jwk::KeyPair;
use crypto::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
use crypto::jose::jwk::alg::ed::{EdCurve, EdKeyPair};
use crypto::jose::jwk::alg::rsa::RsaKeyPair;
use crypto::provider::{PrivateKey, PublicKey};
use crypto::x509::{Issuance, issue_authority_certificate, issue_certificate};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};

const REALM: &str = support::REALM;
/// Seconds since the epoch: 2026-09-14, and 2036-09-14.
const FROM: i64 = 1_789_372_800;
const UNTIL: i64 = 2_104_992_000;

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

/// A certificate for `key`, issued by itself, PEM encoded.
fn certificate(key: &RsaKeyPair, name: &str, serial: u8, authority: bool, until: i64) -> String {
    let issuance = Issuance {
        subject_key: &PublicKey::from_der(key.to_der_public_key()),
        subject_name: name,
        issuer_key: &PrivateKey::from_der(key.to_der_private_key()),
        issuer_name: name,
        serial: &[serial],
        not_before: FROM,
        not_after: until,
    };
    let der = if authority {
        issue_authority_certificate(&issuance)
    } else {
        issue_certificate(&issuance)
    }
    .expect("a certificate issued by the crypto crate");
    support::pem_certificate(&der)
}

/// An authority's certificate for `subject`'s key, issued under `issuer`'s
/// and named like it, PEM encoded: how a key the crate does not sign with is
/// certified here.
fn authority_holding(subject: &dyn KeyPair, issuer: &RsaKeyPair) -> String {
    let der = issue_authority_certificate(&Issuance {
        subject_key: &PublicKey::from_der(subject.to_der_public_key()),
        subject_name: "Authority",
        issuer_key: &PrivateKey::from_der(issuer.to_der_private_key()),
        issuer_name: "Authority",
        serial: &[1],
        not_before: FROM,
        not_after: UNTIL,
    })
    .expect("a certificate issued by the crypto crate");
    support::pem_certificate(&der)
}

fn deposit_body(pem: &str) -> Value {
    json!({ "role": "credential-issuer", "certificate": pem })
}

/// An authority is deposited, listed with what identifies it, refused a
/// second time for the same purpose, and withdrawn once.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_authority_is_deposited_listed_and_withdrawn() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let anchors = format!("/admin/realms/{REALM}/trust-anchors");

    let (status, listed) = asked(&plane, Method::GET, &anchors, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed, json!({ "running": false, "items": [] }));

    let key = RsaKeyPair::generate(2048).expect("an RSA key");
    let pem = certificate(&key, "Credential Authority", 1, true, UNTIL);
    let (status, made) = asked(
        &plane,
        Method::POST,
        &anchors,
        &bearer,
        Some(deposit_body(&pem)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    assert_eq!(made["role"], "credential-issuer", "{made}");
    assert_eq!(made["subject"], "CN=Credential Authority", "{made}");
    assert!(made["key_identifier"].is_string(), "{made}");
    assert_eq!(
        made["fingerprint"].as_str().map(str::len),
        Some(64),
        "{made}"
    );
    let der = crypto::x509::read_pem_certificates(pem.as_bytes()).expect("the certificate");
    assert_eq!(made["certificate"], data_encoding::BASE64.encode(&der[0]));

    let (_, listed) = asked(&plane, Method::GET, &anchors, &bearer, None).await;
    assert_eq!(
        listed["items"].as_array().map(Vec::len),
        Some(1),
        "{listed}"
    );
    assert_eq!(listed["items"][0]["id"], made["id"], "{listed}");

    let (status, told) = asked(
        &plane,
        Method::POST,
        &anchors,
        &bearer,
        Some(deposit_body(&pem)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(
        told["error_code"], "realm.trust_anchor.already_deposited",
        "{told}"
    );

    let one = format!("{anchors}/{}", made["id"].as_str().expect("an id"));
    let (status, told) = asked(&plane, Method::DELETE, &one, &bearer, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (status, told) = asked(&plane, Method::DELETE, &one, &bearer, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "realm.trust_anchor.not_found", "{told}");
    let (_, listed) = asked(&plane, Method::GET, &anchors, &bearer, None).await;
    assert_eq!(listed["items"], json!([]), "{listed}");
}

/// Reading the authorities is the realm's read action; depositing and
/// withdrawing one is its write action.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_reader_lists_the_authorities_and_changes_none() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead]).await;
    let bearer = plane.token(&support::claims());
    let anchors = format!("/admin/realms/{REALM}/trust-anchors");
    let key = RsaKeyPair::generate(2048).expect("an RSA key");
    let pem = certificate(&key, "Authority", 1, true, UNTIL);

    let (status, listed) = asked(&plane, Method::GET, &anchors, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let (status, told) = asked(
        &plane,
        Method::POST,
        &anchors,
        &bearer,
        Some(deposit_body(&pem)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{told}");
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{anchors}/any"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{told}");
}

/// What could not serve as an authority is refused in words: no certificate,
/// several, a text too long, a leaf, a weak key, an expired one, an unknown
/// purpose.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_could_not_serve_as_an_authority_is_refused_in_words() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let anchors = format!("/admin/realms/{REALM}/trust-anchors");
    let key = RsaKeyPair::generate(2048).expect("an RSA key");
    let weak = RsaKeyPair::generate(1024).expect("an RSA key");
    let authority = certificate(&key, "Authority", 1, true, UNTIL);

    for (pem, said) in [
        ("not a certificate".to_owned(), "one certificate"),
        (
            format!(
                "{authority}{}",
                certificate(&key, "Another", 2, true, UNTIL)
            ),
            "one certificate",
        ),
        (
            format!("{authority}{}", " ".repeat(16 * 1024)),
            "at most 16 KiB",
        ),
        (
            certificate(&key, "Leaf", 3, false, UNTIL),
            "not a certification authority",
        ),
        (certificate(&weak, "Weak", 4, true, UNTIL), "2048 bits"),
        (
            certificate(&key, "Expired", 5, true, FROM + 86_400),
            "expired",
        ),
    ] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &anchors,
            &bearer,
            Some(deposit_body(&pem)),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{said}: {told}");
        assert!(
            told["message"]
                .as_str()
                .is_some_and(|held| held.contains(said)),
            "{said}: refused in other words: {told}"
        );
    }

    let (status, told) = asked(
        &plane,
        Method::POST,
        &anchors,
        &bearer,
        Some(json!({ "role": "wallet-provider", "certificate": authority })),
    )
    .await;
    assert!(
        status.is_client_error(),
        "an unknown purpose was taken: {told}"
    );
    let (_, listed) = asked(&plane, Method::GET, &anchors, &bearer, None).await;
    assert_eq!(
        listed["items"],
        json!([]),
        "a refused deposit was kept: {listed}"
    );
}

/// An authority holds a key this build verifies: one on a curve JOSE names is
/// trusted, one on another curve or of another kind is refused in words.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_authority_holds_a_key_this_build_verifies() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let anchors = format!("/admin/realms/{REALM}/trust-anchors");
    let issuer = RsaKeyPair::generate(2048).expect("an RSA key");
    let unnamed = EcKeyPair::generate(EcCurve::Secp256k1).expect("a secp256k1 key");
    let edwards = EdKeyPair::generate(EdCurve::Ed25519).expect("an Ed25519 key");
    let named = EcKeyPair::generate(EcCurve::P256).expect("a P-256 key");

    for (subject, said) in [
        (
            &unnamed as &dyn KeyPair,
            "a curve other than P-256, P-384 or P-521",
        ),
        (&edwards, "a key of a kind not verified here"),
    ] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &anchors,
            &bearer,
            Some(deposit_body(&authority_holding(subject, &issuer))),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{said}: {told}");
        assert!(
            told["message"]
                .as_str()
                .is_some_and(|held| held.contains(said)),
            "{said}: refused in other words: {told}"
        );
    }
    let (status, made) = asked(
        &plane,
        Method::POST,
        &anchors,
        &bearer,
        Some(deposit_body(&authority_holding(&named, &issuer))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
}

/// A realm trusts at most fifty authorities for one purpose, which bounds
/// what one verification walks.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_trusts_a_bounded_number_of_authorities() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let anchors = format!("/admin/realms/{REALM}/trust-anchors");
    let key = RsaKeyPair::generate(2048).expect("an RSA key");
    for serial in 1..=50 {
        let pem = certificate(&key, "Authority", serial, true, UNTIL);
        let (status, told) = asked(
            &plane,
            Method::POST,
            &anchors,
            &bearer,
            Some(deposit_body(&pem)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{serial}: {told}");
    }
    let pem = certificate(&key, "Authority", 51, true, UNTIL);
    let (status, told) = asked(
        &plane,
        Method::POST,
        &anchors,
        &bearer,
        Some(deposit_body(&pem)),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|held| held.contains("at most 50")),
        "refused in other words: {told}"
    );
}

/// Two deposits racing one below the bound leave the realm at it: the second
/// counts once the first has landed, and is refused.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn deposits_racing_at_the_bound_do_not_pass_it() {
    use models::entities::trust_anchors::TrustAnchorRole;
    use services::admin::trust_anchors::{self, MAX_ANCHORS, Undepositable};
    use store::tenancy::TenantContext;

    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let provider = support::provider();
    let context = TenantContext::new(support::TENANT, REALM);
    let key = RsaKeyPair::generate(2048).expect("an RSA key");
    let now = chrono::Utc::now();
    let deposit = |serial: u8| certificate(&key, "Authority", serial, true, UNTIL);

    let standing = plane.scoped(&context).await;
    for serial in 1..u8::try_from(MAX_ANCHORS).expect("a small bound") {
        trust_anchors::deposit(
            &standing,
            &provider,
            TrustAnchorRole::CredentialIssuer,
            &deposit(serial),
            "the-test",
            now,
        )
        .await
        .expect("an authority below the bound");
    }
    standing.commit().await.expect("the authorities stand");

    let rival = plane.scoped(&context).await;
    trust_anchors::deposit(
        &rival,
        &provider,
        TrustAnchorRole::CredentialIssuer,
        &deposit(50),
        "a-rival",
        now,
    )
    .await
    .expect("the last one the bound allows, not yet committed");
    let late = plane.scoped(&context).await;
    let last = deposit(51);
    let (refused, ()) = tokio::join!(
        trust_anchors::deposit(
            &late,
            &provider,
            TrustAnchorRole::CredentialIssuer,
            &last,
            "a-late-caller",
            now,
        ),
        support::commit_once_a_write_queues_behind(rival),
    );
    assert_eq!(refused.map(|_| ()), Err(Undepositable::TooMany));
}
