//! How the answers of the authorization endpoint leave: in a query, after a
//! `#`, or on a page that posts them, from each endpoint that answers.

use actix_web::http::Method;
use actix_web::http::StatusCode;
use actix_web::http::header::{COOKIE, ORIGIN};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use saffui_core::authz::capability::Capability;
use saffui_core::clients::{Client, ClientAuthMethod, KeptProof};
use saffui_core::ids::mint_id;
use saffui_core::oidc::response::ResponseType;
use saffui_core::tenancy::RealmScope;
use saffui_core::testkit::fixtures::{
    Application, create_administrator, create_person, create_realm, register_answered_application,
};
use saffui_core::testkit::memory::MemoryStorage;
use serde_json::json;

use crate::admin::call;
use crate::login::{Answer, get, post};

const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const SCRIPT: &str = "document.forms[0].submit();";

/// The realm `acme`, the person `ada`, `spa` handed back each of the six,
/// and `partner`, which asks each person first.
async fn start() -> saffui_core::app::App {
    let (product, _storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    create_person(&product, scope, "ada", PASSWORD).await;
    for (client_id, requires_consent) in [("spa", false), ("partner", true)] {
        let application = Application {
            client_id,
            redirect_uri: "https://app.example.test/callback",
            post_logout_redirect_uri: None,
            public: true,
            requires_consent,
        };
        register_answered_application(&product, scope, application, &ResponseType::ALL).await;
    }
    product
}

fn write_authorize_path(
    product: &saffui_core::app::App,
    client_id: &str,
    response_type: &str,
    more: &str,
) -> String {
    let challenge = URL_SAFE_NO_PAD.encode(product.digester.sha256(VERIFIER.as_bytes()));
    format!(
        "/realms/acme/oauth2/authorize?response_type={response_type}&client_id={client_id}\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&scope=openid%20email\
         &state=xyz&nonce=n-1&code_challenge={challenge}&code_challenge_method=S256{more}"
    )
}

/// Signs `ada` in on the hosted page for the request at `authorize`, and
/// returns the answer of the page and the cookie of its flow.
async fn sign_in(product: &saffui_core::app::App, authorize: &str) -> (Answer, String) {
    let sent = get(product, authorize, &[]).await;
    assert_eq!(sent.status, StatusCode::SEE_OTHER, "{}", sent.body);
    let request = sent
        .read_location_parameter("request")
        .expect("a pending request");
    let flow = sent
        .read_cookie("__Host-saffui_flow_")
        .expect("a flow cookie");
    let form = format!("request={request}&username=ada&password=correct+horse+battery");
    let answered = post(
        product,
        "/realms/acme/login",
        &[
            (COOKIE.as_str(), &flow),
            (ORIGIN.as_str(), "https://id.example.test"),
        ],
        &form,
    )
    .await;
    (answered, flow)
}

/// The value of a hidden field of a posted answer.
fn read_field(page: &str, name: &str) -> Option<String> {
    let opening = format!(r#"<input type="hidden" name="{name}" value=""#);
    page.split_once(&opening)
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(value, _)| value.to_owned())
}

fn check_posted_page(answer: &Answer, product: &saffui_core::app::App) {
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.location, None);
    assert_eq!(answer.read_header("cache-control"), Some("no-store"));
    let hash = STANDARD.encode(product.digester.sha256(SCRIPT.as_bytes()));
    assert_eq!(
        answer.read_header("content-security-policy"),
        Some(
            format!(
                "default-src 'none'; script-src 'sha256-{hash}'; \
                 form-action https://app.example.test/callback; \
                 frame-ancestors 'none'; base-uri 'none'"
            )
            .as_str()
        ),
        "the page posts to the address it answers, and nowhere else"
    );
    // The headers of every answer stay, but the post names its origin.
    assert_eq!(
        answer.read_header("x-content-type-options"),
        Some("nosniff")
    );
    assert_eq!(answer.read_header("x-frame-options"), Some("DENY"));
    assert_eq!(answer.read_header("referrer-policy"), Some("strict-origin"));
    assert!(
        answer
            .body
            .contains(r#"<form method="post" action="https://app.example.test/callback">"#),
        "{}",
        answer.body
    );
}

#[actix_web::test]
async fn a_person_who_signs_in_for_a_posted_answer_gets_the_page_that_posts_it_and_her_session() {
    let product = start().await;
    let authorize = write_authorize_path(
        &product,
        "spa",
        "code%20id_token",
        "&response_mode=form_post",
    );

    let (answered, _) = sign_in(&product, &authorize).await;

    check_posted_page(&answered, &product);
    for name in ["code", "id_token"] {
        assert!(
            read_field(&answered.body, name).is_some(),
            "{name}: {}",
            answered.body
        );
    }
    assert_eq!(read_field(&answered.body, "state").as_deref(), Some("xyz"));
    assert_eq!(
        read_field(&answered.body, "iss").as_deref(),
        Some("https://id.example.test/realms/acme")
    );
    assert!(
        answered
            .read_cookie("__Host-saffui_session_acme=")
            .is_some(),
        "the session leaves with the page: {:?}",
        answered.cookies
    );
}

#[actix_web::test]
async fn a_session_answers_after_the_hash_with_a_redirection() {
    let product = start().await;
    let (signed_in, _) =
        sign_in(&product, &write_authorize_path(&product, "spa", "code", "")).await;
    let session = signed_in
        .read_cookie("__Host-saffui_session_acme=")
        .expect("a session");

    let answered = get(
        &product,
        &write_authorize_path(&product, "spa", "id_token%20token", ""),
        &[(COOKIE.as_str(), &session)],
    )
    .await;

    assert_eq!(answered.status, StatusCode::SEE_OTHER);
    let location = answered.location.expect("a location");
    assert!(
        location.starts_with("https://app.example.test/callback#id_token="),
        "{location}"
    );
    assert!(location.contains("&access_token="), "{location}");
    assert!(location.contains("&state=xyz&iss="), "{location}");
}

#[actix_web::test]
async fn a_refusal_is_posted_where_the_answer_would_have_been() {
    let product = start().await;
    let authorize = write_authorize_path(
        &product,
        "spa",
        "id_token",
        "&response_mode=form_post&prompt=none",
    );

    let refused = get(&product, &authorize, &[]).await;

    check_posted_page(&refused, &product);
    assert_eq!(
        read_field(&refused.body, "error").as_deref(),
        Some("login_required")
    );
    assert_eq!(read_field(&refused.body, "state").as_deref(), Some("xyz"));
}

#[actix_web::test]
async fn an_allowed_client_is_posted_its_answer_from_the_consent_page() {
    let product = start().await;
    let authorize = write_authorize_path(
        &product,
        "partner",
        "id_token%20token",
        "&response_mode=form_post",
    );
    let (signed_in, flow) = sign_in(&product, &authorize).await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
    let consent = signed_in.location.clone().expect("the consent page");
    let session = signed_in
        .read_cookie("__Host-saffui_session_acme=")
        .expect("a session");
    let cookies = format!("{flow}; {session}");
    let page = get(&product, &consent, &[(COOKIE.as_str(), &cookies)]).await;
    let shown = read_field(&page.body, "shown").expect("what the page showed");
    let request = read_field(&page.body, "request").expect("the request");

    let answered = post(
        &product,
        "/realms/acme/consent",
        &[
            (COOKIE.as_str(), &cookies),
            (ORIGIN.as_str(), "https://id.example.test"),
        ],
        &format!("request={request}&decision=allow&shown={shown}"),
    )
    .await;

    check_posted_page(&answered, &product);
    assert!(read_field(&answered.body, "access_token").is_some());
    assert!(
        answered
            .cookies
            .iter()
            .any(|cookie| cookie.starts_with("__Host-saffui_flow_") && cookie.contains("Max-Age=0")),
        "the flow is over: {:?}",
        answered.cookies
    );
}

#[actix_web::test]
async fn an_administrator_declares_what_a_client_is_handed_back_and_reads_it() {
    let (product, _storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    let token = create_administrator(
        &product,
        "acme",
        scope,
        "operator",
        &[Capability::ClientWrite],
    )
    .await;
    let create = |client_id: &str, response_types: serde_json::Value| {
        json!({
            "client_id": client_id,
            "scopes": ["openid"],
            "redirect_uris": ["https://app.example.test/callback"],
            "public": true,
            "response_types": response_types,
        })
        .to_string()
    };
    let path = "/admin/v1/realms/acme/clients";

    let created = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some(&create("spa", json!(["token id_token", "code"]))),
    )
    .await;
    let plain = call(
        &product,
        Method::POST,
        path,
        Some(&token),
        Some(&create("plain", json!([]))),
    )
    .await;

    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(
        created.body["client"]["response_types"],
        json!(["id_token token", "code"]),
        "each is written in the one spelling"
    );
    assert_eq!(plain.body["client"]["response_types"], json!(["code"]));
    for refused in [
        json!(["token"]),
        json!(["code", "code"]),
        json!(["code none"]),
    ] {
        let answer = call(
            &product,
            Method::POST,
            path,
            Some(&token),
            Some(&create("refused", refused.clone())),
        )
        .await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(
            answer.body["code"], "client.response_types_invalid",
            "{refused}: {}",
            answer.body
        );
    }
}

/// Keeps `relay`, sent back to `redirect_uris`, as a hand in the database
/// would: an address kept before a rule is served as it is kept.
async fn plant_relay(product: &saffui_core::app::App, scope: RealmScope, redirect_uris: &[&str]) {
    let relay = Client {
        id: mint_id(product).expect("an identifier"),
        client_id: "relay".to_owned(),
        name: "Relay".to_owned(),
        auth_method: ClientAuthMethod::None,
        auth_signing_alg: None,
        allows_client_credentials: false,
        allows_authorization_code: true,
        redirect_uris: redirect_uris.iter().map(|uri| (*uri).to_owned()).collect(),
        response_types: vec![ResponseType::Code],
        post_logout_redirect_uris: Vec::new(),
        requires_consent: false,
        scopes: vec!["openid".to_owned()],
        capabilities: Vec::new(),
        id_token_signed_response_alg: None,
        enabled: true,
        self_registered: false,
        created_at: product.now(),
    };
    let nothing = KeptProof {
        secret_digest: None,
        sealed_secret: None,
        jwks: None,
    };
    let mut work = product.storage.begin(scope).await.expect("a unit of work");
    work.insert_client(&relay, &nothing)
        .await
        .expect("a client");
    work.commit().await.expect("a commit");
}

#[actix_web::test]
async fn no_page_that_posts_is_served_to_send_a_form_to_this_deployment_itself() {
    let product = start().await;
    let beta = create_realm(&product, "beta").await;
    plant_relay(
        &product,
        beta,
        &[
            "https://id.example.test/realms/acme/oauth2/logout",
            "https://id.example.test:8443/realms/acme/oauth2/logout",
        ],
    )
    .await;
    let challenge = URL_SAFE_NO_PAD.encode(product.digester.sha256(VERIFIER.as_bytes()));

    for written in [
        "https%3A%2F%2Fid.example.test%2Frealms%2Facme%2Foauth2%2Flogout",
        "https%3A%2F%2Fid.example.test%3A8443%2Frealms%2Facme%2Foauth2%2Flogout",
    ] {
        let asked = format!(
            "/realms/beta/oauth2/authorize?response_type=code&client_id=relay\
             &redirect_uri={written}&scope=openid&state=xyz&response_mode=form_post"
        );
        for authorize in [
            asked.clone(),
            format!("{asked}&code_challenge={challenge}&code_challenge_method=S256"),
        ] {
            let refused = get(&product, &authorize, &[]).await;

            assert_eq!(
                refused.status,
                StatusCode::BAD_REQUEST,
                "shown to the person, and posted nowhere: {}",
                refused.body
            );
            assert_eq!(refused.location, None);
            assert!(
                refused
                    .body
                    .contains("An answer is never posted to this deployment itself."),
                "the person reads why: {}",
                refused.body
            );
            assert!(!refused.body.contains("oauth2/logout"), "{}", refused.body);
            assert!(
                refused
                    .read_header("content-security-policy")
                    .is_none_or(|policy| !policy.contains("form-action https://id.example.test")),
                "{:?}",
                refused.head
            );
        }
    }
}
