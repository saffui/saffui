//! The authorization endpoint in process, posted to: the request is carried
//! on to the endpoint in the browser as it was written, and nothing else
//! happens.

use actix_web::http::header::{CACHE_CONTROL, COOKIE};
use actix_web::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use saffui_core::app::App;
use saffui_core::testkit::fixtures::{
    Application, create_person, create_realm, register_application,
};
use saffui_core::testkit::memory::MemoryStorage;

use super::login::{Answer, Sent, get, post, send};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const ENDPOINT: &str = "/realms/acme/oauth2/authorize";

/// The realm `acme`, the person `ada`, and the public application `portal`.
async fn start() -> App {
    let (product, _storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    create_person(&product, scope, "ada", "correct horse battery").await;
    let portal = Application {
        client_id: "portal",
        redirect_uri: "https://app.example.test/callback",
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: false,
    };
    register_application(&product, scope, portal).await;
    product
}

/// Percent-encodes a value as a form does: every byte but letters and digits.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// Reads a query or a form back: each name and its value, decoded.
fn decode_pairs(text: &str) -> Vec<(String, String)> {
    let decode = |part: &str| {
        let mut bytes = Vec::new();
        let mut rest = part.bytes();
        while let Some(byte) = rest.next() {
            match byte {
                b'+' => bytes.push(b' '),
                b'%' => {
                    let digits = [rest.next().expect("a digit"), rest.next().expect("a digit")];
                    let digits = std::str::from_utf8(&digits).expect("hexadecimal");
                    bytes.push(u8::from_str_radix(digits, 16).expect("hexadecimal"));
                }
                other => bytes.push(other),
            }
        }
        String::from_utf8(bytes).expect("UTF-8")
    };
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').expect("a name and a value");
            (decode(name), decode(value))
        })
        .collect()
}

/// What `portal` asks, every value written as a form writes it.
fn write_form(product: &App, state: &str) -> String {
    let challenge = URL_SAFE_NO_PAD.encode(product.digester.sha256(VERIFIER.as_bytes()));
    format!(
        "response_type=code&client_id=portal&redirect_uri={}&scope=openid+profile\
         &state={}&nonce=&code_challenge={challenge}&code_challenge_method=S256\
         &extra=passed-over",
        encode("https://app.example.test/callback"),
        encode(state)
    )
}

/// Signs `ada` in through `portal`, and returns the cookie of her session.
async fn sign_in(product: &App) -> String {
    let carried = post(product, ENDPOINT, &[], &write_form(product, "s")).await;
    let sent = get(
        product,
        carried.location.as_deref().expect("the endpoint"),
        &[],
    )
    .await;
    let request = sent.read_location_parameter("request").expect("a request");
    let flow = sent
        .read_cookie("__Host-saffui_flow_")
        .expect("a flow cookie");
    let form = format!("request={request}&username=ada&password=correct+horse+battery");
    let signed_in = post(
        product,
        "/realms/acme/login",
        &[(COOKIE.as_str(), &flow)],
        &form,
    )
    .await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
    signed_in
        .read_cookie("__Host-saffui_session_acme=")
        .expect("a session")
}

#[actix_web::test]
async fn a_request_posted_reaches_the_endpoint_with_each_value_it_was_written_with() {
    let product = start().await;
    let state = "50% off+more=yes & é";
    let form = write_form(&product, state);

    let carried = post(&product, ENDPOINT, &[], &form).await;

    assert_eq!(carried.status, StatusCode::SEE_OTHER, "{}", carried.body);
    assert_eq!(
        carried.read_header(CACHE_CONTROL.as_str()),
        Some("no-store"),
        "the relay is kept by no cache"
    );
    assert!(carried.cookies.is_empty(), "{:?}", carried.cookies);
    let location = carried.location.expect("the endpoint");
    let (path, query) = location.split_once('?').expect("a query");
    assert_eq!(path, ENDPOINT, "the same path, and no other");
    let mut posted = decode_pairs(&form);
    posted.retain(|(name, _)| name != "extra");
    assert_eq!(
        decode_pairs(query),
        posted,
        "each value as posted, an empty one empty, in one order"
    );
    assert!(
        !query.contains("prompt=") && !query.contains("extra"),
        "a parameter not posted is not written: {query}"
    );
    let begun = get(&product, &location, &[]).await;
    assert_eq!(begun.status, StatusCode::SEE_OTHER, "{}", begun.body);
    assert!(
        begun
            .location
            .as_deref()
            .is_some_and(|login| login.starts_with("/realms/acme/login?request=")),
        "the endpoint read the request: {:?}",
        begun.location
    );
}

#[actix_web::test]
async fn a_request_posted_with_the_cookie_of_a_session_is_answered_as_one_without() {
    let product = start().await;
    let session = sign_in(&product).await;
    let form = write_form(&product, "xyz");

    let without = post(&product, ENDPOINT, &[], &form).await;
    let with = post(&product, ENDPOINT, &[(COOKIE.as_str(), &session)], &form).await;

    for answer in [&without, &with] {
        assert_eq!(answer.status, StatusCode::SEE_OTHER, "{}", answer.body);
        assert!(answer.cookies.is_empty(), "{:?}", answer.cookies);
    }
    assert_eq!(
        with.location, without.location,
        "the cookie changes nothing of where the request goes"
    );
    assert_eq!(
        with.body, without.body,
        "the cookie changes nothing of what is said"
    );
    let answered = get(
        &product,
        with.location.as_deref().expect("the endpoint"),
        &[(COOKIE.as_str(), &session)],
    )
    .await;
    assert!(
        answered.read_location_parameter("code").is_some(),
        "the navigation that follows carries the session: {:?}",
        answered.location
    );
}

#[actix_web::test]
async fn a_post_that_repeats_a_parameter_is_too_large_is_not_a_form_or_names_no_realm_is_refused() {
    let product = start().await;
    let refused = |answer: &Answer| {
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", answer.body);
        assert!(
            answer.location.is_none(),
            "a refusal sends the browser nowhere: {:?}",
            answer.location
        );
        assert!(answer.body.contains("invalid_request"), "{}", answer.body);
    };

    refused(&post(&product, ENDPOINT, &[], "state=one&state=two").await);
    let large = format!("state={}", "a".repeat(8 * 1024));
    refused(&post(&product, ENDPOINT, &[], &large).await);
    let json = send(
        &product,
        Sent {
            method: Method::POST,
            path: ENDPOINT,
            head: &[("content-type", "application/json")],
            form: None,
        },
    )
    .await;
    refused(&json);

    let misnamed = post(
        &product,
        "/realms/ACME/oauth2/authorize",
        &[],
        &write_form(&product, "xyz"),
    )
    .await;
    assert_eq!(misnamed.status, StatusCode::NOT_FOUND, "{}", misnamed.body);
    assert!(misnamed.location.is_none(), "no realm is written so");
}
