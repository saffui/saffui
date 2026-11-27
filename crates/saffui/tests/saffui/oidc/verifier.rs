//! A journey through the real binary: an administrator lets a confidential
//! application off binding its codes to a verifier. A code asked without a
//! challenge is spent without a verifier, a challenge sent is held to, and a
//! verifier for a code bound to none is refused.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use crypto::adapters::digest::ProviderDigester;
use crypto::adapters::open_provider;
use pgcore::APP_ROLE;
use pgcore::migrate::EMBEDDED;
use pgcore::testkit::TestDatabase;
use saffui_core::ports::crypto::Digester;
use serde_json::json;

use crate::support::http::{read_cookie, read_header, read_parameter};
use crate::support::{self, database, http, node, read_json};

const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");
const JSON: (&str, &str) = ("Content-Type", "application/json");
const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const TOKEN: &str = "/realms/acme/oauth2/token";

/// The realm `acme`, the person `ada`, and the confidential application
/// `portal`, created let off by an administrator. Returns the node and the
/// `Authorization` header of `portal`.
fn prepare_realm(database: &TestDatabase) -> (node::Node, String) {
    let created = support::saffui_command()
        .args(["bootstrap", "--tenant", "Acme", "--realm", "acme"])
        .args(["--client", "operator", "--admin"])
        .env("SAFFUI_DATABASE_URL", database.connection_string(APP_ROLE))
        .env("SAFFUI_PUBLIC_ORIGIN", node::PUBLIC_ORIGIN)
        .output()
        .expect("the saffui binary starts");
    assert_eq!(
        created.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let secret = String::from_utf8(created.stdout)
        .expect("text")
        .lines()
        .find_map(|line| line.strip_prefix("client_secret "))
        .expect("the secret is printed once")
        .to_owned();
    let node = node::Node::start(support::saffui_command(), database);
    let basic = format!("Basic {}", STANDARD.encode(format!("operator:{secret}")));
    let granted = http::send_request(
        node.data,
        "POST",
        TOKEN,
        &[("Authorization", basic.as_str()), FORM],
        "grant_type=client_credentials",
    )
    .expect("an answer");
    assert_eq!(granted.status, 200, "{}", granted.body);
    let bearer = format!(
        "Bearer {}",
        read_json(&granted.body)["access_token"]
            .as_str()
            .expect("a token")
    );
    let head = [JSON, ("Authorization", bearer.as_str())];
    let person = json!({ "username": "ada", "password": PASSWORD });
    let created = http::send_request(
        node.data,
        "POST",
        "/admin/v1/realms/acme/users",
        &head,
        &person.to_string(),
    )
    .expect("an answer");
    assert_eq!(created.status, 201, "{}", created.body);
    let application = json!({
        "client_id": "portal",
        "scopes": ["openid"],
        "redirect_uris": ["https://app.example.test/callback"],
        "require_pkce": false,
    });
    let created = http::send_request(
        node.data,
        "POST",
        "/admin/v1/realms/acme/clients",
        &head,
        &application.to_string(),
    )
    .expect("an answer");
    assert_eq!(created.status, 201, "{}", created.body);
    let created = read_json(&created.body);
    assert_eq!(
        created["client"]["require_pkce"], false,
        "the client is shown let off"
    );
    let secret = created["client_secret"].as_str().expect("a secret");
    let basic = format!("Basic {}", STANDARD.encode(format!("portal:{secret}")));
    (node, basic)
}

/// Signs `ada` in for `portal`, with `pkce` in the query, and returns the
/// code it is sent back with.
fn sign_in_for_code(node: &node::Node, pkce: &str) -> String {
    let path = format!(
        "/realms/acme/oauth2/authorize?response_type=code&client_id=portal\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&scope=openid&state=xyz{pkce}"
    );
    let sent = http::get(node.data, &path).expect("an answer");
    assert_eq!(sent.status, 303, "{}", sent.body);
    let login = read_header(&sent, "location").expect("a location");
    let request = read_parameter(login, "request").expect("a pending request");
    let flow = read_cookie(&sent, "saffui_flow_").expect("a flow cookie");
    let form = format!(
        "request={request}&username=ada&password={}",
        PASSWORD.replace(' ', "+")
    );
    let signed_in = http::send_request(
        node.data,
        "POST",
        "/realms/acme/login",
        &[
            FORM,
            ("Cookie", flow.as_str()),
            ("Origin", node::PUBLIC_ORIGIN),
        ],
        &form,
    )
    .expect("an answer");
    assert_eq!(signed_in.status, 303, "{}", signed_in.body);
    let back = read_header(&signed_in, "location").expect("a location");
    read_parameter(back, "code").expect("a code")
}

/// Exchanges `code` as `portal`, with `verifier` in the form.
fn exchange(node: &node::Node, basic: &str, code: &str, verifier: &str) -> http::Answer {
    let form = format!(
        "grant_type=authorization_code&code={code}\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback{verifier}"
    );
    http::send_request(
        node.data,
        "POST",
        TOKEN,
        &[("Authorization", basic), FORM],
        &form,
    )
    .expect("an answer")
}

#[test]
fn a_client_let_off_spends_a_code_without_a_verifier_and_is_held_to_a_challenge_it_sends() {
    let database = database::create_database(EMBEDDED);
    let (node, basic) = prepare_realm(&database);

    let code = sign_in_for_code(&node, "");
    let granted = exchange(&node, &basic, &code, "");
    assert_eq!(granted.status, 200, "{}", granted.body);
    assert!(
        read_json(&granted.body)["id_token"].is_string(),
        "{}",
        granted.body
    );

    let digester = ProviderDigester::new(open_provider().expect("a provider"));
    let challenge = URL_SAFE_NO_PAD.encode(digester.sha256(VERIFIER.as_bytes()));
    let bound = format!("&code_challenge={challenge}&code_challenge_method=S256");
    let code = sign_in_for_code(&node, &bound);
    let refused = exchange(&node, &basic, &code, "");
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert_eq!(
        read_json(&refused.body)["error"],
        "invalid_grant",
        "a challenge sent without its verifier"
    );
    let code = sign_in_for_code(&node, &bound);
    let granted = exchange(&node, &basic, &code, &format!("&code_verifier={VERIFIER}"));
    assert_eq!(granted.status, 200, "{}", granted.body);

    let code = sign_in_for_code(&node, "");
    let refused = exchange(&node, &basic, &code, &format!("&code_verifier={VERIFIER}"));
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert_eq!(
        read_json(&refused.body)["error"],
        "invalid_grant",
        "a verifier for a request that lost its challenge"
    );
}
