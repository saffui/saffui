//! Journeys through the real binary: a service gets a token, and anyone can
//! verify it with what the realm publishes.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use crypto::adapters::open_provider;
use crypto::adapters::sign::JoseSigner;
use pgcore::migrate::EMBEDDED;
use pgcore::testkit::TestDatabase;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE};
use saffui_core::ports::crypto::{SignatureAlgorithm, Signer};
use serde_json::Value;

#[path = "support/database.rs"]
mod database;
#[path = "support/http.rs"]
mod http;
#[path = "support/node.rs"]
mod node;
mod support;

const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");

/// Creates the realm `acme` with a client `billing`, and returns its secret.
fn bootstrap_with_client(database: &TestDatabase) -> String {
    let created = support::saffui_command()
        .args(["bootstrap", "--tenant", "Acme", "--realm", "acme"])
        .args([
            "--client",
            "billing",
            "--scope",
            "invoices:read",
            "--scope",
            "invoices:write",
        ])
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
    let stdout = String::from_utf8(created.stdout).expect("text");
    assert!(stdout.contains("client billing\n"), "{stdout}");
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("client_secret "))
        .expect("the secret is printed once")
        .to_owned()
}

fn ask_for_token(node: &node::Node, secret: &str, form: &str) -> http::Answer {
    let basic = format!("Basic {}", STANDARD.encode(format!("billing:{secret}")));
    http::send_request(
        node.data,
        "POST",
        "/realms/acme/oauth2/token",
        &[("Authorization", &basic), FORM],
        form,
    )
    .expect("an answer")
}

fn read_json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| panic!("not JSON: {text:?}"))
}

fn decode_part(part: &str) -> Value {
    read_json(&String::from_utf8(URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("text"))
}

#[test]
fn a_service_gets_a_token_that_the_published_key_verifies() {
    let database = database::create_database(EMBEDDED);
    let secret = bootstrap_with_client(&database);
    let node = node::Node::start(support::saffui_command(), &database);

    let answer = ask_for_token(
        &node,
        &secret,
        "grant_type=client_credentials&scope=invoices:read",
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert!(
        answer
            .head
            .to_lowercase()
            .contains("cache-control: no-store")
    );
    let granted = read_json(&answer.body);
    assert_eq!(granted["token_type"], "Bearer");
    assert_eq!(granted["scope"], "invoices:read");
    let token = granted["access_token"].as_str().expect("a token");

    // What any resource server does: fetch the keys, pick the one the token names, verify.
    let key_set = read_json(
        &http::get(node.data, "/realms/acme/oauth2/jwks")
            .expect("an answer")
            .body,
    );
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header = decode_part(parts[0]);
    let key = key_set["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|key| key["kid"] == header["kid"]))
        .expect("the key the token names is published");
    assert!(
        key.get("d").is_none(),
        "no private member is ever published: {key}"
    );
    let signed = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).expect("base64url");
    assert_eq!(
        JoseSigner::new(open_provider().expect("a provider")).verify(
            SignatureAlgorithm::Es256,
            key,
            signed.as_bytes(),
            &signature
        ),
        Ok(true),
        "the published key verifies the token"
    );

    let claims = decode_part(parts[1]);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(claims["iss"], "http://localhost:8080/realms/acme");
    assert_eq!(claims["sub"], "billing");
    assert_eq!(claims["client_id"], "billing");
    assert_eq!(claims["scope"], "invoices:read");
    assert_eq!(
        claims["exp"]
            .as_i64()
            .zip(claims["iat"].as_i64())
            .map(|(exp, iat)| exp - iat),
        Some(300)
    );

    let discovery = read_json(
        &http::get(node.data, "/realms/acme/.well-known/openid-configuration")
            .expect("an answer")
            .body,
    );
    assert_eq!(
        discovery["token_endpoint"],
        "http://localhost:8080/realms/acme/oauth2/token"
    );
    assert_eq!(
        discovery["jwks_uri"],
        "http://localhost:8080/realms/acme/oauth2/jwks"
    );
}

#[test]
fn a_wrong_secret_gets_no_token_and_an_issued_token_is_in_the_audit_chain() {
    let database = database::create_database(EMBEDDED);
    let secret = bootstrap_with_client(&database);
    let node = node::Node::start(support::saffui_command(), &database);

    let refused = ask_for_token(&node, "not-the-secret", "grant_type=client_credentials");
    assert_eq!(refused.status, 401);
    let on_ops = http::send_request(node.ops, "POST", "/realms/acme/oauth2/token", &[FORM], "")
        .expect("an answer");
    assert_eq!(on_ops.status, 404, "the operations plane grants nothing");
    assert_eq!(read_json(&refused.body)["error"], "invalid_client");
    assert_eq!(
        ask_for_token(&node, &secret, "grant_type=client_credentials").status,
        200
    );

    let kinds: Vec<String> = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(async {
            let client = database
                .plan(MAINTENANCE_ROLE)
                .connect_directly()
                .await
                .expect("a connection");
            client
                .query("SELECT kind FROM audit_events ORDER BY seq", &[])
                .await
                .expect("the chain")
                .iter()
                .map(|row| row.get(0))
                .collect()
        });
    assert_eq!(
        kinds,
        [
            "realm.created",
            "key.created",
            "client.created",
            "token.issued"
        ],
        "one event per change, and none for the refusal"
    );
}

#[test]
fn a_node_given_another_root_key_cannot_sign_and_says_nothing_of_why() {
    let database = database::create_database(EMBEDDED);
    let secret = bootstrap_with_client(&database);
    let mut command = support::saffui_command();
    command.env("ROOT_KEY_OF_THE_JOURNEYS", STANDARD.encode([9_u8; 32]));
    let node = node::Node::start(command, &database);

    let answer = ask_for_token(&node, &secret, "grant_type=client_credentials");

    assert_eq!(answer.status, 500);
    assert_eq!(
        read_json(&answer.body),
        serde_json::json!({
            "error": "server_error",
            "error_description": "The request could not be completed.",
        })
    );
}

#[test]
fn bootstrap_without_a_root_key_exits_with_2_and_names_the_setting() {
    let database = database::create_database(EMBEDDED);

    let refused = support::saffui_command()
        .args(["bootstrap", "--tenant", "Acme", "--realm", "acme"])
        .env("SAFFUI_DATABASE_URL", database.connection_string(APP_ROLE))
        .env("SAFFUI_PUBLIC_ORIGIN", node::PUBLIC_ORIGIN)
        .env_remove("SAFFUI_ROOT_KEY")
        .output()
        .expect("the saffui binary starts");

    assert_eq!(refused.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("SAFFUI_ROOT_KEY is required"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}
