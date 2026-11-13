//! Journeys through the real binary: an operator turns the keys of its
//! realm over, and what a retired key signed stands until it is removed; and
//! the operator of the deployment gives a realm made before its keys of RS256
//! that key, and one of its clients the right to turn keys over.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use crypto::adapters::open_provider;
use crypto::adapters::sign::JoseSigner;
use std::process::{Command, Output};

use pgcore::migrate::EMBEDDED;
use pgcore::testkit::TestDatabase;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE};
use saffui_core::ports::crypto::{SignatureAlgorithm, Signer};
use serde_json::{Value, json};

#[path = "support/database.rs"]
mod database;
#[path = "support/http.rs"]
mod http;
#[path = "support/jwk.rs"]
mod jwk;
#[path = "support/node.rs"]
mod node;
mod support;

const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");
const JSON: (&str, &str) = ("Content-Type", "application/json");
const KEYS: &str = "/admin/v1/realms/acme/keys";

/// What `bootstrap` tells of the realm `acme` and its administrator `operator`.
struct Bootstrapped {
    tenant: String,
    realm: String,
    secret: String,
}

/// Creates the realm `acme` with an administrator `operator`.
fn bootstrap_with_administrator(database: &TestDatabase) -> Bootstrapped {
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
    let told = String::from_utf8(created.stdout).expect("text");
    let read = |what: &str| {
        told.lines()
            .find_map(|line| line.strip_prefix(what))
            .expect("told once")
            .to_owned()
    };
    Bootstrapped {
        tenant: read("tenant "),
        realm: read("realm "),
        secret: read("client_secret "),
    }
}

fn read_json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| panic!("not JSON: {text:?}"))
}

fn get_token(node: &node::Node, secret: &str) -> String {
    let basic = format!("Basic {}", STANDARD.encode(format!("operator:{secret}")));
    let answer = http::send_request(
        node.data,
        "POST",
        "/realms/acme/oauth2/token",
        &[("Authorization", &basic), FORM],
        "grant_type=client_credentials",
    )
    .expect("an answer");
    assert_eq!(answer.status, 200, "{}", answer.body);
    read_json(&answer.body)["access_token"]
        .as_str()
        .expect("a token")
        .to_owned()
}

fn call(node: &node::Node, method: &str, path: &str, token: &str, body: &str) -> http::Answer {
    let bearer = format!("Bearer {token}");
    http::send_request(
        node.data,
        method,
        path,
        &[JSON, ("Authorization", &bearer)],
        body,
    )
    .expect("an answer")
}

fn read_header(token: &str) -> Value {
    let part = token.split('.').next().expect("a header");
    read_json(&String::from_utf8(URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("text"))
}

/// Verifies `token` with the key the realm publishes under its `kid`, in the
/// algorithm that key was published for: never the one the header names.
fn verify_with_published_keys(node: &node::Node, token: &str) -> bool {
    let published = read_json(
        &http::get(node.data, "/realms/acme/oauth2/jwks")
            .expect("an answer")
            .body,
    );
    let header = read_header(token);
    let Some(key) = published["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|key| key["kid"] == header["kid"]))
    else {
        return false;
    };
    let algorithm = key["alg"]
        .as_str()
        .and_then(SignatureAlgorithm::parse)
        .expect("a published algorithm");
    let (signed, signature) = token.rsplit_once('.').expect("three parts");
    let signature = URL_SAFE_NO_PAD.decode(signature).expect("base64url");
    JoseSigner::new(open_provider().expect("a provider")).verify(
        algorithm,
        key,
        signed.as_bytes(),
        &signature,
    ) == Ok(true)
}

#[test]
fn an_operator_turns_keys_over_and_what_a_retired_key_signed_stands_until_it_goes() {
    let database = database::create_database(EMBEDDED);
    let secret = bootstrap_with_administrator(&database).secret;
    let node = node::Node::start(support::saffui_command(), &database);
    let before = get_token(&node, &secret);
    let first = read_header(&before)["kid"]
        .as_str()
        .expect("a kid")
        .to_owned();
    assert!(verify_with_published_keys(&node, &before));

    // An RSA key is made by the node while it serves, then an ES256 one.
    let rsa = call(&node, "POST", KEYS, &before, r#"{"alg":"RS256"}"#);
    assert_eq!(rsa.status, 201, "{}", rsa.body);
    let rsa = read_json(&rsa.body);
    assert_eq!(rsa["public_jwk"]["kty"], "RSA");
    assert!(jwk::holds_public_members_only(&rsa["public_jwk"]), "{rsa}");
    let turned = call(&node, "POST", KEYS, &before, r#"{"alg":"ES256"}"#);
    assert_eq!(turned.status, 201, "{}", turned.body);
    let new = read_json(&turned.body)["kid"]
        .as_str()
        .expect("a kid")
        .to_owned();

    let listed = read_json(&call(&node, "GET", KEYS, &before, "").body);
    let mut statuses: Vec<(String, String)> = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| {
            let read = |name: &str| item[name].as_str().expect(name).to_owned();
            (read("alg"), read("status"))
        })
        .collect();
    statuses.sort();
    let pair = |alg: &str, status: &str| (alg.to_owned(), status.to_owned());
    assert_eq!(
        statuses,
        [
            pair("ES256", "active"),
            pair("ES256", "retired"),
            pair("RS256", "active"),
            pair("RS256", "retired"),
        ]
    );
    let read_realm = |token: &str| call(&node, "GET", "/admin/v1/realms/acme", token, "");
    assert_eq!(
        read_realm(&before).status,
        200,
        "the retired key still verifies"
    );
    assert!(verify_with_published_keys(&node, &before));
    let after = get_token(&node, &secret);
    assert_eq!(
        read_header(&after)["kid"],
        new.as_str(),
        "the new key signs"
    );
    assert!(verify_with_published_keys(&node, &after));

    let kept = call(&node, "DELETE", &format!("{KEYS}/{new}"), &after, "");
    assert_eq!(kept.status, 409, "an active key stays: {}", kept.body);
    let removed = call(&node, "DELETE", &format!("{KEYS}/{first}"), &after, "");
    assert_eq!(removed.status, 204, "{}", removed.body);

    let refused = read_realm(&before);
    assert_eq!(refused.status, 401, "a removed key verifies nothing");
    assert!(
        refused
            .head
            .to_lowercase()
            .contains("www-authenticate: bearer"),
        "{}",
        refused.head
    );
    assert!(!verify_with_published_keys(&node, &before));
    assert_eq!(read_realm(&after).status, 200);
    let discovered = read_json(
        &http::get(node.data, "/realms/acme/.well-known/openid-configuration")
            .expect("an answer")
            .body,
    );
    assert_eq!(
        discovered["id_token_signing_alg_values_supported"],
        json!(["ES256", "RS256"])
    );
}

/// `saffui operator` with `arguments`, on `database`.
fn command_operator(database: &TestDatabase, arguments: &[&str]) -> Command {
    let mut command = support::saffui_command();
    command
        .arg("operator")
        .args(arguments)
        .env("SAFFUI_DATABASE_URL", database.connection_string(APP_ROLE))
        .env("SAFFUI_PUBLIC_ORIGIN", node::PUBLIC_ORIGIN);
    command
}

fn operate(database: &TestDatabase, arguments: &[&str]) -> Output {
    command_operator(database, arguments)
        .output()
        .expect("the saffui binary starts")
}

fn operate_without_root_key(database: &TestDatabase, arguments: &[&str]) -> Output {
    command_operator(database, arguments)
        .env_remove("SAFFUI_ROOT_KEY")
        .output()
        .expect("the saffui binary starts")
}

/// Runs `sql` as `role` and returns the first column of each row as text,
/// from a test that has no runtime.
fn read_as(database: &TestDatabase, role: &str, sql: &str) -> Vec<String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime for the statement")
        .block_on(async {
            let client = database
                .plan(role)
                .connect_directly()
                .await
                .expect("a connection");
            client
                .simple_query(sql)
                .await
                .expect("the statement ran")
                .into_iter()
                .filter_map(|message| match message {
                    tokio_postgres::SimpleQueryMessage::Row(row) => row.get(0).map(str::to_owned),
                    _ => None,
                })
                .collect()
        })
}

/// Writes `sql` in the realm of `made`, as the owner of the tables: a hand
/// in the database, behind the product.
fn write_as_owner(database: &TestDatabase, made: &Bootstrapped, sql: &str) {
    read_as(
        database,
        "saffui_owner",
        &format!(
            "BEGIN;
             SELECT set_config('saffui.tenant', '{}', true), set_config('saffui.realm', '{}', true);
             {sql}
             COMMIT",
            made.tenant, made.realm
        ),
    );
}

fn read_text(output: &[u8]) -> String {
    String::from_utf8_lossy(output).into_owned()
}

#[test]
fn the_operator_lets_an_administrator_made_before_the_keys_turn_them_over() {
    let database = database::create_database(EMBEDDED);
    let made = bootstrap_with_administrator(&database);
    // A realm and its administrator as they were before keys could be
    // turned over: one key, and no capability over keys.
    write_as_owner(
        &database,
        &made,
        "DELETE FROM signing_keys WHERE algorithm = 'RS256';
         UPDATE clients
         SET capabilities = array_remove(array_remove(capabilities, 'key:read'), 'key:write')
         WHERE client_id = 'operator';",
    );
    let algorithms = || {
        read_as(
            &database,
            MAINTENANCE_ROLE,
            "SELECT algorithm || ' ' || status FROM signing_keys ORDER BY algorithm",
        )
    };
    let node = node::Node::start(support::saffui_command(), &database);
    let token = get_token(&node, &made.secret);
    let turn_over = || call(&node, "POST", KEYS, &token, r#"{"alg":"ES256"}"#);
    assert_eq!(algorithms(), ["ES256 active"]);
    assert_eq!(
        turn_over().status,
        403,
        "nobody on the plane may grant key:write"
    );

    let rsa = operate(
        &database,
        &["rotate-key", "--realm", "acme", "--alg", "RS256"],
    );
    let granted = operate_without_root_key(
        &database,
        &[
            "grant",
            "--realm",
            "acme",
            "--client",
            "operator",
            "--capability",
            "key:write",
        ],
    );

    assert_eq!(rsa.status.code(), Some(0), "{}", read_text(&rsa.stderr));
    assert!(
        read_text(&rsa.stdout).contains("alg RS256\n"),
        "{}",
        read_text(&rsa.stdout)
    );
    assert_eq!(algorithms(), ["ES256 active", "RS256 active"]);
    assert_eq!(
        granted.status.code(),
        Some(0),
        "a grant needs no root key: {}",
        read_text(&granted.stderr)
    );
    let turned = turn_over();
    assert_eq!(turned.status, 201, "{}", turned.body);
    let by_the_operator = read_as(
        &database,
        MAINTENANCE_ROLE,
        r#"SELECT kind FROM audit_events
           WHERE convert_from(envelope, 'UTF8')::jsonb -> 'payload' -> 'actor'
                 = '{"operator": "command line"}'
           ORDER BY seq"#,
    );
    assert_eq!(
        by_the_operator,
        ["key.created", "client.capabilities_granted"],
        "each gesture is said in the chain, by the operator"
    );
}

#[test]
fn the_operator_command_answers_by_its_exit_code_what_it_refuses() {
    let database = database::create_database(EMBEDDED);
    let made = bootstrap_with_administrator(&database);
    // An application, and as many keys as a realm may hold.
    write_as_owner(
        &database,
        &made,
        "INSERT INTO clients (tenant_id, realm_id, client_row_id, client_id, name, secret_digest,
                              allows_client_credentials, scopes, enabled, created_at,
                              allows_authorization_code, redirect_uris,
                              post_logout_redirect_uris, requires_consent)
             VALUES (current_setting('saffui.tenant')::uuid, current_setting('saffui.realm')::uuid,
                     gen_random_uuid(), 'webapp', 'webapp', NULL, false, '{openid}', true, now(),
                     true, '{https://app.example.test/callback}', '{}', false);
         INSERT INTO signing_keys (tenant_id, realm_id, signing_key_id, kid, algorithm,
                                   public_jwk, sealed_private_key, created_at, status)
             SELECT current_setting('saffui.tenant')::uuid,
                    current_setting('saffui.realm')::uuid, gen_random_uuid(),
                    gen_random_uuid()::text, 'ES256', '{}', decode('00', 'hex'), now(), 'retired'
             FROM generate_series(1, 18);",
    );

    for (arguments, code) in [
        (
            &["rotate-key", "--realm", "nowhere", "--alg", "RS256"][..],
            5,
        ),
        (
            &[
                "grant",
                "--realm",
                "acme",
                "--client",
                "nobody",
                "--capability",
                "key:read",
            ][..],
            5,
        ),
        (
            &[
                "grant",
                "--realm",
                "nowhere",
                "--client",
                "operator",
                "--capability",
                "key:read",
            ][..],
            5,
        ),
        (
            &[
                "grant",
                "--realm",
                "acme",
                "--client",
                "operator",
                "--capability",
                "key:*",
            ][..],
            2,
        ),
        (&["rotate-key", "--realm", "acme", "--alg", "HS256"][..], 2),
        // An application holds no capability.
        (
            &[
                "grant",
                "--realm",
                "acme",
                "--client",
                "webapp",
                "--capability",
                "key:read",
            ][..],
            2,
        ),
        // A realm holds as many keys as it may.
        (&["rotate-key", "--realm", "acme", "--alg", "ES256"][..], 4),
    ] {
        let refused = operate(&database, arguments);
        assert_eq!(
            refused.status.code(),
            Some(code),
            "{arguments:?}: {}",
            read_text(&refused.stderr)
        );
    }
    let without_root_key = operate_without_root_key(
        &database,
        &["rotate-key", "--realm", "acme", "--alg", "RS256"],
    );
    assert_eq!(without_root_key.status.code(), Some(2));
    assert!(
        read_text(&without_root_key.stderr).contains("SAFFUI_ROOT_KEY"),
        "{}",
        read_text(&without_root_key.stderr)
    );
}
