//! Journeys through the real binary: an operator administers its realm over
//! the network, by hand and with the command line, and nothing else does.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::TcpListener;
use std::process::Output;
use std::thread;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use pgcore::APP_ROLE;
use pgcore::migrate::EMBEDDED;
use pgcore::testkit::TestDatabase;
use serde_json::{Value, json};

#[path = "support/database.rs"]
mod database;
#[path = "support/http.rs"]
mod http;
#[path = "support/node.rs"]
mod node;
mod support;

const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");
const JSON: (&str, &str) = ("Content-Type", "application/json");

/// Creates the realm `acme` with an administrator `operator`, and returns its secret.
fn bootstrap_with_administrator(database: &TestDatabase) -> String {
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
    String::from_utf8(created.stdout)
        .expect("text")
        .lines()
        .find_map(|line| line.strip_prefix("client_secret "))
        .expect("the secret is printed once")
        .to_owned()
}

fn read_json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| panic!("not JSON: {text:?}"))
}

fn get_token(node: &node::Node, client_id: &str, secret: &str) -> String {
    let basic = format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")));
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

fn call(
    node: &node::Node,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> http::Answer {
    let bearer = token.map(|token| format!("Bearer {token}"));
    let mut head = vec![JSON];
    if let Some(bearer) = &bearer {
        head.push(("Authorization", bearer));
    }
    http::send_request(node.data, method, path, &head, body).expect("an answer")
}

#[test]
fn an_operator_administers_its_realm_and_a_client_it_created_does_not() {
    let database = database::create_database(EMBEDDED);
    let secret = bootstrap_with_administrator(&database);
    let node = node::Node::start(support::saffui_command(), &database);
    let token = get_token(&node, "operator", &secret);

    let realm = call(&node, "GET", "/admin/v1/realms/acme", Some(&token), "");
    assert_eq!(realm.status, 200, "{}", realm.body);
    assert_eq!(
        read_json(&realm.body)["issuer"],
        "http://localhost:8080/realms/acme"
    );

    let wanted = json!({ "client_id": "billing", "scopes": ["invoices:read"] }).to_string();
    let created = call(
        &node,
        "POST",
        "/admin/v1/realms/acme/clients",
        Some(&token),
        &wanted,
    );
    assert_eq!(created.status, 201, "{}", created.body);
    let billing_secret = read_json(&created.body)["client_secret"]
        .as_str()
        .expect("the secret of the new client")
        .to_owned();

    // The new client is a client like any other: it gets tokens, and they open nothing here.
    let billing_token = get_token(&node, "billing", &billing_secret);
    let refused = call(
        &node,
        "GET",
        "/admin/v1/realms/acme",
        Some(&billing_token),
        "",
    );
    assert_eq!(refused.status, 401);

    let listed = call(
        &node,
        "GET",
        "/admin/v1/realms/acme/clients?count=true",
        Some(&token),
        "",
    );
    let page = read_json(&listed.body);
    assert_eq!(page["total"], 2);
    assert_eq!(page["items"][0]["client_id"], "billing");

    let verdict = call(
        &node,
        "GET",
        "/admin/v1/realms/acme/audit/verification",
        Some(&token),
        "",
    );
    let report = read_json(&verdict.body);
    assert_eq!(report["intact"], true, "{}", verdict.body);
    // Realm, key, operator, its token, the client it created, that client's token.
    assert_eq!(report["events"], 6);
}

#[test]
fn the_administration_plane_answers_nobody_without_a_token_and_is_not_on_the_operations_plane() {
    let database = database::create_database(EMBEDDED);
    bootstrap_with_administrator(&database);
    let node = node::Node::start(support::saffui_command(), &database);

    let anonymous = call(&node, "GET", "/admin/v1/realms/acme", None, "");
    assert_eq!(anonymous.status, 401);
    assert!(
        anonymous
            .head
            .to_lowercase()
            .contains("www-authenticate: bearer"),
        "{}",
        anonymous.head
    );

    let on_ops = http::get(node.ops, "/admin/v1/realms/acme").expect("an answer");
    assert_eq!(on_ops.status, 404);
}

/// Creates the realm `globex` with a client `billing` that may not administer it.
fn bootstrap_without_administrator(database: &TestDatabase) -> String {
    let created = support::saffui_command()
        .args(["bootstrap", "--tenant", "Globex", "--realm", "globex"])
        .args(["--client", "billing", "--scope", "invoices:read"])
        .env("SAFFUI_DATABASE_URL", database.connection_string(APP_ROLE))
        .env("SAFFUI_PUBLIC_ORIGIN", node::PUBLIC_ORIGIN)
        .output()
        .expect("the saffui binary starts");
    assert_eq!(created.status.code(), Some(0));
    String::from_utf8(created.stdout)
        .expect("text")
        .lines()
        .find_map(|line| line.strip_prefix("client_secret "))
        .expect("the secret is printed once")
        .to_owned()
}

/// Runs `saffui realm show` as `client_id`, its secret given by reference.
fn show_realm(server: &str, realm: &str, client_id: &str, secret: &str) -> Output {
    support::saffui_command()
        .args(["realm", "show", "--realm", realm, "--server", server])
        .env("SAFFUI_CLIENT_ID", client_id)
        .env("SAFFUI_CLIENT_SECRET", "env://SECRET_OF_THE_CLIENT")
        .env("SECRET_OF_THE_CLIENT", secret)
        .output()
        .expect("the saffui binary starts")
}

#[test]
fn an_operator_reads_its_realm_over_the_network_with_the_command_line() {
    let database = database::create_database(EMBEDDED);
    let secret = bootstrap_with_administrator(&database);
    let node = node::Node::start(support::saffui_command(), &database);

    let shown = show_realm(
        &format!("http://{}", node.data),
        "acme",
        "operator",
        &secret,
    );

    let stdout = String::from_utf8_lossy(&shown.stdout);
    assert_eq!(
        shown.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    assert!(
        stdout.starts_with("name acme\nissuer http://localhost:8080/realms/acme\nenabled true\n"),
        "{stdout}"
    );
}

#[test]
fn a_refusal_of_the_node_is_told_in_the_exit_code() {
    let database = database::create_database(EMBEDDED);
    let secret = bootstrap_with_administrator(&database);
    let billing = bootstrap_without_administrator(&database);
    let node = node::Node::start(support::saffui_command(), &database);
    let server = format!("http://{}", node.data);

    let wrong_secret = show_realm(&server, "acme", "operator", "not-the-secret");
    assert_eq!(wrong_secret.status.code(), Some(3), "authentication failed");
    let unknown_realm = show_realm(&server, "nowhere", "operator", &secret);
    assert_eq!(
        unknown_realm.status.code(),
        Some(3),
        "an unknown realm is told alike"
    );
    let not_an_administrator = show_realm(&server, "globex", "billing", &billing);
    assert_eq!(
        not_an_administrator.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&not_an_administrator.stderr)
    );
}

#[test]
fn a_node_elsewhere_or_named_and_a_secret_given_as_a_value_are_refused_before_anything_is_sent() {
    // A name would go to the resolver of the system, which may answer anything.
    for elsewhere in [
        "http://10.0.0.1:8080",
        "http://localhost:9",
        "http://[localhost]:9",
        "http://[127.0.0.1]:9",
    ] {
        let refused = show_realm(elsewhere, "acme", "operator", "s3cret");
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert_eq!(refused.status.code(), Some(2), "{elsewhere}: {stderr}");
        assert!(stderr.contains("loopback"), "{elsewhere}: {stderr}");
    }

    let as_value = support::saffui_command()
        .args([
            "realm",
            "show",
            "--realm",
            "acme",
            "--server",
            "http://127.0.0.1:9",
        ])
        .env("SAFFUI_CLIENT_ID", "operator")
        .env("SAFFUI_CLIENT_SECRET", "s3cret")
        .output()
        .expect("the saffui binary starts");
    let stderr = String::from_utf8_lossy(&as_value.stderr);
    assert_eq!(as_value.status.code(), Some(2));
    assert!(stderr.contains("SAFFUI_CLIENT_SECRET"), "{stderr}");
    assert!(
        !stderr.contains("s3cret"),
        "the value is not repeated: {stderr}"
    );
}

#[test]
fn a_command_line_with_no_client_named_asks_for_authentication() {
    let anonymous = support::saffui_command()
        .args(["realm", "show", "--realm", "acme"])
        .args(["--server", "http://127.0.0.1:9"])
        .env_remove("SAFFUI_CLIENT_ID")
        .env_remove("SAFFUI_CLIENT_SECRET")
        .output()
        .expect("the saffui binary starts");
    let stderr = String::from_utf8_lossy(&anonymous.stderr);
    assert_eq!(anonymous.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("SAFFUI_CLIENT_ID"), "{stderr}");
}

#[test]
fn the_command_line_goes_through_no_proxy_its_environment_names() {
    let proxy = TcpListener::bind("127.0.0.1:0").expect("a port");
    proxy.set_nonblocking(true).expect("non-blocking");
    let proxy_url = format!("http://{}", proxy.local_addr().expect("an address"));
    // A node that refuses whoever asks, so the command ends at once.
    let node = TcpListener::bind("127.0.0.1:0").expect("a port");
    let server = format!("http://{}", node.local_addr().expect("an address"));
    thread::spawn(move || {
        let Ok((stream, _)) = node.accept() else {
            return;
        };
        // The whole request is read first: closing on unread bytes would reset the link.
        let mut reader = BufReader::new(stream);
        let mut length = 0;
        let mut line = String::new();
        while reader.read_line(&mut line).is_ok_and(|read| read > 2) {
            let lowered = line.to_ascii_lowercase();
            if let Some(value) = lowered.strip_prefix("content-length:") {
                length = value.trim().parse().unwrap_or(0);
            }
            line.clear();
        }
        let mut body = vec![0; length];
        let _ = reader.read_exact(&mut body);
        let _ = reader.into_inner().write_all(
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    });

    let mut command = support::saffui_command();
    for variable in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        command.env(variable, &proxy_url);
    }
    let refused = command
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .args(["realm", "show", "--realm", "acme", "--server", &server])
        .env("SAFFUI_CLIENT_ID", "operator")
        .env("SAFFUI_CLIENT_SECRET", "env://SECRET_OF_THE_CLIENT")
        .env("SECRET_OF_THE_CLIENT", "s3cret")
        .output()
        .expect("the saffui binary starts");

    assert_eq!(
        refused.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let reached = proxy.accept().map(|_| ());
    assert_eq!(
        reached.map_err(|error| error.kind()),
        Err(ErrorKind::WouldBlock),
        "the secret went to the proxy"
    );
}
