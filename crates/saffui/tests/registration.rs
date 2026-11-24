//! Journeys through the real binary: a realm opens registration by initial
//! access token; a client registers itself, asks the person on a page before
//! it gets a code, changes what it says of itself and ends its
//! registration, and is refused everything after. The operator of the
//! deployment gives an administrator made before registration the right to
//! open it.

use std::process::Output;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use crypto::adapters::digest::ProviderDigester;
use crypto::adapters::open_provider;
use pgcore::APP_ROLE;
use pgcore::migrate::EMBEDDED;
use pgcore::testkit::TestDatabase;
use saffui_core::ports::crypto::Digester;
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
const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CALLBACK: &str = "https://app.example.test/callback";
const REGISTER: &str = "/realms/acme/oauth2/register";
const TOKEN: &str = "/realms/acme/oauth2/token";
const SETTINGS: &str = "/admin/v1/realms/acme/settings/registration";

/// What `bootstrap` tells of the realm `acme` and its administrator `operator`.
struct Bootstrapped {
    tenant: String,
    realm: String,
    secret: String,
}

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

/// What a page of consent says it showed of the client, for its answer.
fn read_shown(page: &str) -> String {
    page.split_once(r#"name="shown" value=""#)
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(shown, _)| shown.to_owned())
        .expect("what the page showed")
}

fn read_json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| panic!("not JSON: {text:?}"))
}

/// The value of one header of an answer, the first when it is repeated.
fn read_header<'a>(answer: &'a http::Answer, name: &str) -> Option<&'a str> {
    answer.head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// The `name=value` of the cookie an answer sets whose name starts with `prefix`.
fn read_cookie(answer: &http::Answer, prefix: &str) -> Option<String> {
    answer.head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        let value = value.trim();
        (key.eq_ignore_ascii_case("set-cookie") && value.starts_with(prefix))
            .then(|| value.split(';').next().unwrap_or_default().to_owned())
    })
}

fn read_parameter(location: &str, name: &str) -> Option<String> {
    let (_, query) = location.split_once('?')?;
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

fn get_token(node: &node::Node, secret: &str) -> String {
    let basic = format!("Basic {}", STANDARD.encode(format!("operator:{secret}")));
    let answer = http::send_request(
        node.data,
        "POST",
        TOKEN,
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

/// Sends `body` as JSON, with `token` as a bearer when there is one.
fn send(
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

/// Where `client_id` sends a browser to ask for `openid`, written for a query.
fn write_authorize_path(client_id: &str) -> String {
    let digester = ProviderDigester::new(open_provider().expect("a provider"));
    let challenge = URL_SAFE_NO_PAD.encode(digester.sha256(VERIFIER.as_bytes()));
    format!(
        "/realms/acme/oauth2/authorize?response_type=code&client_id={client_id}\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&scope=openid\
         &state=xyz&nonce=n-1&code_challenge={challenge}&code_challenge_method=S256"
    )
}

fn read_algorithm(token: &str) -> Value {
    let part = token.split('.').next().expect("a header");
    read_json(&String::from_utf8(URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("text"))
        ["alg"]
        .clone()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one journey, read from top to bottom"
)]
fn a_client_registers_itself_asks_the_person_changes_ends_and_is_refused_after() {
    let database = database::create_database(EMBEDDED);
    let made = bootstrap_with_administrator(&database);
    let node = node::Node::start(support::saffui_command(), &database);
    let operator = get_token(&node, &made.secret);
    let person = json!({ "username": "ada", "email": "ada@example.org", "password": PASSWORD });
    let created = send(
        &node,
        "POST",
        "/admin/v1/realms/acme/users",
        Some(&operator),
        &person.to_string(),
    );
    assert_eq!(created.status, 201, "{}", created.body);
    let metadata = json!({
        "redirect_uris": [CALLBACK],
        "token_endpoint_auth_method": "none",
        "client_name": "Registered",
    })
    .to_string();

    let closed = send(&node, "POST", REGISTER, None, &metadata);
    assert_eq!(closed.status, 403, "{}", closed.body);
    assert_eq!(read_json(&closed.body)["error"], "access_denied");
    let opened = send(
        &node,
        "PUT",
        SETTINGS,
        Some(&operator),
        &json!({ "registration": "initial_token", "registrable_scopes": ["openid"] }).to_string(),
    );
    assert_eq!(opened.status, 200, "{}", opened.body);
    let discovered = read_json(
        &http::get(node.data, "/realms/acme/.well-known/openid-configuration")
            .expect("an answer")
            .body,
    );
    assert_eq!(
        discovered["registration_endpoint"],
        format!("{}{REGISTER}", node::PUBLIC_ORIGIN)
    );
    let made_token = send(
        &node,
        "POST",
        "/admin/v1/realms/acme/initial-access-tokens",
        Some(&operator),
        &json!({ "uses": 1, "expires_in": 3600 }).to_string(),
    );
    assert_eq!(made_token.status, 201, "{}", made_token.body);
    let initial = read_json(&made_token.body)["initial_access_token"]
        .as_str()
        .expect("the token, shown once")
        .to_owned();

    let without = send(&node, "POST", REGISTER, None, &metadata);
    assert_eq!(without.status, 401, "{}", without.body);
    let registered = send(&node, "POST", REGISTER, Some(&initial), &metadata);
    assert_eq!(registered.status, 201, "{}", registered.body);
    assert_eq!(read_header(&registered, "cache-control"), Some("no-store"));
    assert_eq!(
        send(&node, "POST", REGISTER, Some(&initial), &metadata).status,
        401,
        "one use"
    );
    let registered = read_json(&registered.body);
    let client_id = registered["client_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();
    let managed_at = registered["registration_client_uri"]
        .as_str()
        .expect("where it is managed")
        .strip_prefix(node::PUBLIC_ORIGIN)
        .expect("under the public origin")
        .to_owned();
    let first = registered["registration_access_token"]
        .as_str()
        .expect("a token")
        .to_owned();

    // The person signs in, and is asked on a page before the client gets a code.
    let path = write_authorize_path(&client_id);
    let begun = http::get(node.data, &path).expect("an answer");
    assert_eq!(begun.status, 303, "{}", begun.body);
    let flow = read_cookie(&begun, "saffui_flow_").expect("a flow cookie");
    let login = read_header(&begun, "location").expect("a location");
    let request = read_parameter(login, "request").expect("a request");
    let origin = ("Origin", node::PUBLIC_ORIGIN);
    let signed_in = http::send_request(
        node.data,
        "POST",
        "/realms/acme/login",
        &[FORM, ("Cookie", &flow), origin],
        &format!(
            "request={request}&username=ada&password={}",
            PASSWORD.replace(' ', "+")
        ),
    )
    .expect("an answer");
    assert_eq!(signed_in.status, 303, "{}", signed_in.body);
    let consent_page = format!("/realms/acme/consent?request={request}");
    assert_eq!(
        read_header(&signed_in, "location"),
        Some(consent_page.as_str()),
        "a client anyone registered asks the person first"
    );
    let session = read_cookie(&signed_in, "saffui_session_acme=").expect("a session");
    let silent = http::send_request(
        node.data,
        "GET",
        &format!("{path}&prompt=none"),
        &[("Cookie", &session)],
        "",
    )
    .expect("an answer");
    assert_eq!(
        read_header(&silent, "location").and_then(|location| read_parameter(location, "error")),
        Some("consent_required".to_owned()),
        "a session alone gives it no code"
    );
    let both = format!("{flow}; {session}");
    let page = http::send_request(node.data, "GET", &consent_page, &[("Cookie", &both)], "")
        .expect("an answer");
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("This application registered itself")
            && page.body.contains("<bdi>app.example.test</bdi>"),
        "the page says who stands behind it, and where it sends the person: {}",
        page.body
    );
    let allowed = http::send_request(
        node.data,
        "POST",
        "/realms/acme/consent",
        &[FORM, ("Cookie", &both), origin],
        &format!(
            "request={request}&decision=allow&shown={}",
            read_shown(&page.body)
        ),
    )
    .expect("an answer");
    assert_eq!(allowed.status, 303, "{}", allowed.body);
    let code = read_header(&allowed, "location")
        .and_then(|location| read_parameter(location, "code"))
        .expect("a code");
    let exchanged = http::send_request(
        node.data,
        "POST",
        TOKEN,
        &[FORM],
        &format!(
            "grant_type=authorization_code&client_id={client_id}&code={code}\
             &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&code_verifier={VERIFIER}"
        ),
    )
    .expect("an answer");
    assert_eq!(exchanged.status, 200, "{}", exchanged.body);
    let tokens = read_json(&exchanged.body);
    assert_eq!(
        read_algorithm(tokens["id_token"].as_str().expect("an identity token")),
        "RS256"
    );
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned();

    // It changes what it says of itself, then ends its registration.
    let changed = json!({
        "client_id": client_id,
        "redirect_uris": [CALLBACK],
        "token_endpoint_auth_method": "none",
        "client_name": "Renamed",
    });
    let updated = send(
        &node,
        "PUT",
        &managed_at,
        Some(&first),
        &changed.to_string(),
    );
    assert_eq!(updated.status, 200, "{}", updated.body);
    let updated = read_json(&updated.body);
    assert_eq!(updated["client_name"], "Renamed");
    let second = updated["registration_access_token"]
        .as_str()
        .expect("the next token")
        .to_owned();
    assert_eq!(
        send(&node, "GET", &managed_at, Some(&first), "").status,
        401,
        "a token serves once"
    );
    let ended = send(&node, "DELETE", &managed_at, Some(&second), "");
    assert_eq!(ended.status, 204, "{}", ended.body);

    let refreshed = http::send_request(
        node.data,
        "POST",
        TOKEN,
        &[FORM],
        &format!("grant_type=refresh_token&client_id={client_id}&refresh_token={refresh_token}"),
    )
    .expect("an answer");
    assert_eq!(refreshed.status, 401, "{}", refreshed.body);
    assert_eq!(read_json(&refreshed.body)["error"], "invalid_client");
    let asked = http::send_request(node.data, "GET", &path, &[("Cookie", &session)], "")
        .expect("an answer");
    assert_eq!(
        asked.status, 404,
        "a client gone sends nobody anywhere: {}",
        asked.body
    );
    assert!(asked.body.contains("No such client."), "{}", asked.body);
    assert_eq!(
        send(&node, "GET", &managed_at, Some(&second), "").status,
        401
    );
}

/// `saffui operator` with `arguments`, on `database`, without the root key:
/// a grant seals and opens nothing.
fn grant(database: &TestDatabase, arguments: &[&str]) -> Output {
    support::saffui_command()
        .arg("operator")
        .args(arguments)
        .env("SAFFUI_DATABASE_URL", database.connection_string(APP_ROLE))
        .env("SAFFUI_PUBLIC_ORIGIN", node::PUBLIC_ORIGIN)
        .env_remove("SAFFUI_ROOT_KEY")
        .output()
        .expect("the saffui binary starts")
}

/// Writes `sql` in the realm of `made`, as the owner of the tables: a hand
/// in the database, behind the product.
fn write_as_owner(database: &TestDatabase, made: &Bootstrapped, sql: &str) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime for the statement")
        .block_on(async {
            let client = database
                .plan("saffui_owner")
                .connect_directly()
                .await
                .expect("a connection");
            client
                .batch_execute(&format!(
                    "BEGIN;
                     SELECT set_config('saffui.tenant', '{}', true),
                            set_config('saffui.realm', '{}', true);
                     {sql}
                     COMMIT",
                    made.tenant, made.realm
                ))
                .await
                .expect("the statement ran");
        });
}

#[test]
fn the_operator_gives_an_administrator_made_before_registration_the_right_to_open_it() {
    let database = database::create_database(EMBEDDED);
    let made = bootstrap_with_administrator(&database);
    // An administrator as one was made before the settings of a realm.
    write_as_owner(
        &database,
        &made,
        "UPDATE clients SET capabilities = array_remove(capabilities, 'realm:write')
         WHERE client_id = 'operator';",
    );
    let node = node::Node::start(support::saffui_command(), &database);
    let token = get_token(&node, &made.secret);
    let open = || {
        send(
            &node,
            "PUT",
            SETTINGS,
            Some(&token),
            &json!({ "registration": "open" }).to_string(),
        )
    };
    assert_eq!(
        open().status,
        403,
        "nobody on the plane may grant realm:write"
    );

    let granted = grant(
        &database,
        &[
            "grant",
            "--realm",
            "acme",
            "--client",
            "operator",
            "--capability",
            "realm:write",
        ],
    );

    assert_eq!(
        granted.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&granted.stderr)
    );
    let opened = open();
    assert_eq!(opened.status, 200, "{}", opened.body);
    assert_eq!(read_json(&opened.body)["registration"], "open");
}
