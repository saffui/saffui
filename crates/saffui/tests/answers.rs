//! Journeys through the real binary: an administrator declares what an
//! application is handed back; a person signs in, and the application gets a
//! code posted by a page whose policy lets only that post run, an identity
//! token and an access token after the `#`, then a code and an identity token
//! that binds it, each verifiable with what the realm publishes.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use crypto::adapters::digest::ProviderDigester;
use crypto::adapters::open_provider;
use crypto::adapters::sign::JoseSigner;
use pgcore::APP_ROLE;
use pgcore::migrate::EMBEDDED;
use pgcore::testkit::TestDatabase;
use saffui_core::ports::crypto::{Digester, SignatureAlgorithm, Signer};
use saffui_core::tokens::mint::write_half_hash;
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
const TOKEN: &str = "/realms/acme/oauth2/token";

fn read_json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| panic!("not JSON: {text:?}"))
}

fn read_header<'a>(answer: &'a http::Answer, name: &str) -> Option<&'a str> {
    answer.head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn read_cookie(answer: &http::Answer, prefix: &str) -> Option<String> {
    answer.head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        let value = value.trim();
        (key.eq_ignore_ascii_case("set-cookie") && value.starts_with(prefix))
            .then(|| value.split(';').next().unwrap_or_default().to_owned())
    })
}

/// A parameter of what follows `separator` in an address, still encoded.
fn read_parameter(location: &str, separator: char, name: &str) -> Option<String> {
    let (_, answer) = location.split_once(separator)?;
    answer
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

/// The value of a hidden field of a posted answer, as the page writes it.
fn read_field(page: &str, name: &str) -> Option<String> {
    let opening = format!(r#"<input type="hidden" name="{name}" value=""#);
    page.split_once(&opening)
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(value, _)| value.to_owned())
}

/// The realm `acme`, the person `ada`, and the public application `spa`,
/// which an administrator declared handed back a code, an identity token
/// with a code, and an identity token with an access token.
fn prepare_realm(database: &TestDatabase) -> node::Node {
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
    let person = json!({ "username": "ada", "email": "ada@example.org", "password": PASSWORD });
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
        "client_id": "spa",
        "scopes": ["openid", "email"],
        "redirect_uris": [CALLBACK],
        "public": true,
        "response_types": ["code", "id_token code", "id_token token"],
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
    assert_eq!(
        read_json(&created.body)["client"]["response_types"],
        json!(["code", "code id_token", "id_token token"])
    );
    node
}

/// Where `spa` sends a browser to ask for `response_type`.
fn write_authorize_path(response_type: &str, more: &str) -> String {
    let digester = ProviderDigester::new(open_provider().expect("a provider"));
    let challenge = URL_SAFE_NO_PAD.encode(digester.sha256(VERIFIER.as_bytes()));
    format!(
        "/realms/acme/oauth2/authorize?response_type={response_type}&client_id=spa\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&scope=openid%20email\
         &state=xyz&nonce=n-1&code_challenge={challenge}&code_challenge_method=S256{more}"
    )
}

/// Signs `ada` in on the hosted page for `spa` asking `response_type`, and
/// returns the answer of the page.
fn sign_in(node: &node::Node, response_type: &str, more: &str) -> http::Answer {
    let sent = http::get(node.data, &write_authorize_path(response_type, more)).expect("an answer");
    assert_eq!(sent.status, 303, "{}", sent.body);
    let login = read_header(&sent, "location")
        .expect("a location")
        .to_owned();
    let request = read_parameter(&login, '?', "request").expect("a pending request");
    let flow = read_cookie(&sent, "saffui_flow_").expect("a flow cookie");
    let form = format!(
        "request={request}&username=ada&password={}",
        PASSWORD.replace(' ', "+")
    );
    http::send_request(
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
    .expect("an answer")
}

fn exchange_code(node: &node::Node, code: &str) -> Value {
    let form = format!(
        "grant_type=authorization_code&client_id=spa&code={code}\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&code_verifier={VERIFIER}"
    );
    let granted = http::send_request(node.data, "POST", TOKEN, &[FORM], &form).expect("an answer");
    assert_eq!(granted.status, 200, "{}", granted.body);
    read_json(&granted.body)
}

/// Verifies a token with the keys the realm publishes, and returns its
/// header and its claims.
fn verify_with_published_keys(node: &node::Node, token: &str) -> (Value, Value) {
    let key_set = read_json(
        &http::get(node.data, "/realms/acme/oauth2/jwks")
            .expect("an answer")
            .body,
    );
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let decode = |part: &str| {
        read_json(
            &String::from_utf8(URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("text"),
        )
    };
    let header = decode(parts[0]);
    let key = key_set["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|key| key["kid"] == header["kid"]))
        .expect("the key the token names is published");
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
    (header, decode(parts[1]))
}

fn write_published_half_hash(value: &str) -> String {
    let digester = ProviderDigester::new(open_provider().expect("a provider"));
    write_half_hash(&digester, SignatureAlgorithm::Es256, value).expect("a hash")
}

#[test]
fn a_code_is_posted_by_a_page_whose_policy_runs_its_script_alone_and_posts_to_the_client_alone() {
    let database = database::create_database(EMBEDDED);
    let node = prepare_realm(&database);

    let posted = sign_in(&node, "code", "&response_mode=form_post");

    assert_eq!(posted.status, 200, "{}", posted.body);
    assert!(read_header(&posted, "location").is_none());
    assert_eq!(read_header(&posted, "cache-control"), Some("no-store"));
    assert!(read_cookie(&posted, "saffui_session_acme=").is_some());
    let script = posted
        .body
        .split_once("<script>")
        .and_then(|(_, rest)| rest.split_once("</script>"))
        .map(|(script, _)| script)
        .expect("the script of the page");
    let digester = ProviderDigester::new(open_provider().expect("a provider"));
    let hash = STANDARD.encode(digester.sha256(script.as_bytes()));
    assert_eq!(
        read_header(&posted, "content-security-policy"),
        Some(
            format!(
                "default-src 'none'; script-src 'sha256-{hash}'; form-action {CALLBACK}; \
                 frame-ancestors 'none'; base-uri 'none'"
            )
            .as_str()
        ),
        "a browser runs the script of the page, and the page posts to the client alone"
    );
    assert!(
        posted
            .body
            .contains(&format!(r#"<form method="post" action="{CALLBACK}">"#)),
        "{}",
        posted.body
    );
    assert_eq!(read_field(&posted.body, "state").as_deref(), Some("xyz"));
    let code = read_field(&posted.body, "code").expect("a code");
    let granted = exchange_code(&node, &code);
    assert_eq!(granted["scope"], "openid email");
}

#[test]
fn an_identity_token_and_an_access_token_come_back_after_the_hash_bound_to_each_other() {
    let database = database::create_database(EMBEDDED);
    let node = prepare_realm(&database);

    let back = sign_in(&node, "token%20id_token", "");

    assert_eq!(back.status, 303, "{}", back.body);
    let location = read_header(&back, "location").expect("a location");
    assert!(location.starts_with(&format!("{CALLBACK}#")), "{location}");
    assert!(!location.contains('?'), "nothing on the query: {location}");
    assert_eq!(
        read_parameter(location, '#', "state").as_deref(),
        Some("xyz")
    );
    assert_eq!(read_parameter(location, '#', "code"), None);
    let access_token = read_parameter(location, '#', "access_token").expect("an access token");
    let id_token = read_parameter(location, '#', "id_token").expect("an identity token");
    let (_, identity) = verify_with_published_keys(&node, &id_token);
    assert_eq!(identity["aud"], "spa");
    assert_eq!(identity["nonce"], "n-1");
    assert_eq!(
        identity["at_hash"],
        write_published_half_hash(&access_token)
    );
    let (header, access) = verify_with_published_keys(&node, &access_token);
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(access["sid"], identity["sid"]);
    let told = http::send_request(
        node.data,
        "GET",
        "/realms/acme/oauth2/userinfo",
        &[("Authorization", format!("Bearer {access_token}").as_str())],
        "",
    )
    .expect("an answer");
    assert_eq!(told.status, 200, "{}", told.body);
    assert_eq!(read_json(&told.body)["email"], "ada@example.org");
}

#[test]
fn a_code_and_the_identity_token_that_binds_it_come_back_and_the_code_is_spent_as_any() {
    let database = database::create_database(EMBEDDED);
    let node = prepare_realm(&database);

    let back = sign_in(&node, "code%20id_token", "");

    assert_eq!(back.status, 303, "{}", back.body);
    let location = read_header(&back, "location").expect("a location");
    assert!(
        location.starts_with(&format!("{CALLBACK}#code=")),
        "{location}"
    );
    let code = read_parameter(location, '#', "code").expect("a code");
    let id_token = read_parameter(location, '#', "id_token").expect("an identity token");
    let (_, identity) = verify_with_published_keys(&node, &id_token);
    assert_eq!(identity["c_hash"], write_published_half_hash(&code));
    assert!(identity.get("at_hash").is_none(), "{identity}");
    let granted = exchange_code(&node, &code);
    let (_, exchanged) =
        verify_with_published_keys(&node, granted["id_token"].as_str().expect("one"));
    assert_eq!(exchanged["sub"], identity["sub"]);
    assert_eq!(exchanged["sid"], identity["sid"]);

    let refused =
        http::get(node.data, &write_authorize_path("code%20token", "")).expect("an answer");
    assert_eq!(refused.status, 303, "{}", refused.body);
    assert_eq!(
        read_parameter(
            read_header(&refused, "location").expect("a location"),
            '#',
            "error"
        )
        .as_deref(),
        Some("unauthorized_client"),
        "a type the administrator did not declare"
    );
}
