//! Journeys through the real binary: an operator creates a person and an
//! application, the person signs in on the hosted page, and the application
//! exchanges its code for tokens anyone can verify.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use crypto::adapters::digest::ProviderDigester;
use crypto::adapters::open_provider;
use crypto::adapters::sign::JoseSigner;
use crypto::adapters::soft_key::SoftKey;
use pgcore::migrate::EMBEDDED;
use pgcore::testkit::TestDatabase;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE};
use saffui_core::ports::crypto::{Digester, SignatureAlgorithm, Signer};
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
const TOKEN: &str = "/realms/acme/oauth2/token";
const OWNER: &str = "saffui_owner";

fn read_json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| panic!("not JSON: {text:?}"))
}

fn decode_part(part: &str) -> Value {
    read_json(&String::from_utf8(URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("text"))
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

/// The realm `acme`, an operator, the person `ada` and the public application
/// `portal`, the last two created through the administration plane.
fn prepare_realm(database: &TestDatabase, node_command: std::process::Command) -> node::Node {
    prepare_realm_with_operator(database, node_command).0
}

/// As [`prepare_realm`], and the `Authorization` header of the operator.
fn prepare_realm_with_operator(
    database: &TestDatabase,
    node_command: std::process::Command,
) -> (node::Node, String) {
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
    let node = node::Node::start(node_command, database);

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
        "client_id": "portal",
        "scopes": ["openid", "profile", "email"],
        "redirect_uris": ["https://app.example.test/callback"],
        "post_logout_redirect_uris": ["https://app.example.test/goodbye"],
        "public": true,
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
    assert_eq!(created["client"]["public"], true);
    assert!(
        created.get("client_secret").is_none(),
        "a public client is given no secret: {created}"
    );
    (node, basic)
}

fn write_authorize_path() -> String {
    let digester = ProviderDigester::new(open_provider().expect("a provider"));
    let challenge = URL_SAFE_NO_PAD.encode(digester.sha256(VERIFIER.as_bytes()));
    format!(
        "/realms/acme/oauth2/authorize?response_type=code&client_id=portal\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&scope=openid%20email\
         &state=xyz&nonce=n-1&code_challenge={challenge}&code_challenge_method=S256"
    )
}

/// Signs `ada` in on the hosted page. Returns where the browser is sent
/// back, and the session cookie it was given.
fn sign_in(node: &node::Node, password: &str) -> (http::Answer, Option<String>) {
    sign_in_from(node, password, None)
}

/// As [`sign_in`], behind a proxy that says where the request comes from.
fn sign_in_from(
    node: &node::Node,
    password: &str,
    forwarded_for: Option<&str>,
) -> (http::Answer, Option<String>) {
    let sent_to_login = http::get(node.data, &write_authorize_path()).expect("an answer");
    assert_eq!(sent_to_login.status, 303, "{}", sent_to_login.body);
    let login = read_header(&sent_to_login, "location")
        .expect("a location")
        .to_owned();
    let request = read_parameter(&login, "request").expect("a pending request");
    let flow = read_cookie(&sent_to_login, "saffui_flow_").expect("a flow cookie");

    let page =
        http::send_request(node.data, "GET", &login, &[("Cookie", &flow)], "").expect("an answer");
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("<form method=\"post\""), "{}", page.body);

    let form = format!(
        "request={request}&username=ada&password={}",
        password.replace(' ', "+")
    );
    let mut head = vec![
        FORM,
        ("Cookie", flow.as_str()),
        ("Origin", node::PUBLIC_ORIGIN),
    ];
    if let Some(address) = forwarded_for {
        head.push(("X-Forwarded-For", address));
    }
    let answer = http::send_request(node.data, "POST", "/realms/acme/login", &head, &form)
        .expect("an answer");
    let session = read_cookie(&answer, "saffui_session_acme=");
    (answer, session)
}

fn exchange_code(node: &node::Node, code: &str, verifier: &str) -> http::Answer {
    let form = format!(
        "grant_type=authorization_code&client_id=portal&code={code}\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&code_verifier={verifier}"
    );
    http::send_request(node.data, "POST", TOKEN, &[FORM], &form).expect("an answer")
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
    let header = decode_part(parts[0]);
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
    (header, decode_part(parts[1]))
}

/// The stored passwords, read as the owner in the scope of `acme`, and the
/// kinds of the events of the chain, read as maintenance.
fn read_passwords_and_events(database: &TestDatabase) -> (Vec<String>, Vec<String>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(async {
            let read_column = async |client: &tokio_postgres::Client, query: &str| {
                client
                    .query(query, &[])
                    .await
                    .expect("rows")
                    .iter()
                    .map(|row| row.get(0))
                    .collect::<Vec<String>>()
            };
            // The passwords under the owner, in the scope of the realm:
            // maintenance is never granted them.
            let mut owner = database
                .plan(OWNER)
                .connect_directly()
                .await
                .expect("a connection");
            let scoped = owner.transaction().await.expect("a transaction");
            scoped
                .batch_execute(
                    "SELECT set_config('saffui.tenant', tenant_id::text, true),
                            set_config('saffui.realm', realm_id::text, true)
                     FROM realm_directory WHERE name = 'acme'",
                )
                .await
                .expect("the scope of the realm");
            let passwords: Vec<String> = scoped
                .query("SELECT phc FROM password_credentials", &[])
                .await
                .expect("rows")
                .iter()
                .map(|row| row.get(0))
                .collect();
            scoped.rollback().await.expect("nothing to keep");
            let maintenance = database
                .plan(MAINTENANCE_ROLE)
                .connect_directly()
                .await
                .expect("a connection");
            (
                passwords,
                read_column(&maintenance, "SELECT kind FROM audit_events ORDER BY seq").await,
            )
        })
}

#[test]
fn a_person_signs_in_and_the_application_gets_tokens_the_published_key_verifies() {
    let database = database::create_database(EMBEDDED);
    let node = prepare_realm(&database, support::saffui_command());

    let (back, session) = sign_in(&node, PASSWORD);
    assert_eq!(back.status, 303, "{}", back.body);
    let location = read_header(&back, "location").expect("a location");
    assert!(
        location.starts_with("https://app.example.test/callback?code="),
        "{location}"
    );
    assert_eq!(read_parameter(location, "state").as_deref(), Some("xyz"));
    assert_eq!(
        read_parameter(location, "iss").as_deref(),
        Some("http%3A%2F%2Flocalhost%3A8080%2Frealms%2Facme")
    );
    let session = session.expect("a session cookie");
    // The origin of this node is not served over TLS: the cookie says so.
    assert!(
        !back.head.contains("; Secure"),
        "a Secure cookie would never come back over http: {}",
        back.head
    );

    let code = read_parameter(location, "code").expect("a code");
    let granted = exchange_code(&node, &code, VERIFIER);
    assert_eq!(granted.status, 200, "{}", granted.body);
    let granted = read_json(&granted.body);
    assert_eq!(granted["scope"], "openid email");

    let (header, identity) =
        verify_with_published_keys(&node, granted["id_token"].as_str().expect("an ID token"));
    assert_eq!(header["alg"], "ES256");
    assert_eq!(identity["iss"], "http://localhost:8080/realms/acme");
    assert_eq!(identity["aud"], "portal");
    assert_eq!(identity["nonce"], "n-1");
    assert_eq!(identity["email"], "ada@example.org");
    assert_eq!(identity["email_verified"], false);
    assert!(
        identity.get("preferred_username").is_none(),
        "the profile scope was not asked for: {identity}"
    );
    let (header, access) = verify_with_published_keys(
        &node,
        granted["access_token"].as_str().expect("an access token"),
    );
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(access["sub"], identity["sub"]);
    assert_eq!(access["sid"], identity["sid"]);
    assert_eq!(access["client_id"], "portal");

    // The code served once, and the session spares the person a second sign-in.
    assert_eq!(exchange_code(&node, &code, VERIFIER).status, 400);
    let straight_back = http::send_request(
        node.data,
        "GET",
        &write_authorize_path(),
        &[("Cookie", &session)],
        "",
    )
    .expect("an answer");
    assert_eq!(straight_back.status, 303);
    assert!(
        read_header(&straight_back, "location")
            .is_some_and(|location| location.starts_with("https://app.example.test/callback?code=")),
        "{}",
        straight_back.head
    );
}

#[test]
fn a_code_is_worth_nothing_without_its_verifier_and_a_wrong_password_opens_no_session() {
    let database = database::create_database(EMBEDDED);
    let node = prepare_realm(&database, support::saffui_command());

    let (refused, session) = sign_in(&node, "not the password");
    assert_eq!(refused.status, 401, "{}", refused.body);
    assert_eq!(session, None);
    assert!(read_header(&refused, "location").is_none());
    let on_ops = http::get(node.ops, &write_authorize_path()).expect("an answer");
    assert_eq!(on_ops.status, 404, "the operations plane signs nobody in");

    // A byte no client writes names no client: it is refused like an unknown
    // one, and never sent to a database that would fail on it.
    let with_a_null = write_authorize_path().replace("client_id=portal", "client_id=portal%00");
    assert_eq!(
        http::get(node.data, &with_a_null)
            .expect("an answer")
            .status,
        404
    );
    let state_with_a_null = write_authorize_path().replace("state=xyz", "state=x%00z");
    let returned = http::get(node.data, &state_with_a_null).expect("an answer");
    assert_eq!(returned.status, 303, "{}", returned.body);
    let location = read_header(&returned, "location").expect("a location");
    assert_eq!(
        read_parameter(location, "error").as_deref(),
        Some("invalid_request")
    );
    assert_eq!(read_parameter(location, "state"), None, "{location}");
    let named_with_a_null = http::send_request(
        node.data,
        "POST",
        TOKEN,
        &[FORM],
        "grant_type=authorization_code&client_id=portal%00&code=x&redirect_uri=y&code_verifier=z",
    )
    .expect("an answer");
    assert_eq!(named_with_a_null.status, 401, "{}", named_with_a_null.body);

    let (back, _session) = sign_in(&node, PASSWORD);
    let location = read_header(&back, "location").expect("a location");
    let code = read_parameter(location, "code").expect("a code");
    let stolen = exchange_code(
        &node,
        &code,
        "a-verifier-the-thief-made-up-and-long-enough-to-pass",
    );
    assert_eq!(stolen.status, 400, "{}", stolen.body);
    assert_eq!(read_json(&stolen.body)["error"], "invalid_grant");
    // The attempt burned the code: its owner must start again.
    assert_eq!(exchange_code(&node, &code, VERIFIER).status, 400);

    let (stored_passwords, kinds) = read_passwords_and_events(&database);
    assert_eq!(stored_passwords.len(), 1);
    assert!(
        stored_passwords[0].starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
        "the password is kept as an Argon2id hash at the cost of the house: {}",
        stored_passwords[0]
    );
    assert_eq!(
        kinds,
        [
            "realm.created",
            "key.created",
            "client.created",
            "token.issued",
            "person.created",
            "client.created",
            "session.opened",
        ],
        "one event per change, and none for the refusals"
    );
}

#[test]
fn guesses_lock_out_the_address_they_come_from_and_a_header_is_believed_from_a_named_proxy_only() {
    // Behind a proxy the deployment named: the address it reports is the caller.
    let database = database::create_database(EMBEDDED);
    let mut behind_a_proxy = support::saffui_command();
    behind_a_proxy.env("SAFFUI_TRUSTED_PROXIES", "127.0.0.0/8");
    let node = prepare_realm(&database, behind_a_proxy);
    for _ in 0..5 {
        let (refused, _) = sign_in_from(&node, "a guess", Some("203.0.113.7"));
        assert_eq!(refused.status, 401, "{}", refused.body);
    }
    let (still_refused, _) = sign_in_from(&node, PASSWORD, Some("203.0.113.7"));
    assert_eq!(
        still_refused.status, 401,
        "the address that guessed is locked out of the name"
    );
    let (welcomed, session) = sign_in_from(&node, PASSWORD, Some("198.51.100.9"));
    assert_eq!(welcomed.status, 303, "{}", welcomed.body);
    assert!(session.is_some(), "the person signs in from where they are");

    // Without a named proxy the header is words: every request is its peer's.
    let database = database::create_database(EMBEDDED);
    let node = prepare_realm(&database, support::saffui_command());
    for round in 0..5 {
        let claimed = format!("203.0.113.{round}");
        let (refused, _) = sign_in_from(&node, "a guess", Some(&claimed));
        assert_eq!(refused.status, 401, "{}", refused.body);
    }
    let (refused, _) = sign_in_from(&node, PASSWORD, Some("198.51.100.9"));
    assert_eq!(
        refused.status, 401,
        "five guesses from one peer lock it out, whatever addresses it claimed"
    );
}

/// Spends a refresh token of `portal` for the next one.
fn refresh(node: &node::Node, refresh_token: &str) -> http::Answer {
    let form = format!("grant_type=refresh_token&client_id=portal&refresh_token={refresh_token}");
    http::send_request(node.data, "POST", TOKEN, &[FORM], &form).expect("an answer")
}

/// Signs `ada` in and exchanges the code: the tokens, and the session cookie.
fn sign_in_for_tokens(node: &node::Node) -> (Value, String) {
    let (back, session) = sign_in(node, PASSWORD);
    assert_eq!(back.status, 303, "{}", back.body);
    let location = read_header(&back, "location").expect("a location");
    let code = read_parameter(location, "code").expect("a code");
    let tokens = exchange_code(node, &code, VERIFIER);
    assert_eq!(tokens.status, 200, "{}", tokens.body);
    (read_json(&tokens.body), session.expect("a session cookie"))
}

fn ask_user_info(node: &node::Node, access_token: &str) -> http::Answer {
    let bearer = format!("Bearer {access_token}");
    http::send_request(
        node.data,
        "GET",
        "/realms/acme/oauth2/userinfo",
        &[("Authorization", bearer.as_str())],
        "",
    )
    .expect("an answer")
}

#[test]
fn a_session_is_kept_by_its_refresh_tokens_given_back_and_ended_on_the_real_binary() {
    let database = database::create_database(EMBEDDED);
    let node = prepare_realm(&database, support::saffui_command());

    // The access token says who signed in, as far as its scopes allow.
    let (first, _) = sign_in_for_tokens(&node);
    let told = ask_user_info(&node, first["access_token"].as_str().expect("a token"));
    assert_eq!(told.status, 200, "{}", told.body);
    assert_eq!(read_json(&told.body)["email"], "ada@example.org");

    // A refresh token is spent for the next one. Presented again, it takes
    // its whole family with it.
    let spent = first["refresh_token"].as_str().expect("a refresh token");
    let next = refresh(&node, spent);
    assert_eq!(next.status, 200, "{}", next.body);
    let next = read_json(&next.body)["refresh_token"]
        .as_str()
        .expect("the next refresh token")
        .to_owned();
    assert_ne!(next, spent);
    let replayed = refresh(&node, spent);
    assert_eq!(replayed.status, 400);
    assert_eq!(read_json(&replayed.body)["error"], "invalid_grant");
    assert_eq!(
        refresh(&node, &next).status,
        400,
        "the token that descends from the replayed one is gone too"
    );

    // Given back by its application, a refresh token is spent no more.
    let (second, session) = sign_in_for_tokens(&node);
    let given_back = format!(
        "client_id=portal&token={}",
        second["refresh_token"].as_str().expect("a refresh token")
    );
    let revoked = http::send_request(
        node.data,
        "POST",
        "/realms/acme/oauth2/revoke",
        &[FORM],
        &given_back,
    )
    .expect("an answer");
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    assert_eq!(
        refresh(
            &node,
            second["refresh_token"].as_str().expect("a refresh token")
        )
        .status,
        400
    );

    // The identity token of the session ends it at once, and the browser
    // goes back to the address the application registered.
    let path = format!(
        "/realms/acme/oauth2/logout?id_token_hint={}\
         &post_logout_redirect_uri=https%3A%2F%2Fapp.example.test%2Fgoodbye&state=bye",
        second["id_token"].as_str().expect("an identity token")
    );
    let out = http::send_request(node.data, "GET", &path, &[("Cookie", session.as_str())], "")
        .expect("an answer");
    assert_eq!(out.status, 303, "{}", out.body);
    assert_eq!(
        read_header(&out, "location"),
        Some("https://app.example.test/goodbye?state=bye")
    );
    let after = ask_user_info(&node, second["access_token"].as_str().expect("a token"));
    assert_eq!(
        after.status, 401,
        "the access token of an ended session tells nothing"
    );

    let (_, kinds) = read_passwords_and_events(&database);
    let counted = |kind: &str| kinds.iter().filter(|known| *known == kind).count();
    assert_eq!(
        counted("token.revoked"),
        2,
        "the replay and the giving back: {kinds:?}"
    );
    assert_eq!(counted("session.ended"), 1, "{kinds:?}");
}

/// The code an authenticator application shows for a secret at an instant:
/// the real one, of the real clock.
fn compute_code(typed_secret: &str, unix_seconds: u64) -> String {
    use crypto::otp::totp::{TotpParams, format_code, totp_at};
    use crypto::provider::HashAlg;
    use crypto::secrecy::SecretBox;

    let secret = data_encoding::BASE32_NOPAD
        .decode(typed_secret.as_bytes())
        .expect("a secret in base32");
    let provider = open_provider().expect("a provider");
    let code = totp_at(
        provider.hmac(),
        &SecretBox::new(Box::new(secret)),
        unix_seconds,
        TotpParams::new(HashAlg::Sha1),
    )
    .expect("a code");
    format_code(code, 6)
}

fn read_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
}

/// Starts a sign-in in a browser that has no session and gives the password.
/// Returns the pending request and its cookie: a code is owed next.
fn give_password_then_owe_a_code(node: &node::Node) -> (String, String) {
    let sent_to_login = http::get(node.data, &write_authorize_path()).expect("an answer");
    let login = read_header(&sent_to_login, "location")
        .expect("a location")
        .to_owned();
    let request = read_parameter(&login, "request").expect("a pending request");
    let flow = read_cookie(&sent_to_login, "saffui_flow_").expect("a flow cookie");
    let asked = http::send_request(
        node.data,
        "POST",
        "/realms/acme/login",
        &[FORM, ("Cookie", &flow), ("Origin", node::PUBLIC_ORIGIN)],
        &format!("request={request}&username=ada&password=correct+horse+battery"),
    )
    .expect("an answer");
    assert_eq!(asked.status, 200, "{}", asked.body);
    assert!(asked.body.contains("name=\"code\""), "{}", asked.body);
    assert!(
        read_cookie(&asked, "saffui_session_acme=").is_none(),
        "no session before the code"
    );
    (request, flow)
}

fn give_code(node: &node::Node, request: &str, flow: &str, code: &str) -> http::Answer {
    http::send_request(
        node.data,
        "POST",
        "/realms/acme/login",
        &[FORM, ("Cookie", flow), ("Origin", node::PUBLIC_ORIGIN)],
        &format!("request={request}&code={code}"),
    )
    .expect("an answer")
}

#[test]
fn a_person_sets_up_an_authenticator_owes_its_codes_and_an_administrator_takes_it_away() {
    let database = database::create_database(EMBEDDED);
    let (node, operator) = prepare_realm_with_operator(&database, support::saffui_command());
    let (_, session) = sign_in(&node, PASSWORD);
    let session = session.expect("a session cookie");
    let browser = [
        FORM,
        ("Cookie", session.as_str()),
        ("Origin", node::PUBLIC_ORIGIN),
    ];

    // A secret shown once, then the password and a first code.
    let authenticator = "/realms/acme/account/authenticator";
    let offered =
        http::send_request(node.data, "POST", authenticator, &browser, "").expect("an answer");
    assert_eq!(offered.status, 200, "{}", offered.body);
    let secret = offered
        .body
        .split_once("<code id=\"secret\">")
        .and_then(|(_, rest)| rest.split_once("</code>"))
        .map(|(secret, _)| secret.to_owned())
        .expect("the secret is shown");
    let enrolled_at = read_unix_seconds();
    let first_code = compute_code(&secret, enrolled_at);
    let confirmed = http::send_request(
        node.data,
        "POST",
        "/realms/acme/account/authenticator/confirm",
        &browser,
        &format!("password=correct+horse+battery&code={first_code}"),
    )
    .expect("an answer");
    assert_eq!(confirmed.status, 200, "{}", confirmed.body);

    // Signing in now takes the password, then a code. The code that
    // confirmed is spent: whoever read it over a shoulder gets nothing.
    let (request, flow) = give_password_then_owe_a_code(&node);
    let replayed = give_code(&node, &request, &flow, &first_code);
    assert_eq!(replayed.status, 401, "{}", replayed.body);
    assert!(read_header(&replayed, "location").is_none());

    // The code of the next half minute is one the window allows already.
    let next_code = compute_code(&secret, enrolled_at + 30);
    let signed_in = give_code(&node, &request, &flow, &next_code);
    assert_eq!(signed_in.status, 303, "{}", signed_in.body);
    let location = read_header(&signed_in, "location").expect("a location");
    let code = read_parameter(location, "code").expect("a code");
    let tokens = read_json(&exchange_code(&node, &code, VERIFIER).body);
    let (_, identity) =
        verify_with_published_keys(&node, tokens["id_token"].as_str().expect("an ID token"));
    assert_eq!(identity["amr"], json!(["pwd", "otp", "mfa"]));

    // The person lost the device: an administrator takes it away.
    let granted = http::send_request(
        node.data,
        "POST",
        TOKEN,
        &[("Authorization", &operator), FORM],
        "grant_type=client_credentials",
    )
    .expect("an answer");
    let bearer = format!(
        "Bearer {}",
        read_json(&granted.body)["access_token"]
            .as_str()
            .expect("a token")
    );
    let head = [JSON, ("Authorization", bearer.as_str())];
    let listed = http::send_request(node.data, "GET", "/admin/v1/realms/acme/users", &head, "")
        .expect("an answer");
    let person = read_json(&listed.body)["items"][0]["id"]
        .as_str()
        .expect("the identifier of ada")
        .to_owned();
    let removed = http::send_request(
        node.data,
        "DELETE",
        &format!("/admin/v1/realms/acme/users/{person}/authenticator"),
        &head,
        "",
    )
    .expect("an answer");
    assert_eq!(removed.status, 204, "{}", removed.body);

    let (back, _) = sign_in(&node, PASSWORD);
    assert_eq!(
        back.status, 303,
        "the password is enough again: {}",
        back.body
    );
    let location = read_header(&back, "location").expect("a location");
    let code = read_parameter(location, "code").expect("a code");
    let tokens = read_json(&exchange_code(&node, &code, VERIFIER).body);
    let (_, identity) =
        verify_with_published_keys(&node, tokens["id_token"].as_str().expect("an ID token"));
    assert_eq!(identity["amr"], json!(["pwd"]));
}

const SECURITY_KEY: &str = "/realms/acme/account/security-key";
const CONFIRM_KEY: &str = "/realms/acme/account/security-key/confirm";
const LOGIN_PAGE: &str = "/realms/acme/login";
/// Where a page that imitates ours stands.
const LOOKALIKE: &str = "http://localhost.evil.example:8080";

/// Reads what a page hands to the browser for a key, out of its attribute.
fn read_key_options(page: &str) -> Value {
    let written = page
        .split_once("data-options=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(found, _)| found)
        .expect("the options of a key");
    let text = written
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    serde_json::from_str(&text).expect("options written as JSON")
}

/// The `Authorization` header of a token the operator asked for itself.
fn ask_operator_token(node: &node::Node, operator: &str) -> String {
    let granted = http::send_request(
        node.data,
        "POST",
        TOKEN,
        &[("Authorization", operator), FORM],
        "grant_type=client_credentials",
    )
    .expect("an answer");
    format!(
        "Bearer {}",
        read_json(&granted.body)["access_token"]
            .as_str()
            .expect("a token")
    )
}

/// The identifier of the one person of the realm, as the administration lists it.
fn find_only_person(node: &node::Node, bearer: &str) -> String {
    let listed = http::send_request(
        node.data,
        "GET",
        "/admin/v1/realms/acme/users",
        &[JSON, ("Authorization", bearer)],
        "",
    )
    .expect("an answer");
    read_json(&listed.body)["items"][0]["id"]
        .as_str()
        .expect("the identifier of ada")
        .to_owned()
}

/// Writes the answer of a key as its form carries it.
fn write_key_field(answer: &Value) -> String {
    let written: String = answer
        .to_string()
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect();
    format!("key={written}")
}

/// Gives the password on the page that adds a key, and returns what the
/// key is asked.
fn ask_to_add_a_key(node: &node::Node, browser: &[(&str, &str)]) -> Value {
    let asked = http::send_request(
        node.data,
        "POST",
        SECURITY_KEY,
        browser,
        "password=correct+horse+battery",
    )
    .expect("an answer");
    assert_eq!(asked.status, 200, "{}", asked.body);
    assert!(asked.body.contains("data-ceremony=\"create\""));
    read_key_options(&asked.body)
}

/// Starts a sign-in in a browser that has no session, gives the password,
/// and returns the pending request, its cookie and what the key is asked.
fn give_password_then_owe_a_key(node: &node::Node) -> (String, String, Value) {
    let sent_to_login = http::get(node.data, &write_authorize_path()).expect("an answer");
    let login = read_header(&sent_to_login, "location")
        .expect("a location")
        .to_owned();
    let request = read_parameter(&login, "request").expect("a pending request");
    let flow = read_cookie(&sent_to_login, "saffui_flow_").expect("a flow cookie");
    let asked = http::send_request(
        node.data,
        "POST",
        LOGIN_PAGE,
        &[FORM, ("Cookie", &flow), ("Origin", node::PUBLIC_ORIGIN)],
        &format!("request={request}&username=ada&password=correct+horse+battery"),
    )
    .expect("an answer");
    assert_eq!(asked.status, 200, "{}", asked.body);
    assert!(
        asked.body.contains("data-ceremony=\"get\""),
        "{}",
        asked.body
    );
    assert!(
        read_cookie(&asked, "saffui_session_acme=").is_none(),
        "no session before the key"
    );
    let options = read_key_options(&asked.body);
    (request, flow, options)
}

fn give_key_answer(node: &node::Node, request: &str, flow: &str, answer: &Value) -> http::Answer {
    http::send_request(
        node.data,
        "POST",
        LOGIN_PAGE,
        &[FORM, ("Cookie", flow), ("Origin", node::PUBLIC_ORIGIN)],
        &format!("request={request}&{}", write_key_field(answer)),
    )
    .expect("an answer")
}

/// Reads how the person of an ID token signed in, once its code is exchanged.
fn read_methods(node: &node::Node, signed_in: &http::Answer) -> Value {
    let location = read_header(signed_in, "location").expect("a location");
    let code = read_parameter(location, "code").expect("a code");
    let tokens = read_json(&exchange_code(node, &code, VERIFIER).body);
    let (_, identity) =
        verify_with_published_keys(node, tokens["id_token"].as_str().expect("an ID token"));
    identity["amr"].clone()
}

#[test]
fn a_person_adds_a_security_key_owes_its_answer_and_an_administrator_takes_it_away() {
    let database = database::create_database(EMBEDDED);
    let (node, operator) = prepare_realm_with_operator(&database, support::saffui_command());
    let (_, session) = sign_in(&node, PASSWORD);
    let session = session.expect("a session cookie");
    let browser = [
        FORM,
        ("Cookie", session.as_str()),
        ("Origin", node::PUBLIC_ORIGIN),
    ];
    let mut key = SoftKey::make();

    // The person adds the key: their password, then the key answers. An
    // answer made for a page that imitates ours adds nothing, and spends
    // what was started.
    let options = ask_to_add_a_key(&node, &browser);
    assert_eq!(options["publicKey"]["rp"]["id"], "localhost");
    let imitated = http::send_request(
        node.data,
        "POST",
        CONFIRM_KEY,
        &browser,
        &write_key_field(&key.attest(&options, LOOKALIKE)),
    )
    .expect("an answer");
    assert_eq!(imitated.status, 400, "{}", imitated.body);
    let spent = http::send_request(
        node.data,
        "POST",
        CONFIRM_KEY,
        &browser,
        &write_key_field(&key.attest(&options, node::PUBLIC_ORIGIN)),
    )
    .expect("an answer");
    assert_eq!(spent.status, 400, "{}", spent.body);
    let options = ask_to_add_a_key(&node, &browser);
    let added = http::send_request(
        node.data,
        "POST",
        CONFIRM_KEY,
        &browser,
        &write_key_field(&key.attest(&options, node::PUBLIC_ORIGIN)),
    )
    .expect("an answer");
    assert_eq!(added.status, 200, "{}", added.body);

    // Signing in now takes the password, then the key. What the key signs
    // for a page that imitates ours serves nowhere.
    let (request, flow, options) = give_password_then_owe_a_key(&node);
    assert_eq!(
        options["publicKey"]["allowCredentials"][0]["id"],
        key.name_credential()
    );
    let imitated = give_key_answer(&node, &request, &flow, &key.answer(&options, LOOKALIKE));
    assert_eq!(imitated.status, 401, "{}", imitated.body);
    assert!(read_header(&imitated, "location").is_none());
    let signed_in = give_key_answer(
        &node,
        &request,
        &flow,
        &key.answer(&options, node::PUBLIC_ORIGIN),
    );
    assert_eq!(signed_in.status, 303, "{}", signed_in.body);
    assert_eq!(
        read_methods(&node, &signed_in),
        json!(["pwd", "pop", "mfa"])
    );

    // A copy of the key that was used less than the key is told by its counter.
    let (request, flow, options) = give_password_then_owe_a_key(&node);
    let used = key.counter;
    key.counter = 0;
    let copied = give_key_answer(
        &node,
        &request,
        &flow,
        &key.answer(&options, node::PUBLIC_ORIGIN),
    );
    assert_eq!(copied.status, 401, "{}", copied.body);
    key.counter = used;
    let signed_in = give_key_answer(
        &node,
        &request,
        &flow,
        &key.answer(&options, node::PUBLIC_ORIGIN),
    );
    assert_eq!(signed_in.status, 303, "{}", signed_in.body);

    // The person lost the key: an administrator takes it away.
    let bearer = ask_operator_token(&node, &operator);
    let person = find_only_person(&node, &bearer);
    let removed = http::send_request(
        node.data,
        "DELETE",
        &format!("/admin/v1/realms/acme/users/{person}/security-keys"),
        &[JSON, ("Authorization", bearer.as_str())],
        "",
    )
    .expect("an answer");
    assert_eq!(removed.status, 204, "{}", removed.body);

    let (back, _) = sign_in(&node, PASSWORD);
    assert_eq!(
        back.status, 303,
        "the password is enough again: {}",
        back.body
    );
    assert_eq!(read_methods(&node, &back), json!(["pwd"]));
}
