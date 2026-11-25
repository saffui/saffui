//! A journey through the real binary: an administrator registers an
//! application that signs each of its requests with its key, the binary
//! refuses it any other, and a request it signed leads a person through the
//! sign-in page to a code, then to tokens, and never proves the application.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use crypto::adapters::digest::ProviderDigester;
use crypto::adapters::open_provider;
use crypto::adapters::sign::JoseSigner;
use pgcore::APP_ROLE;
use pgcore::migrate::EMBEDDED;
use saffui_core::ports::crypto::{Digester, GeneratedSigningKey, SignatureAlgorithm, Signer};
use serde_json::{Value, json};

use crate::support::http::{read_cookie, read_header, read_parameter};
use crate::support::{self, database, http, node, read_json};

const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");
const JSON: (&str, &str) = ("Content-Type", "application/json");
const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CALLBACK: &str = "https://app.example.test/callback";
const ISSUER: &str = "http://localhost:8080/realms/acme";
const TOKEN: &str = "/realms/acme/oauth2/token";
const ASSERTION_TYPE: &str = "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer";

fn read_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

/// Signs `claims` with `key`, under a header of `typ` that names the key.
fn sign(
    signer: &JoseSigner,
    key: &GeneratedSigningKey,
    typ: Option<&str>,
    claims: &Value,
) -> String {
    let mut header = json!({ "alg": key.algorithm.name(), "kid": key.key_id });
    if let Some(typ) = typ {
        header["typ"] = json!(typ);
    }
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = signer
        .sign(key.algorithm, &key.private_key, input.as_bytes())
        .expect("a signature");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// The realm `acme`, the person `ada`, and the application `signed-app`,
/// which proves itself with `key` and signs each of its requests with it.
fn prepare_realm(
    database: &pgcore::testkit::TestDatabase,
    key: &GeneratedSigningKey,
) -> node::Node {
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
        "client_id": "signed-app",
        "scopes": ["openid", "email"],
        "redirect_uris": [CALLBACK],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": { "keys": [key.public_jwk] },
        "request_object_signing_alg": "ES256",
        "require_signed_request_object": true,
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
    node
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one journey, read from top to bottom"
)]
fn a_request_an_application_signed_leads_to_a_code_then_to_tokens_and_no_other_is_heard() {
    let database = database::create_database(EMBEDDED);
    let signer = JoseSigner::new(open_provider().expect("a provider"));
    let key = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime")
        .block_on(signer.generate_key(SignatureAlgorithm::Es256, Box::new(())))
        .expect("a key");
    let node = prepare_realm(&database, &key);
    let digester = ProviderDigester::new(open_provider().expect("a provider"));
    let challenge = URL_SAFE_NO_PAD.encode(digester.sha256(VERIFIER.as_bytes()));

    let unsigned = format!(
        "/realms/acme/oauth2/authorize?response_type=code&client_id=signed-app\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&scope=openid&state=xyz\
         &code_challenge={challenge}&code_challenge_method=S256"
    );
    let refused = http::get(node.data, &unsigned).expect("an answer");
    assert_eq!(refused.status, 303, "{}", refused.body);
    let back = read_header(&refused, "location").expect("a location");
    assert!(back.starts_with(CALLBACK), "{back}");
    assert_eq!(
        read_parameter(back, "error").as_deref(),
        Some("invalid_request")
    );

    let now = read_now();
    let claims = json!({
        "iss": "signed-app",
        "aud": ISSUER,
        "client_id": "signed-app",
        "exp": now + 300,
        "iat": now,
        "response_type": "code",
        "redirect_uri": CALLBACK,
        "scope": "openid email",
        "state": "signed-state",
        "nonce": "signed-nonce",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    });
    let request = sign(&signer, &key, Some("oauth-authz-req+jwt"), &claims);
    let sent = http::get(
        node.data,
        &format!("/realms/acme/oauth2/authorize?client_id=signed-app&scope=openid%20email&request={request}"),
    )
    .expect("an answer");
    assert_eq!(sent.status, 303, "{}", sent.body);
    let login = read_header(&sent, "location")
        .expect("a location")
        .to_owned();
    assert!(login.starts_with("/realms/acme/login?"), "{login}");
    let pending = read_parameter(&login, "request").expect("a pending request");
    let flow = read_cookie(&sent, "saffui_flow_").expect("a flow cookie");
    let form = format!(
        "request={pending}&username=ada&password={}",
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
    assert!(back.starts_with(&format!("{CALLBACK}?code=")), "{back}");
    assert_eq!(
        read_parameter(back, "state").as_deref(),
        Some("signed-state")
    );
    let code = read_parameter(back, "code").expect("a code");

    let assertion = sign(
        &signer,
        &key,
        None,
        &json!({
            "iss": "signed-app",
            "sub": "signed-app",
            "aud": ISSUER,
            "jti": "exchange-1",
            "exp": now + 60,
            "iat": now,
        }),
    );
    let exchange = format!(
        "grant_type=authorization_code&code={code}\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&code_verifier={VERIFIER}\
         &client_assertion_type={ASSERTION_TYPE}&client_assertion={assertion}"
    );
    let granted =
        http::send_request(node.data, "POST", TOKEN, &[FORM], &exchange).expect("an answer");
    assert_eq!(granted.status, 200, "{}", granted.body);
    let tokens = read_json(&granted.body);
    assert_eq!(tokens["scope"], "openid email");
    let id_token = tokens["id_token"].as_str().expect("an identity token");
    let identity = read_json(
        &String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(id_token.split('.').nth(1).expect("claims"))
                .expect("base64url"),
        )
        .expect("text"),
    );
    assert_eq!(identity["aud"], "signed-app");
    assert_eq!(
        identity["nonce"], "signed-nonce",
        "the nonce the request signed"
    );
}

#[test]
fn a_request_an_application_signed_proves_nothing_at_the_token_endpoint_typed_or_not() {
    let database = database::create_database(EMBEDDED);
    let signer = JoseSigner::new(open_provider().expect("a provider"));
    let key = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime")
        .block_on(signer.generate_key(SignatureAlgorithm::Es256, Box::new(())))
        .expect("a key");
    let node = prepare_realm(&database, &key);
    let now = read_now();

    // Every claim an assertion of the application needs, and those of a request.
    for (typ, jti) in [
        (Some("oauth-authz-req+jwt"), "object-1"),
        (None, "object-2"),
    ] {
        let request = sign(
            &signer,
            &key,
            typ,
            &json!({
                "iss": "signed-app",
                "sub": "signed-app",
                "aud": ISSUER,
                "jti": jti,
                "exp": now + 300,
                "iat": now,
                "client_id": "signed-app",
                "response_type": "code",
                "redirect_uri": CALLBACK,
                "scope": "openid",
            }),
        );
        let refresh = format!(
            "grant_type=refresh_token&refresh_token=unknown\
             &client_assertion_type={ASSERTION_TYPE}&client_assertion={request}"
        );

        let refused =
            http::send_request(node.data, "POST", TOKEN, &[FORM], &refresh).expect("an answer");

        assert_eq!(refused.status, 401, "{typ:?}: {}", refused.body);
        assert_eq!(
            read_json(&refused.body)["error"],
            "invalid_client",
            "{typ:?}"
        );
    }
}
