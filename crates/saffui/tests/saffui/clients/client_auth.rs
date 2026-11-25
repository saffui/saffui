//! Journeys through the real binary: clients prove themselves with
//! assertions signed by their secret or by their key, once each, their keys
//! are read at registration as a verification reads them, and an
//! administrator turns a secret over.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use crypto::adapters::digest::ProviderDigester;
use crypto::adapters::open_provider;
use crypto::adapters::sign::JoseSigner;
use crypto::jose::jwk::KeyPair as _;
use crypto::jose::jwk::alg::ed::{EdCurve, EdKeyPair};
use pgcore::APP_ROLE;
use pgcore::migrate::EMBEDDED;
use pgcore::testkit::TestDatabase;
use saffui_core::ports::crypto::{Digester, GeneratedSigningKey, SignatureAlgorithm, Signer};
use saffui_core::secret::Secret;
use serde_json::{Value, json};

use crate::support::jws::write_input;
use crate::support::{self, database, http, node, read_json};

const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");
const JSON: (&str, &str) = ("Content-Type", "application/json");
const TOKEN: &str = "/realms/acme/oauth2/token";
const CLIENTS: &str = "/admin/v1/realms/acme/clients";
const ASSERTION_TYPE: &str = "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer";
const ISSUER: &str = "http://localhost:8080/realms/acme";

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

fn ask_in_basic(node: &node::Node, client_id: &str, secret: &str) -> http::Answer {
    let basic = format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")));
    http::send_request(
        node.data,
        "POST",
        TOKEN,
        &[("Authorization", &basic), FORM],
        "grant_type=client_credentials",
    )
    .expect("an answer")
}

/// The bearer of a token of the administrator.
fn start_administering(node: &node::Node, secret: &str) -> String {
    let granted = ask_in_basic(node, "operator", secret);
    assert_eq!(granted.status, 200, "{}", granted.body);
    format!(
        "Bearer {}",
        read_json(&granted.body)["access_token"]
            .as_str()
            .expect("a token")
    )
}

fn call(node: &node::Node, bearer: &str, path: &str, body: &str) -> http::Answer {
    http::send_request(
        node.data,
        "POST",
        path,
        &[JSON, ("Authorization", bearer)],
        body,
    )
    .expect("an answer")
}

fn write_claims(client_id: &str, jti: &str, audience: &str) -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs();
    json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "jti": jti,
        "exp": now + 60,
        "iat": now,
    })
}

fn sign_with_secret(secret: &str, claims: &Value) -> String {
    let input = write_input(&json!({ "alg": "HS256" }), claims);
    let mac = ProviderDigester::new(open_provider().expect("a provider"))
        .hmac_sha256(&Secret::new(secret.as_bytes().to_vec()), input.as_bytes())
        .expect("a mac");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(mac))
}

fn sign_with_key(signer: &JoseSigner, key: &GeneratedSigningKey, claims: &Value) -> String {
    let header = json!({ "alg": key.algorithm.name(), "kid": key.key_id });
    let input = write_input(&header, claims);
    let signature = signer
        .sign(key.algorithm, &key.private_key, input.as_bytes())
        .expect("a signature");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn present(node: &node::Node, assertion: &str) -> http::Answer {
    let form = format!(
        "grant_type=client_credentials&client_assertion_type={ASSERTION_TYPE}\
         &client_assertion={assertion}"
    );
    http::send_request(node.data, "POST", TOKEN, &[FORM], &form).expect("an answer")
}

fn make_key(signer: &JoseSigner, algorithm: SignatureAlgorithm) -> GeneratedSigningKey {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime")
        .block_on(signer.generate_key(algorithm, Box::new(())))
        .expect("a key")
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one journey, read from top to bottom"
)]
fn clients_prove_themselves_with_assertions_signed_by_their_secret_or_their_key_once() {
    let database = database::create_database(EMBEDDED);
    let secret = bootstrap_with_administrator(&database);
    let node = node::Node::start(support::saffui_command(), &database);
    let bearer = start_administering(&node, &secret);
    let discovery = read_json(
        &http::get(node.data, "/realms/acme/.well-known/openid-configuration")
            .expect("an answer")
            .body,
    );
    assert_eq!(
        discovery["token_endpoint_auth_signing_alg_values_supported"][0],
        "HS256"
    );

    // By a secret the realm keeps sealed, to check the signature with.
    let created = call(
        &node,
        &bearer,
        CLIENTS,
        &json!({
            "client_id": "signer",
            "scopes": ["reports:read"],
            "token_endpoint_auth_method": "client_secret_jwt",
        })
        .to_string(),
    );
    assert_eq!(created.status, 201, "{}", created.body);
    let created = read_json(&created.body);
    assert_eq!(
        created["client"]["token_endpoint_auth_method"],
        "client_secret_jwt"
    );
    let signer_secret = created["client_secret"]
        .as_str()
        .expect("a secret, shown once");
    let assertion = sign_with_secret(signer_secret, &write_claims("signer", "s-1", ISSUER));
    let answered = present(&node, &assertion);
    assert_eq!(answered.status, 200, "{}", answered.body);
    assert_eq!(read_json(&answered.body)["scope"], "reports:read");
    let replayed = present(&node, &assertion);
    assert_eq!(replayed.status, 401, "an assertion serves once");
    assert_eq!(read_json(&replayed.body)["error"], "invalid_client");
    let to_the_endpoint = sign_with_secret(
        signer_secret,
        &write_claims("signer", "s-2", &format!("{ISSUER}/oauth2/token")),
    );
    assert_eq!(
        present(&node, &to_the_endpoint).status,
        401,
        "addressed to the token endpoint, not to the realm"
    );

    // By a key it registered: the realm keeps only its public half.
    let signer = JoseSigner::new(open_provider().expect("a provider"));
    let key = make_key(&signer, SignatureAlgorithm::Es256);
    let created = call(
        &node,
        &bearer,
        CLIENTS,
        &json!({
            "client_id": "keyed",
            "scopes": ["reports:read"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": { "keys": [key.public_jwk] },
        })
        .to_string(),
    );
    assert_eq!(created.status, 201, "{}", created.body);
    assert!(
        read_json(&created.body).get("client_secret").is_none(),
        "{}",
        created.body
    );
    let answered = present(
        &node,
        &sign_with_key(&signer, &key, &write_claims("keyed", "k-1", ISSUER)),
    );
    assert_eq!(answered.status, 200, "{}", answered.body);

    // An RSA key that names no algorithm is given one: only an assertion
    // of it is verified by it.
    let rsa = make_key(&signer, SignatureAlgorithm::Rs256);
    let mut unnamed = rsa.public_jwk.clone();
    unnamed
        .as_object_mut()
        .expect("an object")
        .remove("alg")
        .expect("a named algorithm");
    let created = call(
        &node,
        &bearer,
        CLIENTS,
        &json!({
            "client_id": "unnamed",
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": { "keys": [unnamed] },
        })
        .to_string(),
    );
    assert_eq!(created.status, 201, "{}", created.body);
    let answered = present(
        &node,
        &sign_with_key(&signer, &rsa, &write_claims("unnamed", "r-1", ISSUER)),
    );
    assert_eq!(answered.status, 200, "{}", answered.body);

    // A key a verification would refuse is refused before it is kept.
    let mut modulus = vec![0_u8; 256];
    modulus[0] = 0x80;
    modulus[255] = 1;
    let costly = json!({
        "kty": "RSA",
        "n": URL_SAFE_NO_PAD.encode(&modulus),
        "e": "Aw",
        "alg": "RS256",
    });
    let mut on_ed448 = Value::Object(
        EdKeyPair::generate(EdCurve::Ed448)
            .expect("a pair")
            .to_jwk_public_key()
            .into(),
    );
    on_ed448["alg"] = json!("EdDSA");
    for (wanted, why) in [
        (
            json!({ "jwks": { "keys": [costly] } }),
            "an RSA key of the exponent 3",
        ),
        (
            json!({ "jwks": { "keys": [on_ed448] } }),
            "a key of EdDSA on Ed448",
        ),
        (
            json!({ "jwks_uri": "https://keys.example.org/jwks" }),
            "an address of keys",
        ),
    ] {
        let mut wanted = wanted;
        wanted["client_id"] = json!("careless");
        wanted["token_endpoint_auth_method"] = json!("private_key_jwt");
        let refused = call(&node, &bearer, CLIENTS, &wanted.to_string());
        assert_eq!(refused.status, 400, "{why}: {}", refused.body);
        assert_eq!(
            read_json(&refused.body)["code"],
            "client.jwks_invalid",
            "{why}"
        );
    }

    // A secret turned over is shown once, kept by no cache, and the one it
    // replaces proves nothing from then on.
    let created = call(
        &node,
        &bearer,
        CLIENTS,
        &json!({ "client_id": "billing", "scopes": ["invoices:read"] }).to_string(),
    );
    assert_eq!(created.status, 201, "{}", created.body);
    let old = read_json(&created.body)["client_secret"]
        .as_str()
        .expect("a secret")
        .to_owned();
    let rotated = call(&node, &bearer, &format!("{CLIENTS}/billing/secret"), "");
    assert_eq!(rotated.status, 200, "{}", rotated.body);
    let head = rotated.head.to_lowercase();
    assert!(
        head.contains("cache-control: no-store") && head.contains("pragma: no-cache"),
        "{}",
        rotated.head
    );
    let new = read_json(&rotated.body)["client_secret"]
        .as_str()
        .expect("the new secret, shown once")
        .to_owned();
    assert_eq!(ask_in_basic(&node, "billing", &new).status, 200);
    assert_eq!(
        ask_in_basic(&node, "billing", &old).status,
        401,
        "the old secret proves nothing"
    );
}
