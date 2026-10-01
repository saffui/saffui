#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use super::wallet::{
    Wallet, answered, asked, encrypted, fetched, mint_request_key, name_pid_issuer, path_of,
    pid_query, plane_that_verifies, standing_of,
};
use actix_web::http::{Method, StatusCode};
use crypto::jose::jwk::KeyPair;
use crypto::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
use crypto::jose::jwk::alg::rsa::RsaKeyPair;
use crypto::provider::{CryptoProvider, HashAlg, PrivateKey, PublicKey};
use crypto::x509::{Issuance, issue_authority_certificate, issue_certificate};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use serde_json::{Map, Value, json};
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;

const NO_CERTIFICATE: &str = "the realm holds no certificate valid now to present itself by: \
                              take one for its verifier key first";

fn verifier_path() -> String {
    format!("/admin/realms/{REALM}/verifier")
}

/// An authority's hierarchy, as an access certificate authority holds one:
/// a root, and the intermediate that certifies verifiers' keys.
struct Authority {
    intermediate_key: RsaKeyPair,
    root: Vec<u8>,
    intermediate: Vec<u8>,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn authority() -> Authority {
    let (root_key, intermediate_key) = (
        RsaKeyPair::generate(2048).expect("a root key"),
        RsaKeyPair::generate(2048).expect("an intermediate key"),
    );
    let issued = |subject: &RsaKeyPair, name: &str, issuer: &RsaKeyPair, issuer_name: &str| {
        issue_authority_certificate(&Issuance {
            subject_key: &PublicKey::from_der(subject.to_der_public_key()),
            subject_name: name,
            issuer_key: &PrivateKey::from_der(issuer.to_der_private_key()),
            issuer_name,
            serial: &[1],
            not_before: now() - 3_600,
            not_after: now() + 365 * 86_400,
        })
        .expect("an authority issued by the crypto crate")
    };
    Authority {
        root: issued(&root_key, "Access Root", &root_key, "Access Root"),
        intermediate: issued(&intermediate_key, "Access CA", &root_key, "Access Root"),
        intermediate_key,
    }
}

impl Authority {
    /// The access certificate for the key a realm drew, as its public JWK
    /// names it.
    fn certify(&self, public_jwk: &Value, name: &str) -> Vec<u8> {
        let key = crypto::public_jwk::public_key_from_jwk(public_jwk.as_object().expect("a JWK"))
            .expect("a P-256 key");
        issue_certificate(&Issuance {
            subject_key: &key,
            subject_name: name,
            issuer_key: &PrivateKey::from_der(self.intermediate_key.to_der_private_key()),
            issuer_name: "Access CA",
            serial: &[2],
            not_before: now() - 60,
            not_after: now() + 90 * 86_400,
        })
        .expect("a certificate issued by the crypto crate")
    }

    /// What an operator pastes: the certificate, then its authorities, the
    /// root included.
    fn pasted(&self, leaf: &[u8]) -> String {
        [leaf, &self.intermediate, &self.root]
            .iter()
            .map(|der| support::pem_certificate(der))
            .collect()
    }
}

/// The client identifier a certificate gives: `x509_hash:` and the base64url
/// SHA-256 of the leaf, as OpenID4VP 1.0 §5.9.3 has a wallet compute it.
fn x509_hash_of(leaf: &[u8]) -> String {
    let digest = support::provider()
        .digest()
        .hash(HashAlg::Sha256, leaf)
        .expect("a digest");
    format!("x509_hash:{}", BASE64URL_NOPAD.encode(&digest))
}

fn subject() -> Value {
    json!({
        "common_name": "Acme verifier",
        "organization": "Acme SA",
        "organization_identifier": "VATFR-12345678901",
        "country": "FR",
    })
}

fn registrar_dataset() -> Value {
    json!({
        "identifier": [
            { "type": "http://data.europa.eu/eudi/id/VATIN", "identifier": "FR12345678901" }
        ],
        "srvDescription": [
            { "lang": "en", "content": "Account opening" },
            { "lang": "fr", "content": "Ouverture de compte" }
        ],
        "registryURI": "https://registrar.example/api",
        "intendedUseIdentifier": "account-opening",
        "purpose": [{ "lang": "en", "content": "Know your customer" }],
        "policyURI": "https://acme.example/privacy",
    })
}

/// A registration certificate as a registrar signs one (TS 119 475 §5.2):
/// typed, its chain in `x5c`, naming the relying party and when it was
/// issued.
fn registration_certificate(authority: &Authority) -> String {
    use crypto::jose::jws::{ES256, JwsHeader};
    let registrar = EcKeyPair::generate(EcCurve::P256).expect("a registrar key");
    let sealed = issue_certificate(&Issuance {
        subject_key: &PublicKey::from_der(registrar.to_der_public_key()),
        subject_name: "Registrar",
        issuer_key: &PrivateKey::from_der(authority.intermediate_key.to_der_private_key()),
        issuer_name: "Access CA",
        serial: &[3],
        not_before: now() - 60,
        not_after: now() + 365 * 86_400,
    })
    .expect("a certificate issued by the crypto crate");
    let mut header = JwsHeader::new();
    header.set_token_type("rc-wrp+jwt");
    header.set_x509_certificate_chain(&[sealed]);
    let claims = json!({
        "sub": "VATFR-12345678901",
        "name": "Acme verifier",
        "country": "FR",
        "registry_uri": "https://registrar.example/api",
        "iat": now(),
        "exp": now() + 180 * 86_400,
    });
    let signer = ES256
        .signer_from_pem(registrar.to_pem_private_key())
        .expect("a registrar signer");
    crypto::jose::jws::serialize_compact(claims.to_string().as_bytes(), &header, &signer)
        .expect("signed")
}

/// Draw a key and its certificate request, as the administrator does.
async fn request_certificate(plane: &Plane, bearer: &str) -> Value {
    let (status, drawn) = asked(
        plane,
        Method::POST,
        &format!("{}/keys", verifier_path()),
        bearer,
        Some(subject()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{drawn}");
    drawn
}

/// Take what the authority issued for the key awaiting its certificate.
async fn take_certificate(plane: &Plane, bearer: &str, chain: String) -> (StatusCode, Value) {
    asked(
        plane,
        Method::POST,
        &format!("{}/certificate", verifier_path()),
        bearer,
        Some(json!({ "chain": chain })),
    )
    .await
}

async fn present_as(plane: &Plane, bearer: &str, settings: Value) -> (StatusCode, Value) {
    asked(plane, Method::PUT, &verifier_path(), bearer, Some(settings)).await
}

/// A realm presenting itself by a certificate the authority issued for its
/// key, which the realm drew. Hands back the leaf.
async fn present_by_certificate(plane: &Plane, bearer: &str, authority: &Authority) -> Vec<u8> {
    let drawn = request_certificate(plane, bearer).await;
    let leaf = authority.certify(&drawn["public_jwk"], "Acme verifier");
    let (status, told) = take_certificate(plane, bearer, authority.pasted(&leaf)).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, told) = present_as(plane, bearer, json!({ "identity": "x509-hash" })).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    leaf
}

/// Read a request the way the EUDI wallets' library does: fetch it at the
/// address the link gives, take the client identifier for the hash of the
/// certificate the request carries first, find that certificate chained to
/// the authority the wallet trusts, and verify the request under its key.
async fn read_certified_request(
    plane: &Plane,
    link: &str,
    authority: &Authority,
) -> (Map<String, Value>, Map<String, Value>) {
    use crypto::jose::jws::ES256;
    let link = url::Url::parse(link).expect("an openid4vp link");
    let given = |name: &str| {
        link.query_pairs()
            .find(|(held, _)| held == name)
            .map(|(_, value)| value.into_owned())
            .unwrap_or_else(|| panic!("a link without {name}"))
    };
    let (status, signed) = fetched(plane, Method::GET, &path_of(&given("request_uri")), None).await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    let Value::Object(header) = serde_json::from_slice(
        &BASE64URL_NOPAD
            .decode(signed.split('.').next().expect("a header").as_bytes())
            .expect("base64url"),
    )
    .expect("a JSON header") else {
        panic!("a header that is not an object")
    };
    let chain: Vec<Vec<u8>> = header["x5c"]
        .as_array()
        .expect("an x5c header")
        .iter()
        .map(|written| {
            BASE64
                .decode(written.as_str().expect("base64").as_bytes())
                .expect("standard base64")
        })
        .collect();
    assert_eq!(
        chain[1..],
        [authority.intermediate.as_slice()],
        "the chain does not lead to the authority, or carries its root"
    );
    assert_eq!(given("client_id"), x509_hash_of(&chain[0]));
    let key = crypto::x509::public_key_of(&chain[0]).expect("a certified key");
    let verifier = ES256.verifier_from_der(key.der()).expect("a verifier");
    let (payload, _) = crypto::jose::jws::deserialize_compact(&signed, &verifier)
        .expect("a request signed under the certified key");
    let Value::Object(request) = serde_json::from_slice(&payload).expect("a JSON request") else {
        panic!("a request that is not an object")
    };
    assert_eq!(request["client_id"], given("client_id").as_str());
    (header, request)
}

/// A realm draws a key and the request an authority certifies it from, takes
/// the chain issued for that key and no other, and then presents itself by
/// it: its requests signed ES256 under the certificate, named by its hash,
/// carrying what its registrar holds of it; a wallet's answer bound to that
/// name verifies. No Ed25519 key is needed while it presents itself so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_presents_itself_by_the_certificate_issued_for_its_key() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = name_pid_issuer(&plane, &bearer).await;
    let authority = authority();

    let (status, held) = asked(&plane, Method::GET, &verifier_path(), &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert_eq!(
        held,
        json!({
            "identity": "did-web",
            "registrar_dataset": null,
            "registration_certificate": null,
            "updated_by": null,
            "updated_at": null,
            "keys": [],
            "running": true,
        })
    );
    let (status, told) = present_as(&plane, &bearer, json!({ "identity": "x509-hash" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(told["message"], NO_CERTIFICATE);

    let drawn = request_certificate(&plane, &bearer).await;
    assert_eq!(drawn["state"], "awaiting");
    assert_eq!(drawn["certificate"], Value::Null);
    assert_eq!(drawn["subject"], subject());
    assert!(
        drawn["request"]
            .as_str()
            .is_some_and(|pem| pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----")),
        "{drawn}"
    );
    let public_jwk = &drawn["public_jwk"];
    assert_eq!(
        (
            public_jwk["kty"].as_str(),
            public_jwk["crv"].as_str(),
            public_jwk["alg"].as_str(),
            public_jwk["use"].as_str(),
        ),
        (Some("EC"), Some("P-256"), Some("ES256"), Some("sig"))
    );
    assert!(
        public_jwk.get("d").is_none(),
        "the private key left the realm"
    );
    assert_eq!(public_jwk["kid"], drawn["kid"]);
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("{}/keys", verifier_path()),
        &bearer,
        Some(subject()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "a key already awaits its certificate: take the certificate issued for it, or withdraw it"
    );

    let stranger = EcKeyPair::generate(EcCurve::P256).expect("another key");
    let elsewhere = authority.certify(
        &Value::Object(stranger.to_jwk_public_key().as_ref().clone()),
        "Acme verifier",
    );
    let (status, told) = take_certificate(&plane, &bearer, authority.pasted(&elsewhere)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "the first certificate certifies another key than this one"
    );

    let leaf = authority.certify(public_jwk, "Acme verifier");
    let (status, certified) = take_certificate(&plane, &bearer, authority.pasted(&leaf)).await;
    assert_eq!(status, StatusCode::OK, "{certified}");
    assert_eq!(certified["state"], "serving");
    assert_eq!(certified["kid"], drawn["kid"]);
    let certificate = &certified["certificate"];
    assert_eq!(certificate["client_id"], x509_hash_of(&leaf));
    assert_eq!(
        certificate["chain"],
        json!([BASE64.encode(&leaf), BASE64.encode(&authority.intermediate)])
    );
    assert_eq!(
        certificate["subjects"],
        json!(["CN=Acme verifier", "CN=Access CA"])
    );
    let (status, told) = take_certificate(&plane, &bearer, authority.pasted(&leaf)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "no key awaits a certificate: request one first"
    );

    // While the realm presents itself by its did:web it needs an Ed25519 key
    // to ask by; once by its certificate, the certificate's key is enough.
    let profile = json!({
        "credential_query": {
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:1"] },
            "claims": [{ "path": ["family_name"] }]
        },
        "issuer": format!("{}/pid", wallet.issuer),
        "identifier_path": ["family_name"],
    });
    let wallet_identity = format!("/admin/realms/{REALM}/wallet-identity");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &wallet_identity,
        &bearer,
        Some(profile.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "the realm holds no Ed25519 key to sign a request with: mint one under its keys"
    );

    let (status, told) = present_as(
        &plane,
        &bearer,
        json!({ "identity": "x509-hash", "registrar_dataset": { "registryURI": "https://registrar.example/api" } }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "the registrar's dataset names the relying party by an identifier: a type URI and a value"
    );
    let (status, told) = present_as(
        &plane,
        &bearer,
        json!({ "identity": "x509-hash", "registration_certificate": "not-a-jwt" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "send the registration certificate as a compact JWT in at most 16 KiB"
    );
    let registration = registration_certificate(&authority);
    let (status, presented) = present_as(
        &plane,
        &bearer,
        json!({
            "identity": "x509-hash",
            "registrar_dataset": registrar_dataset(),
            "registration_certificate": registration,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{presented}");
    assert_eq!(presented["identity"], "x509-hash");
    assert_eq!(presented["registrar_dataset"], registrar_dataset());
    assert_eq!(presented["registration_certificate"], registration.as_str());
    assert_eq!(presented["keys"][0]["kid"], drawn["kid"]);
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &wallet_identity,
        &bearer,
        Some(profile),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let (status, asked_for) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/presentations"),
        &bearer,
        Some(json!({ "dcql_query": pid_query() })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{asked_for}");
    let (header, request) = read_certified_request(
        &plane,
        asked_for["uri"].as_str().expect("a link"),
        &authority,
    )
    .await;
    assert_eq!(
        (header["alg"].as_str(), header["typ"].as_str()),
        (Some("ES256"), Some("oauth-authz-req+jwt"))
    );
    assert!(
        header
            .get("iat")
            .and_then(Value::as_i64)
            .is_some_and(|signed| (signed - now()).abs() < 60),
        "{header:?}"
    );
    assert!(
        header.get("kid").is_none(),
        "the request names its key otherwise than by its chain"
    );
    let client_id = x509_hash_of(&leaf);
    assert_eq!(request["client_id"], client_id.as_str());
    assert_eq!(request["iss"], client_id.as_str());
    assert_eq!(request["aud"], "https://self-issued.me/v2");
    assert_eq!(
        request["verifier_info"],
        json!([
            { "format": "registrar_dataset", "data": registrar_dataset() },
            { "format": "registration_cert", "data": registration },
        ])
    );
    let answer_key = &request["client_metadata"]["jwks"]["keys"][0];
    assert!(
        answer_key["kid"].is_string() && answer_key["use"] == "enc",
        "{answer_key}"
    );

    answer_and_settle(
        &plane, &bearer, &wallet, &asked_for, &request, &client_id, None,
    )
    .await;
}

/// What a key binding to another audience than the request's comes to.
const BOUND_ELSEWHERE: &str = "a credential's disclosures, key binding or time claims do not hold";

/// Answer a request with a PID bound to `audience`, and check what it
/// settled as: verified, or failed for the reason given, which the wallet is
/// told too.
async fn answer_and_settle(
    plane: &Plane,
    bearer: &str,
    wallet: &Wallet,
    asked_for: &Value,
    request: &Map<String, Value>,
    audience: &str,
    failure: Option<&str>,
) {
    let nonce = request["nonce"].as_str().expect("a nonce");
    let answer = json!({
        "vp_token": { "pid": [wallet.presented(audience, nonce)] },
        "state": request["state"],
    });
    let (status, told) = answered(
        plane,
        request,
        &[("response", &encrypted(request, &answer))],
    )
    .await;
    let standing = standing_of(plane, bearer, &asked_for["id"]).await;
    match failure {
        None => {
            assert_eq!(status, StatusCode::OK, "{told}");
            assert_eq!(standing["status"], "verified", "{standing}");
        }
        Some(reason) => {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
            let told: Value = serde_json::from_str(&told).expect("a JSON error");
            assert_eq!(told["error_description"], reason);
            assert_eq!(standing["status"], "failed", "{standing}");
            assert_eq!(standing["outcome"]["reason"], reason);
        }
    }
}

async fn ask_certified(
    plane: &Plane,
    bearer: &str,
    authority: &Authority,
) -> (Value, Map<String, Value>, Vec<u8>) {
    let (status, asked_for) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/presentations"),
        bearer,
        Some(json!({ "dcql_query": pid_query() })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{asked_for}");
    let (header, request) =
        read_certified_request(plane, asked_for["uri"].as_str().expect("a link"), authority).await;
    let leaf = BASE64
        .decode(header["x5c"][0].as_str().expect("a leaf").as_bytes())
        .expect("standard base64");
    (asked_for, request, leaf)
}

/// A request is answered under the identifier it was asked under: one asked
/// before a renewed certificate came into service is still answered bound to
/// the old certificate's hash, and one asked after is not. The key serving
/// goes on serving while its successor awaits a certificate, and is dropped
/// once the successor serves. A request kept before identifiers were kept
/// with requests is answered under the realm's did:web.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_answer_is_held_to_the_identifier_its_request_was_asked_under() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = name_pid_issuer(&plane, &bearer).await;
    let authority = authority();
    let first = present_by_certificate(&plane, &bearer, &authority).await;
    let before = x509_hash_of(&first);

    let (asked_before, request_before, signed_under) =
        ask_certified(&plane, &bearer, &authority).await;
    assert_eq!(signed_under, first);
    let renewing = request_certificate(&plane, &bearer).await;
    let (asked_while, request_while, signed_under) =
        ask_certified(&plane, &bearer, &authority).await;
    assert_eq!(
        signed_under, first,
        "a key awaiting its certificate signed a request"
    );
    let second = authority.certify(&renewing["public_jwk"], "Acme verifier 2");
    let (status, told) = take_certificate(&plane, &bearer, authority.pasted(&second)).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, held) = asked(&plane, Method::GET, &verifier_path(), &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{held}");
    let kids: Vec<&Value> = held["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|key| &key["kid"])
        .collect();
    assert_eq!(kids, [&renewing["kid"]], "the key replaced was kept");

    let (asked_after, request_after, signed_under) =
        ask_certified(&plane, &bearer, &authority).await;
    assert_eq!(signed_under, second);
    let after = x509_hash_of(&second);
    assert_ne!(before, after);

    answer_and_settle(
        &plane,
        &bearer,
        &wallet,
        &asked_before,
        &request_before,
        &before,
        None,
    )
    .await;
    answer_and_settle(
        &plane,
        &bearer,
        &wallet,
        &asked_while,
        &request_while,
        &before,
        None,
    )
    .await;
    answer_and_settle(
        &plane,
        &bearer,
        &wallet,
        &asked_after,
        &request_after,
        &before,
        Some(BOUND_ELSEWHERE),
    )
    .await;

    // Under its did:web the realm sends nothing of what its registrar holds,
    // which only a request signed under its certificate carries.
    mint_request_key(&plane, &bearer).await;
    let (status, told) = present_as(
        &plane,
        &bearer,
        json!({ "identity": "did-web", "registrar_dataset": registrar_dataset() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (asked_kept, request_kept) = super::wallet::ask_for(&plane, &bearer, &pid_query()).await;
    assert!(
        request_kept.get("verifier_info").is_none(),
        "{request_kept:?}"
    );
    let did_client_id = request_kept["client_id"]
        .as_str()
        .expect("a client_id")
        .to_owned();
    assert!(
        did_client_id.starts_with("decentralized_identifier:did:web:"),
        "{did_client_id}"
    );
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    let forgotten = transaction
        .execute(
            "UPDATE presentation_requests SET client_id = NULL WHERE request_id = $1",
            &[&asked_kept["id"].as_str().expect("an id")],
        )
        .await
        .expect("the identifier forgotten");
    assert_eq!(forgotten, 1);
    transaction.commit().await.expect("committed");
    answer_and_settle(
        &plane,
        &bearer,
        &wallet,
        &asked_kept,
        &request_kept,
        &did_client_id,
        None,
    )
    .await;
}

/// A key in service is withdrawn only once the realm no longer presents
/// itself by it, and a certificate no longer valid neither signs a request
/// nor can be chosen to present the realm by.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_certificate_serves_only_while_valid_and_is_withdrawn_once_out_of_service() {
    let (plane, bearer) = plane_that_verifies().await;
    name_pid_issuer(&plane, &bearer).await;
    let authority = authority();
    present_by_certificate(&plane, &bearer, &authority).await;
    let (_, held) = asked(&plane, Method::GET, &verifier_path(), &bearer, None).await;
    let serving = held["keys"][0]["kid"].as_str().expect("a kid").to_owned();

    let key_path = |kid: &str| format!("{}/keys/{kid}", verifier_path());
    let (status, told) = asked(&plane, Method::DELETE, &key_path(&serving), &bearer, None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "the realm presents itself by this key's certificate: present it by its did:web before \
         withdrawing the key"
    );
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &key_path("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "realm.verifier_key.not_found");
    let awaiting = request_certificate(&plane, &bearer).await;
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &key_path(awaiting["kid"].as_str().expect("a kid")),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    transaction
        .execute(
            "UPDATE realm_verifier_keys SET not_after = now() - interval '1 second' \
             WHERE state = 'serving'",
            &[],
        )
        .await
        .expect("the certificate ran out");
    transaction.commit().await.expect("committed");
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/presentations"),
        &bearer,
        Some(json!({ "dcql_query": pid_query() })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "the realm's verifier certificate is not valid now: take a renewed one, or present the \
         realm by its did:web"
    );
    let (status, told) = present_as(&plane, &bearer, json!({ "identity": "x509-hash" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(told["message"], NO_CERTIFICATE);

    let (status, told) = present_as(&plane, &bearer, json!({ "identity": "did-web" })).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, told) = asked(&plane, Method::DELETE, &key_path(&serving), &bearer, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (status, held) = asked(&plane, Method::GET, &verifier_path(), &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert_eq!(held["keys"], json!([]));
    assert_eq!(held["identity"], "did-web");
}
