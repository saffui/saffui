//! Request objects on Postgres, each signed for real, by a key or a secret
//! the cryptography of the product makes as the test runs. What an object
//! says is the request, and an object that does not stand is believed in
//! nothing: its refusal goes where the query alone says, if anywhere.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crypto::adapters::digest::ProviderDigester;
use crypto::adapters::open_provider;
use crypto::adapters::sign::JoseSigner;
use pgcore::testkit::TestDatabase;
use saffui_core::app::App;
use saffui_core::clients::register::{ClientChecker, NewClient, check_new_client, register_client};
use saffui_core::clients::{AssertionAlgorithm, ClientAuthMethod};
use saffui_core::error::ErrorCode;
use saffui_core::oidc::authorize::{
    Authorization, AuthorizationParameters, AuthorizationRefusal, begin_authorization,
};
use saffui_core::oidc::code::PendingAuthorization;
use saffui_core::oidc::response::ResponseMode;
use saffui_core::ports::crypto::{Digester, GeneratedSigningKey, SignatureAlgorithm, Signer};
use saffui_core::secret::Secret;
use saffui_core::tenancy::RealmScope;
use serde_json::{Value, json};

#[path = "support/product.rs"]
#[expect(
    dead_code,
    reason = "its hands in the database serve the tests of the keys"
)]
mod product;

const ISSUER: &str = "https://id.example.test/realms/acme";
const CALLBACK: &str = "https://app.example.org/callback";
const ELSEWHERE: &str = "https://app.example.org/elsewhere";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The realm `acme` and its clients: `keyed` signs its requests with an
/// ES256 key, `signer` with its secret, `strict` with the same key and
/// sends nothing else, and `plain` holds the key and named no algorithm of
/// requests.
struct Realm {
    app: App,
    scope: RealmScope,
    signer: JoseSigner,
    es256: GeneratedSigningKey,
    secret: Secret,
    _database: TestDatabase,
}

async fn register(
    app: &App,
    scope: RealmScope,
    client_id: &str,
    method: ClientAuthMethod,
    jwks: Option<&Value>,
    request_object_signing_alg: Option<AssertionAlgorithm>,
    require_signed_request_object: bool,
) -> Option<Secret> {
    let scopes = ["openid", "email"].map(str::to_owned);
    let callbacks = [CALLBACK, ELSEWHERE].map(str::to_owned);
    let checked = check_new_client(
        app,
        ClientChecker::Administrator(scope.tenant()),
        NewClient {
            client_id,
            name: client_id,
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &callbacks,
            post_logout_redirect_uris: &[],
            response_types: &[],
            public: false,
            requires_consent: false,
            id_token_signed_response_alg: None,
            auth_method: Some(method),
            jwks,
            jwks_uri: None,
            auth_signing_alg: None,
            request_object_signing_alg,
            require_signed_request_object,
            created_by: None,
        },
    )
    .await
    .expect("a client to register");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let (_, secret) = register_client(app, work.as_mut(), checked)
        .await
        .expect("a client");
    work.commit().await.expect("a commit");
    secret
}

async fn prepare_realm() -> Realm {
    let (app, database) = product::wire_on_postgres().await;
    let scope = product::create_realm(&app, "acme").await;
    let signer = JoseSigner::new(open_provider().expect("a provider"));
    let es256 = signer
        .generate_key(SignatureAlgorithm::Es256, Box::new(()))
        .await
        .expect("a key");
    let keys = json!({ "keys": [es256.public_jwk] });
    let es256_alg = AssertionAlgorithm::parse("ES256");
    let keyed = ClientAuthMethod::PrivateKeyJwt;
    register(&app, scope, "keyed", keyed, Some(&keys), es256_alg, false).await;
    register(&app, scope, "strict", keyed, Some(&keys), es256_alg, true).await;
    register(&app, scope, "plain", keyed, Some(&keys), None, false).await;
    let secret = register(
        &app,
        scope,
        "signer",
        ClientAuthMethod::ClientSecretJwt,
        None,
        Some(AssertionAlgorithm::Hs256),
        false,
    )
    .await
    .expect("a secret, shown once");
    Realm {
        app,
        scope,
        signer,
        es256,
        secret,
        _database: database,
    }
}

fn write_input(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

fn sign_with_secret(secret: &Secret, claims: &Value) -> String {
    let input = write_input(&json!({ "alg": "HS256" }), claims);
    let mac = ProviderDigester::new(open_provider().expect("a provider"))
        .hmac_sha256(secret, input.as_bytes())
        .expect("a mac");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(mac))
}

impl Realm {
    /// The claims of a request of `client_id` for a code, bound to it and to
    /// the realm, with each of `changes` written over them: null takes one
    /// out.
    fn write_claims(&self, client_id: &str, changes: &Value) -> Value {
        let now = self.app.now().unix_timestamp();
        let mut claims = json!({
            "iss": client_id,
            "aud": ISSUER,
            "client_id": client_id,
            "exp": now + 300,
            "iat": now,
            "response_type": "code",
            "redirect_uri": CALLBACK,
            "scope": "openid email",
            "state": "signed-state",
            "nonce": "signed-nonce",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
        });
        for (name, value) in changes.as_object().expect("changes") {
            if value.is_null() {
                claims.as_object_mut().expect("claims").remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
        claims
    }

    /// Signs `claims` with `key`, under a header that names it.
    fn sign_with_key(&self, key: &GeneratedSigningKey, header: &Value, claims: &Value) -> String {
        let mut header = header.clone();
        header["alg"] = json!(key.algorithm.name());
        if header.get("kid").is_none() {
            header["kid"] = json!(key.key_id);
        }
        let input = write_input(&header, claims);
        let signature = self
            .signer
            .sign(key.algorithm, &key.private_key, input.as_bytes())
            .expect("a signature");
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    /// An object of `keyed` signed with its ES256 key, with `changes`.
    fn sign_keyed(&self, changes: &Value) -> String {
        self.sign_with_key(
            &self.es256,
            &json!({}),
            &self.write_claims("keyed", changes),
        )
    }

    async fn begin(&self, parameters: &AuthorizationParameters<'_>) -> Outcome {
        match begin_authorization(&self.app, "acme", *parameters, None).await {
            Ok(Authorization::SignInRequired { request, .. }) => {
                let mut work = self
                    .app
                    .storage
                    .begin(self.scope)
                    .await
                    .expect("a unit of work");
                Outcome::Waiting(Box::new(
                    work.read_pending_authorization(request, self.app.now())
                        .await
                        .expect("a read")
                        .expect("the request waits"),
                ))
            }
            Ok(other) => panic!("no sign-in asked: {other:?}"),
            Err(AuthorizationRefusal::Returned { response }) => Outcome::Returned {
                to: response.redirect_uri().to_owned(),
                error: response
                    .read_parameter("error")
                    .expect("an error")
                    .to_owned(),
                state: response.read_parameter("state").map(str::to_owned),
            },
            Err(AuthorizationRefusal::Shown(failure)) => Outcome::Shown(failure.code),
        }
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Waiting(Box<PendingAuthorization>),
    Returned {
        to: String,
        error: String,
        state: Option<String>,
    },
    Shown(ErrorCode),
}

impl Outcome {
    fn into_pending(self) -> PendingAuthorization {
        match self {
            Self::Waiting(pending) => *pending,
            refused => panic!("the request does not wait: {refused:?}"),
        }
    }
}

/// A request that sends `request` alone, as a client of request objects does.
fn send<'a>(client_id: &'a str, request: &'a str) -> AuthorizationParameters<'a> {
    AuthorizationParameters {
        client_id: Some(client_id),
        request: Some(request),
        ..AuthorizationParameters::default()
    }
}

/// As [`send`], with a query that names where the client is answered: the
/// one place a refusal of the object may go.
fn send_answerable<'a>(client_id: &'a str, request: &'a str) -> AuthorizationParameters<'a> {
    AuthorizationParameters {
        redirect_uri: Some(CALLBACK),
        state: Some("query-state"),
        ..send(client_id, request)
    }
}

fn refused_in_query(error: &str) -> Outcome {
    Outcome::Returned {
        to: CALLBACK.to_owned(),
        error: error.to_owned(),
        state: Some("query-state".to_owned()),
    }
}

#[tokio::test]
async fn an_object_signed_by_a_key_of_its_client_is_the_request_and_the_query_beside_it_is_not_read()
 {
    let realm = prepare_realm().await;
    let object = realm.sign_keyed(&json!({ "max_age": 600 }));

    let pending = realm.begin(&send("keyed", &object)).await.into_pending();

    assert_eq!(pending.client_id, "keyed");
    assert_eq!(pending.redirect_uri, CALLBACK);
    assert_eq!(pending.scopes, ["openid", "email"]);
    assert_eq!(pending.state.as_deref(), Some("signed-state"));
    assert_eq!(pending.nonce.as_deref(), Some("signed-nonce"));
    assert_eq!(pending.code_challenge.as_deref(), Some(CHALLENGE));
    assert_eq!(pending.response_mode, ResponseMode::Query);

    // A query that says otherwise is not read: no other address, no other
    // state, no other mode, and no request answered without a page.
    let rewritten = AuthorizationParameters {
        redirect_uri: Some(ELSEWHERE),
        state: Some("query-state"),
        nonce: Some("query-nonce"),
        response_mode: Some("form_post"),
        prompt: Some("none"),
        code_challenge: Some("Zm9yZ2VkLWNoYWxsZW5nZS1vZi10aGUtcXVlcnktZm9yZ2Vk"),
        ..send("keyed", &object)
    };
    let pending = realm.begin(&rewritten).await.into_pending();
    assert_eq!(pending.redirect_uri, CALLBACK);
    assert_eq!(pending.state.as_deref(), Some("signed-state"));
    assert_eq!(pending.nonce.as_deref(), Some("signed-nonce"));
    assert_eq!(pending.response_mode, ResponseMode::Query);
    assert_eq!(pending.code_challenge.as_deref(), Some(CHALLENGE));

    // What the object asks is judged as a query would be.
    let silent = realm.sign_keyed(&json!({ "prompt": "none" }));
    assert_eq!(
        realm.begin(&send("keyed", &silent)).await,
        Outcome::Returned {
            to: CALLBACK.to_owned(),
            error: "login_required".to_owned(),
            state: Some("signed-state".to_owned()),
        },
        "the prompt of the object is read"
    );
    let typed = realm.sign_with_key(
        &realm.es256,
        &json!({ "typ": "oauth-authz-req+jwt" }),
        &realm.write_claims("keyed", &json!({})),
    );
    assert!(
        matches!(
            realm.begin(&send("keyed", &typed)).await,
            Outcome::Waiting(_)
        ),
        "typed as a request object"
    );
}

#[tokio::test]
async fn an_object_signed_by_the_secret_of_its_client_is_the_request() {
    let realm = prepare_realm().await;
    let claims = realm.write_claims("signer", &json!({ "scope": "openid" }));

    let pending = realm
        .begin(&send("signer", &sign_with_secret(&realm.secret, &claims)))
        .await
        .into_pending();

    assert_eq!(pending.client_id, "signer");
    assert_eq!(pending.scopes, ["openid"]);
    let guessed = Secret::new(b"not-the-secret-of-the-client-at-all".to_vec());
    assert_eq!(
        realm
            .begin(&send_answerable(
                "signer",
                &sign_with_secret(&guessed, &claims)
            ))
            .await,
        refused_in_query("invalid_request_object"),
        "another secret"
    );
}

#[tokio::test]
async fn an_object_is_read_only_in_the_algorithm_and_by_the_key_its_client_registered() {
    let realm = prepare_realm().await;
    let claims = realm.write_claims("keyed", &json!({}));
    let make_key = async |algorithm| {
        realm
            .signer
            .generate_key(algorithm, Box::new(()))
            .await
            .expect("a key")
    };
    let stranger = make_key(SignatureAlgorithm::Es256).await;
    // An RSA key is long to make and to check: drawn by this test alone.
    let rs256 = make_key(SignatureAlgorithm::Rs256).await;
    let paired = json!({ "keys": [realm.es256.public_jwk, rs256.public_jwk] });
    register(
        &realm.app,
        realm.scope,
        "paired",
        ClientAuthMethod::PrivateKeyJwt,
        Some(&paired),
        AssertionAlgorithm::parse("ES256"),
        false,
    )
    .await;
    let unsigned = format!("{}.", write_input(&json!({ "alg": "none" }), &claims));
    let encrypted = [
        URL_SAFE_NO_PAD.encode(r#"{"alg":"RSA-OAEP-256","enc":"A256GCM"}"#),
        URL_SAFE_NO_PAD.encode([7_u8; 256]),
        URL_SAFE_NO_PAD.encode([1_u8; 12]),
        URL_SAFE_NO_PAD.encode(claims.to_string()),
        URL_SAFE_NO_PAD.encode([2_u8; 16]),
    ]
    .join(".");
    let signed = realm.sign_keyed(&json!({}));
    let by_secret = sign_with_secret(&realm.secret, &claims);
    let plain_claims = realm.write_claims("plain", &json!({}));
    for (client_id, object, why) in [
        (
            "paired",
            realm.sign_with_key(
                &rs256,
                &json!({}),
                &realm.write_claims("paired", &json!({})),
            ),
            "a key of the client, of another algorithm than registered",
        ),
        ("keyed", unsigned, "no signature"),
        (
            "keyed",
            realm.sign_with_key(&realm.es256, &json!({ "kid": "nobody" }), &claims),
            "a key the client does not hold",
        ),
        (
            "keyed",
            realm.sign_with_key(&stranger, &json!({ "kid": realm.es256.key_id }), &claims),
            "the name of its key on the signature of another",
        ),
        ("keyed", by_secret, "a secret in place of its key"),
        (
            "keyed",
            realm.sign_with_key(&realm.es256, &json!({ "typ": "JWT" }), &claims),
            "a token of another type",
        ),
        (
            "keyed",
            realm.sign_with_key(&realm.es256, &json!({ "crit": ["exp"] }), &claims),
            "members it must understand",
        ),
        ("keyed", encrypted, "encrypted"),
        (
            "keyed",
            format!("{signed}.{signed}"),
            "a part after the signature",
        ),
        (
            "plain",
            realm.sign_with_key(&realm.es256, &json!({}), &plain_claims),
            "a client that named no algorithm of requests",
        ),
    ] {
        assert_eq!(
            realm.begin(&send_answerable(client_id, &object)).await,
            refused_in_query("invalid_request_object"),
            "{why}"
        );
    }
    assert!(
        matches!(
            realm.begin(&send("keyed", &signed)).await,
            Outcome::Waiting(_)
        ),
        "the same claims, signed as registered"
    );
}

#[tokio::test]
async fn an_object_made_for_another_provider_another_client_or_another_time_is_refused() {
    let realm = prepare_realm().await;
    let now = realm.app.now().unix_timestamp();
    for (changes, why) in [
        (
            json!({ "aud": "https://other.example.org/realms/acme" }),
            "another provider",
        ),
        (
            json!({ "aud": [ISSUER, "https://other.example.org"] }),
            "this provider and another",
        ),
        (json!({ "aud": null }), "no audience"),
        (json!({ "exp": null }), "no expiry"),
        (json!({ "exp": now + 3601 }), "past an hour"),
        (json!({ "exp": now - 1 }), "expired"),
        (json!({ "nbf": now + 31 }), "valid later"),
        (json!({ "iat": now + 31 }), "made later"),
        (json!({ "iss": "signer" }), "issued by another client"),
        (json!({ "client_id": "signer" }), "for another client"),
        (
            json!({ "sub": "keyed" }),
            "a subject that names the client, as its assertion would",
        ),
        (json!({ "request": "a.b.c" }), "an object in the object"),
        (
            json!({ "request_uri": "https://app.example.org/request" }),
            "an address of an object in the object",
        ),
        (json!({ "scope": ["openid"] }), "a scope that is no text"),
    ] {
        assert_eq!(
            realm
                .begin(&send_answerable("keyed", &realm.sign_keyed(&changes)))
                .await,
            refused_in_query("invalid_request_object"),
            "{why}"
        );
    }
    for (changes, why) in [
        (json!({ "aud": [ISSUER] }), "this provider alone, in a list"),
        (
            json!({ "nbf": now + 30, "iat": now + 30 }),
            "within the skew",
        ),
        (json!({ "exp": now + 3600 }), "an hour away"),
    ] {
        assert!(
            matches!(
                realm
                    .begin(&send("keyed", &realm.sign_keyed(&changes)))
                    .await,
                Outcome::Waiting(_)
            ),
            "{why}"
        );
    }
}

#[tokio::test]
async fn a_query_that_says_otherwise_than_its_object_is_refused() {
    let realm = prepare_realm().await;
    let object = realm.sign_keyed(&json!({}));
    for (query, why) in [
        (
            AuthorizationParameters {
                response_type: Some("code id_token"),
                ..send_answerable("keyed", &object)
            },
            "another response type",
        ),
        (
            AuthorizationParameters {
                scope: Some("openid"),
                ..send_answerable("keyed", &object)
            },
            "another scope",
        ),
    ] {
        assert_eq!(
            realm.begin(&query).await,
            refused_in_query("invalid_request_object"),
            "{why}"
        );
    }
    let repeated = AuthorizationParameters {
        response_type: Some("code"),
        scope: Some("email openid"),
        ..send("keyed", &object)
    };
    assert!(
        matches!(realm.begin(&repeated).await, Outcome::Waiting(_)),
        "the same, repeated in the query for OpenID Connect, in any order"
    );
    let unsaid = realm.sign_keyed(&json!({ "response_type": null }));
    assert_eq!(
        realm
            .begin(&AuthorizationParameters {
                response_type: Some("code"),
                ..send_answerable("keyed", &unsaid)
            })
            .await,
        refused_in_query("invalid_request_object"),
        "a type the query writes and the object does not"
    );
}

#[tokio::test]
async fn a_refusal_of_an_object_goes_back_only_where_the_query_names_an_address_the_client_registered()
 {
    let realm = prepare_realm().await;
    let expired = realm.sign_keyed(&json!({ "exp": realm.app.now().unix_timestamp() - 1 }));

    assert_eq!(
        realm.begin(&send("keyed", &expired)).await,
        Outcome::Shown(ErrorCode::RequestObjectInvalid),
        "the address the object names is not believed"
    );
    assert_eq!(
        realm
            .begin(&AuthorizationParameters {
                redirect_uri: Some("https://evil.example.org/callback"),
                ..send("keyed", &expired)
            })
            .await,
        Outcome::Shown(ErrorCode::RequestObjectInvalid),
        "an address the client did not register"
    );
    assert_eq!(
        realm
            .begin(&AuthorizationParameters {
                redirect_uri: Some(ELSEWHERE),
                ..send("keyed", &expired)
            })
            .await,
        Outcome::Returned {
            to: ELSEWHERE.to_owned(),
            error: "invalid_request_object".to_owned(),
            state: None,
        },
        "the state of the object is not echoed back"
    );
}

#[tokio::test]
async fn an_address_of_a_request_is_never_fetched_and_a_client_that_requires_objects_sends_no_other()
 {
    let realm = prepare_realm().await;
    let object = realm.sign_keyed(&json!({}));
    let address = "https://app.example.org/request.jwt";
    let by_reference = AuthorizationParameters {
        request_uri: Some(address),
        request: None,
        ..send_answerable("keyed", "")
    };
    assert_eq!(
        realm.begin(&by_reference).await,
        refused_in_query("request_uri_not_supported")
    );
    assert_eq!(
        realm
            .begin(&AuthorizationParameters {
                request_uri: Some(address),
                ..send_answerable("keyed", &object)
            })
            .await,
        refused_in_query("invalid_request"),
        "both at once"
    );
    assert_eq!(
        realm
            .begin(&AuthorizationParameters {
                request_uri: Some(address),
                request: None,
                ..send("keyed", "")
            })
            .await,
        Outcome::Shown(ErrorCode::RequestInvalid),
        "nowhere trusted to send the refusal"
    );

    let unsigned = AuthorizationParameters {
        response_type: Some("code"),
        scope: Some("openid"),
        nonce: Some("n"),
        code_challenge: Some(CHALLENGE),
        code_challenge_method: Some("S256"),
        request: None,
        ..send_answerable("strict", "")
    };
    assert_eq!(
        realm.begin(&unsigned).await,
        refused_in_query("invalid_request"),
        "a client that requires its requests signed sends no other"
    );
    let signed = realm.sign_with_key(
        &realm.es256,
        &json!({}),
        &realm.write_claims("strict", &json!({})),
    );
    assert!(matches!(
        realm.begin(&send("strict", &signed)).await,
        Outcome::Waiting(_)
    ));
    assert!(
        matches!(
            realm
                .begin(&AuthorizationParameters {
                    client_id: Some("keyed"),
                    ..unsigned
                })
                .await,
            Outcome::Waiting(_)
        ),
        "the same request, of a client that does not require objects"
    );
    assert!(
        matches!(
            realm
                .begin(&AuthorizationParameters {
                    client_id: Some("keyed"),
                    request: Some(""),
                    request_uri: Some(""),
                    ..unsigned
                })
                .await,
            Outcome::Waiting(_)
        ),
        "a parameter sent without a value is one that was not sent"
    );
}
