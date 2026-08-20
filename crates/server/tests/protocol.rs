//! The one door on this plane with no gate in front of it.

mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use data_encoding::BASE64;
use server::api::config::{Plane as Mounted, register};
use support::Plane;

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        sealing: support::sealing(),
    }
}

/// Every answer, refusals included, carries the fields a client library reads.
/// The envelope the rest of this server uses would parse as a token response
/// carrying no token.
async fn ask(plane: &Plane, realm: &str, form: &[(&str, &str)]) -> (StatusCode, serde_json::Value) {
    asking(plane, realm, form, None).await
}

/// The same, with what §2.3.1 puts in the header.
async fn asking(
    plane: &Plane,
    realm: &str,
    form: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> (StatusCode, serde_json::Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut request = test::TestRequest::post()
        .uri(&format!("/realms/{realm}/protocol/openid-connect/token"))
        .set_form(form);
    if let Some((client_id, secret)) = basic {
        let encoded = BASE64.encode(format!("{client_id}:{secret}").as_bytes());
        request = request.insert_header(("authorization", format!("Basic {encoded}")));
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

/// The whole way through: a client proves itself, gets a token, and the token is
/// one this deployment takes back. A grant tested only against its own response
/// proves a string was returned.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_acting_for_itself_gets_a_token_this_realm_takes_back() {
    let plane = Plane::with_actions(&[]).await;
    let (status, body) = asking(
        &plane,
        support::REALM,
        &[("grant_type", "client_credentials")],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 300);
    assert!(
        body.get("refresh_token").is_none(),
        "§4.4.3: a refresh token would be a second credential for the same \
         authority with a longer life, and the client already holds the one \
         that produced this: {body}"
    );

    let token = body["access_token"].as_str().expect("a token");
    let claims = plane.claims_of(token).await;
    assert_eq!(
        claims["iss"],
        format!("https://id.test/realms/{}", support::REALM)
    );
    assert_eq!(claims["azp"], support::CONFIDENTIAL);
    assert_eq!(claims["aud"], support::CONFIDENTIAL);
    assert_eq!(claims["typ"], "Bearer");
    assert_eq!(
        claims["sub"],
        format!("service-account-{}", support::CONFIDENTIAL),
        "a machine token carried no subject, so every gate downstream would \
         need a second kind of caller"
    );
    assert!(
        claims["sid"].as_str().is_some_and(|sid| !sid.is_empty()),
        "no login was named, so the gate that reads one refuses this token"
    );
    assert!(
        claims["jti"].as_str().is_some_and(|jti| !jti.is_empty()),
        "no identifier, so no revocation could ever name it"
    );
}

/// The login is written before the token is handed out. Answering first and
/// committing after hands a client a token whose login the gate cannot find.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_login_the_token_names_is_there_when_the_client_gets_it() {
    let plane = Plane::with_actions(&[]).await;
    let (_, body) = asking(
        &plane,
        support::REALM,
        &[("grant_type", "client_credentials")],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    let token = body["access_token"].as_str().expect("a token");
    let session_id = plane.claims_of(token).await["sid"]
        .as_str()
        .expect("a login")
        .to_owned();

    assert!(
        plane.session_exists(&session_id).await,
        "the token was handed out before the login it names was written"
    );
}

/// A client that authenticates and may not have this grant is told that, which
/// §5.2 keeps apart from failing to authenticate. A public client may not: §4.4
/// is authentication by credential alone, and a public client has none to keep.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_public_client_may_not_act_for_itself() {
    let plane = Plane::with_actions(&[]).await;
    let (status, body) = ask(
        &plane,
        support::REALM,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", support::PUBLIC),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unauthorized_client");
}

/// Switching off the account is the lever an operator reaches for first, and it
/// has to work while the client registration still says the grant is enabled.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_account_the_realm_switched_off_acts_for_nobody() {
    let plane = Plane::with_actions(&[]).await;
    let (status, body) = asking(
        &plane,
        support::REALM,
        &[("grant_type", "client_credentials")],
        Some((support::OFFBOARDED, support::CLIENT_SECRET)),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "unauthorized_client");
}

/// A registered client, proving it, in each of the two ways §2.3.1 allows.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_that_proves_itself_reaches_the_grant() {
    let plane = Plane::with_actions(&[]).await;

    let (header, _) = asking(
        &plane,
        support::REALM,
        &[("grant_type", "client_credentials")],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(header, StatusCode::OK);

    let (post, _) = ask(
        &plane,
        support::REALM,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", support::CONFIDENTIAL),
            ("client_secret", support::CLIENT_SECRET),
        ],
    )
    .await;
    assert_eq!(post, StatusCode::OK);
}

/// Everything about who is asking collapses to one answer. Four distinguishable
/// refusals would let a caller read off which clients a realm holds and which
/// of them are switched on.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn nothing_about_a_client_is_readable_from_a_refusal() {
    let plane = Plane::with_actions(&[]).await;
    let grant = ("grant_type", "client_credentials");

    for (label, basic) in [
        ("a wrong secret", (support::CONFIDENTIAL, "not-the-secret")),
        ("no such client", ("no-such-client", support::CLIENT_SECRET)),
        (
            "a public client presenting a secret it cannot keep",
            (support::PUBLIC, support::CLIENT_SECRET),
        ),
    ] {
        let (status, body) = asking(&plane, support::REALM, &[grant], Some(basic)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{label}");
        assert_eq!(body["error"], "invalid_client", "{label}");
        assert_eq!(
            body["error_description"], "the client could not be authenticated",
            "{label} was distinguishable from the others"
        );
    }
}

/// A confidential client with no secret is refused, and a public one with none
/// is not: the proof a public client offers is elsewhere.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_a_public_client_gets_anywhere_on_its_name_alone() {
    let plane = Plane::with_actions(&[]).await;

    let (status, _) = ask(
        &plane,
        support::REALM,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", support::CONFIDENTIAL),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (_, body) = ask(
        &plane,
        support::REALM,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", support::PUBLIC),
        ],
    )
    .await;
    assert_eq!(
        body["error"], "unauthorized_client",
        "a public client was refused for holding no secret, rather than for \
         being one this grant is not open to"
    );
}

/// RFC 6749 §2.3 forbids two methods at once. A server that picked one lets a
/// caller present a weak credential beside a strong one and be judged on
/// whichever gets checked.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn two_ways_of_proving_it_at_once_is_a_request_failure() {
    let plane = Plane::with_actions(&[]).await;

    let (status, body) = asking(
        &plane,
        support::REALM,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", support::CONFIDENTIAL),
            ("client_secret", support::CLIENT_SECRET),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");

    // A header naming one client and a form naming another is two claims about
    // who is asking, whichever carries the secret.
    let (_, disagreeing) = asking(
        &plane,
        support::REALM,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", support::PUBLIC),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(disagreeing["error"], "invalid_request");
}

/// The grant is read after the client is established, so an unauthenticated
/// caller cannot learn which grants a deployment performs.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_grant_is_not_answered_before_the_client_is_known() {
    let plane = Plane::with_actions(&[]).await;

    let (status, body) = asking(
        &plane,
        support::REALM,
        &[("grant_type", "urn:nonsense")],
        Some((support::CONFIDENTIAL, "not-the-secret")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body["error"], "invalid_client",
        "the grant was judged before the caller was"
    );

    // The same for a request that names no grant at all. Answering
    // `invalid_request` here tells a caller its body was read, and read against
    // a client it never proved it was.
    let (status, shapeless) = asking(
        &plane,
        support::REALM,
        &[],
        Some((support::CONFIDENTIAL, "not-the-secret")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(shapeless["error"], "invalid_client");
}

/// It answers without a bearer. Everything else on this plane is behind a gate,
/// and a caller asking for a token has none to present.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_token_endpoint_answers_without_a_bearer() {
    let plane = Plane::with_actions(&[]).await;
    let (status, body) = asking(
        &plane,
        support::REALM,
        &[("grant_type", "client_credentials")],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.get("access_token").is_some(),
        "a client that proved itself got no token: {body}"
    );
    assert!(
        body.get("error").is_none(),
        "a refusal a client cannot act on: {body}"
    );
    assert!(
        body.get("error_code").is_none(),
        "the admin envelope reached a client that reads RFC 6749: {body}"
    );
}

/// A grant nobody has ever heard of and a grant this build does not perform are
/// both `unsupported_grant_type`, and a missing one is a request failure. A
/// client retries the third and stops on the first two.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_refusal_says_which_kind_of_failure_it_is() {
    let plane = Plane::with_actions(&[]).await;
    let proof = Some((support::CONFIDENTIAL, support::CLIENT_SECRET));

    for (form, expected) in [
        (vec![], "invalid_request"),
        (vec![("grant_type", "")], "invalid_request"),
        (
            vec![("grant_type", "urn:nonsense")],
            "unsupported_grant_type",
        ),
        // A grant this build performs, asked for without what it needs.
        (
            vec![("grant_type", "authorization_code")],
            "invalid_request",
        ),
        (vec![("grant_type", "refresh_token")], "invalid_request"),
    ] {
        let (_, body) = asking(&plane, support::REALM, &form, proof).await;
        assert_eq!(body["error"], expected, "for {form:?}: {body}");
    }
}

/// A request naming no client at all is a client failure, not a request one.
/// §2.3 makes establishing who is asking the first thing that happens.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_request_naming_no_client_is_refused_as_a_client() {
    let plane = Plane::with_actions(&[]).await;

    let (status, body) = ask(
        &plane,
        support::REALM,
        &[("grant_type", "client_credentials")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");
}

/// A realm this deployment does not hold is answered the way a client that
/// failed to authenticate is. Telling the two apart is a way to read off which
/// realms exist, one request at a time.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn no_such_realm_is_not_distinguishable_from_a_client_that_did_not_authenticate() {
    let plane = Plane::with_actions(&[]).await;
    let (status, body) = ask(
        &plane,
        "no-such-realm",
        &[("grant_type", "client_credentials")],
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");
}

/// Never stored, never served from a cache. A cached token response is a token
/// handed to whoever asks next, so the rule is on the refusals too.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn nothing_from_this_endpoint_may_be_cached() {
    let plane = Plane::with_actions(&[]).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let request = test::TestRequest::post()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/token",
            support::REALM
        ))
        .set_form([("grant_type", "client_credentials")])
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(response.headers().get("pragma").unwrap(), "no-cache");
}

/// The ceiling is this scope's own. It is the one door reachable with nothing
/// presented, so how much an unidentified caller may make the server read is a
/// number somebody chose rather than one a dependency supplies.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn more_than_a_token_request_holds_is_not_read() {
    let plane = Plane::with_actions(&[]).await;
    let padding = "x".repeat(9 * 1024);
    let (status, body) = ask(
        &plane,
        support::REALM,
        &[("grant_type", "client_credentials"), ("scope", &padding)],
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error"], "invalid_request",
        "a body past the ceiling was read as a grant"
    );
}

const REDIRECT: &str = "https://app.example/callback";

/// The verifier and its S256 challenge, the pair RFC 7636 §4 describes.
use crypto::provider::CryptoProvider as _;

fn pkce_pair() -> (String, String) {
    let verifier = "a-verifier-of-at-least-forty-three-characters-long";
    let digest = crypto::provider::openssl::OpenSslProvider::new(&crypto::provider::CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .expect("a software provider")
    .digest()
    .hash(crypto::provider::HashAlg::Sha256, verifier.as_bytes())
    .expect("a digest");
    (
        verifier.to_owned(),
        data_encoding::BASE64URL_NOPAD.encode(&digest),
    )
}

/// A code spent yields the three tokens, and the access token is one this
/// deployment takes back. Checking only the response proves a string came out.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_code_spent_yields_tokens_this_realm_takes_back() {
    let plane = Plane::with_actions(&[]).await;
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid profile", None)
        .await;

    let (status, body) = asking(
        &plane,
        support::REALM,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scope"], "openid profile");
    let access = body["access_token"].as_str().expect("an access token");
    let claims = plane.claims_of(access).await;
    assert_eq!(claims["sub"], support::SUBJECT);
    assert_eq!(claims["sid"], support::SESSION);
    assert_eq!(claims["typ"], "Bearer");

    let id_token = body["id_token"].as_str().expect("an id token");
    let identity = plane.claims_of(id_token).await;
    assert_eq!(identity["typ"], "ID");
    assert_eq!(identity["nonce"], "n-once");
    assert_eq!(
        identity["auth_time"], 1_700_000_000,
        "auth_time is the login's instant, not the redemption's"
    );
    assert_eq!(identity["acr"], "password");

    let refresh = body["refresh_token"].as_str().expect("a refresh token");
    let renewal = plane.claims_of(refresh).await;
    assert_eq!(renewal["typ"], "Refresh");
    assert!(
        plane.session_exists(support::SESSION).await,
        "the login the tokens name is not there"
    );
}

/// A code is spent by the attempt, not by the attempt succeeding. Otherwise a
/// code refused for one reason can be presented again without it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_code_is_spent_once_however_it_ends() {
    let plane = Plane::with_actions(&[]).await;
    let spend = |code: String, redirect: &'static str| {
        let plane = &plane;
        async move {
            asking(
                plane,
                support::REALM,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", redirect),
                ],
                Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
            )
            .await
        }
    };

    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid", None)
        .await;
    assert_eq!(spend(code.clone(), REDIRECT).await.0, StatusCode::OK);
    let (status, body) = spend(code, REDIRECT).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");

    // Refused for the redirect, and gone all the same.
    let second = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid", None)
        .await;
    assert_eq!(
        spend(second.clone(), "https://elsewhere.example/cb")
            .await
            .1["error"],
        "invalid_grant"
    );
    assert_eq!(
        spend(second, REDIRECT).await.1["error"],
        "invalid_grant",
        "a code refused for its redirect was still spendable with the right one"
    );
}

/// Everything a redemption re-checks, and one answer for all of them. A client
/// that could tell them apart could learn whether a code it does not hold
/// exists.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn nothing_about_a_code_is_readable_from_a_refusal() {
    let plane = Plane::with_actions(&[]).await;

    for (label, minted_for, presented_redirect) in [
        (
            "a code minted for another client",
            support::PUBLIC,
            REDIRECT,
        ),
        (
            "a redirect the code was not minted against",
            support::CONFIDENTIAL,
            "https://elsewhere.example/cb",
        ),
    ] {
        let code = plane.mint_code(minted_for, REDIRECT, "openid", None).await;
        let (status, body) = asking(
            &plane,
            support::REALM,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", presented_redirect),
            ],
            Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
        assert_eq!(body["error"], "invalid_grant", "{label}");
    }

    // A code nobody minted.
    let (_, unknown) = asking(
        &plane,
        support::REALM,
        &[
            ("grant_type", "authorization_code"),
            ("code", "never-minted"),
            ("redirect_uri", REDIRECT),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(unknown["error"], "invalid_grant");
}

/// The proof RFC 7636 describes, and the two ways of not having it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_challenge_is_answered_or_the_code_is_not_spent() {
    let plane = Plane::with_actions(&[]).await;
    let (verifier, challenge) = pkce_pair();

    let spend = |code: String, verifier: Option<String>| {
        let plane = &plane;
        async move {
            let mut form = vec![
                ("grant_type".to_owned(), "authorization_code".to_owned()),
                ("code".to_owned(), code),
                ("redirect_uri".to_owned(), REDIRECT.to_owned()),
            ];
            if let Some(verifier) = verifier {
                form.push(("code_verifier".to_owned(), verifier));
            }
            let borrowed: Vec<(&str, &str)> = form
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            asking(
                plane,
                support::REALM,
                &borrowed,
                Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
            )
            .await
        }
    };

    let held = plane
        .mint_code(
            support::CONFIDENTIAL,
            REDIRECT,
            "openid",
            Some((&challenge, "S256")),
        )
        .await;
    assert_eq!(
        spend(held, Some(verifier.clone())).await.0,
        StatusCode::OK,
        "the verifier the challenge was built from was refused"
    );

    for (label, offered) in [
        ("no verifier at all", None),
        (
            "the wrong one",
            Some("a-different-verifier-of-decent-length".to_owned()),
        ),
        (
            "the challenge presented as its own verifier",
            Some(challenge.clone()),
        ),
    ] {
        let code = plane
            .mint_code(
                support::CONFIDENTIAL,
                REDIRECT,
                "openid",
                Some((&challenge, "S256")),
            )
            .await;
        assert_eq!(
            spend(code, offered).await.1["error"],
            "invalid_grant",
            "{label}"
        );
    }

    // A method this build does not know must not fall back to comparing the
    // verifier against the challenge, which is what treating it as `plain`
    // would do: the challenge travels in the authorize request, so anyone who
    // saw that request would hold the answer.
    let unknown = plane
        .mint_code(
            support::CONFIDENTIAL,
            REDIRECT,
            "openid",
            Some((&verifier, "S512")),
        )
        .await;
    assert_eq!(
        spend(unknown, Some(verifier)).await.1["error"],
        "invalid_grant",
        "an unknown challenge method was treated as plain"
    );
}

/// A public client authenticates with nothing, so the challenge is the whole of
/// its proof. A code minted for one without a challenge is one anybody who
/// intercepted the redirect can spend.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_public_client_without_a_challenge_spends_nothing() {
    let plane = Plane::with_actions(&[]).await;
    let code = plane
        .mint_code(support::PUBLIC, REDIRECT, "openid", None)
        .await;

    let (status, body) = ask(
        &plane,
        support::REALM,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("client_id", support::PUBLIC),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// A code outlives nothing. Logging out between authorizing and redeeming has
/// to stop the redemption, or the tokens name a login the gate cannot find.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_login_that_ended_spends_no_code() {
    let plane = Plane::with_actions(&[]).await;
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid", None)
        .await;
    plane.end_login().await;

    let (status, body) = asking(
        &plane,
        support::REALM,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// An id token is what `openid` asks for. Minting one for a scope that did not
/// ask hands out a record of a login nobody requested.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn no_openid_scope_means_no_id_token() {
    let plane = Plane::with_actions(&[]).await;
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "profile", None)
        .await;

    let (status, body) = asking(
        &plane,
        support::REALM,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("id_token").is_none(), "{body}");
    assert!(body.get("access_token").is_some());
}

/// Renewing hands back a fresh set, and the token it hands back is the one that
/// works next. Checking only that a string came out proves nothing about which.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_refresh_token_renews_and_is_replaced_by_the_one_it_hands_back() {
    let plane = Plane::with_actions(&[]).await;
    let first = spend_a_code(&plane, "openid").await;

    let (status, renewed) = renew(&plane, first["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{renewed}");

    let successor = renewed["refresh_token"].as_str().expect("a successor");
    assert_ne!(
        successor,
        first["refresh_token"].as_str().unwrap(),
        "the same token came back, so nothing rotated"
    );
    assert_eq!(plane.claims_of(successor).await["typ"], "Refresh");
    assert_eq!(
        plane
            .claims_of(renewed["access_token"].as_str().unwrap())
            .await["sid"],
        support::SESSION
    );
    assert!(renewed.get("id_token").is_some(), "openid was granted");

    assert_eq!(
        renew(&plane, successor).await.0,
        StatusCode::OK,
        "the successor did not work in its turn"
    );
}

/// A token two rotations back is neither the one the session holds nor the one
/// it just replaced, so it is a replay. The family ends; the login does not,
/// because ending it would sign the user out of every other client and make one
/// stale token a way to do that on demand.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_two_rotations_back_ends_the_family() {
    let plane = Plane::with_actions(&[]).await;
    let first = spend_a_code(&plane, "openid").await;
    let stale = first["refresh_token"].as_str().unwrap().to_owned();

    let second = renew(&plane, &stale).await.1["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let third = renew(&plane, &second).await.1["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, body) = renew(&plane, &stale).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        body["error_description"], "the grant presented was not honoured",
        "the answer said a replay had been detected"
    );

    assert_eq!(
        renew(&plane, &third).await.1["error"],
        "invalid_grant",
        "the newest token in the family kept working after the replay"
    );
    assert!(
        plane.login_is_open(support::SESSION).await,
        "a replay of one client's token signed the user out everywhere"
    );
}

/// The token a rotation just replaced is still accepted. A client that fired two
/// refreshes at once, or retried after a response that never arrived, presents
/// exactly this, and without the window an ordinary double submit would destroy
/// its session.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_double_submit_is_not_a_replay() {
    let plane = Plane::with_actions(&[]).await;
    let first = spend_a_code(&plane, "openid").await;
    let presented = first["refresh_token"].as_str().unwrap().to_owned();

    let (rotated, _) = renew(&plane, &presented).await;
    assert_eq!(rotated, StatusCode::OK);

    let (again, body) = renew(&plane, &presented).await;
    assert_eq!(again, StatusCode::OK, "{body}");
    assert!(
        plane.login_is_open(support::SESSION).await,
        "a double submit ended the login"
    );
}

/// What must be true of the token itself. An access token that renewed would
/// make the longest-lived credential a client holds whichever lives longest.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_a_refresh_token_of_this_client_renews() {
    let plane = Plane::with_actions(&[]).await;
    let granted = spend_a_code(&plane, "openid").await;

    for (label, presented) in [
        ("an access token", granted["access_token"].as_str().unwrap()),
        ("an id token", granted["id_token"].as_str().unwrap()),
        ("not a token at all", "not.a.token"),
    ] {
        assert_eq!(
            renew(&plane, presented).await.1["error"],
            "invalid_grant",
            "{label} renewed"
        );
    }

    // Refused, and nothing else. Read as a refresh token these would name a jti
    // the session does not hold, and the family would end for a token its own
    // holder was entitled to present.
    assert_eq!(
        renew(&plane, granted["refresh_token"].as_str().unwrap())
            .await
            .0,
        StatusCode::OK,
        "presenting an access token ended the family"
    );
}

/// A token is a bearer thing, so the only thing tying one to a client is what it
/// says about one. Without that check the lookup falls through to the presenting
/// client's own session, the identifiers disagree, and one client ends another's
/// family by presenting a token it legitimately holds.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn one_clients_refresh_token_does_not_touch_another_clients_session() {
    let plane = Plane::with_actions(&[]).await;
    let mine = spend_a_code(&plane, "openid").await;

    // The other client gets a family of its own under the same login.
    let code = plane
        .mint_code(support::OTHER, REDIRECT, "openid", None)
        .await;
    let (status, theirs) = asking(
        &plane,
        support::REALM,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
        ],
        Some((support::OTHER, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{theirs}");

    let (refused, _) = asking(
        &plane,
        support::REALM,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", mine["refresh_token"].as_str().unwrap()),
        ],
        Some((support::OTHER, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(refused, StatusCode::BAD_REQUEST);

    // And theirs still works, which is the half a mismatch would have destroyed.
    let (still, body) = asking(
        &plane,
        support::REALM,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", theirs["refresh_token"].as_str().unwrap()),
        ],
        Some((support::OTHER, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(
        still,
        StatusCode::OK,
        "another client's token ended this one's family: {body}"
    );
}

/// A logout has to end the renewals too, or the refresh token outlives the
/// session it was minted from and the logout ended nothing.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_login_that_ended_renews_nothing() {
    let plane = Plane::with_actions(&[]).await;
    let granted = spend_a_code(&plane, "openid").await;
    plane.end_login().await;

    assert_eq!(
        renew(&plane, granted["refresh_token"].as_str().unwrap())
            .await
            .1["error"],
        "invalid_grant"
    );
}

/// An account switched off between two renewals stops renewing. Honouring it at
/// login only leaves it live for as long as its refresh token lasts.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_account_switched_off_renews_nothing() {
    let plane = Plane::with_actions(&[]).await;
    let granted = spend_a_code(&plane, "openid").await;
    plane.disable_subject().await;

    assert_eq!(
        renew(&plane, granted["refresh_token"].as_str().unwrap())
            .await
            .1["error"],
        "invalid_grant"
    );
}

/// Spend a code and return what came back, so a renewal test starts from a real
/// token rather than one a test built.
async fn spend_a_code(plane: &Plane, scope: &str) -> serde_json::Value {
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, scope, None)
        .await;
    let (status, granted) = asking(
        plane,
        support::REALM,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{granted}");
    granted
}

async fn renew(plane: &Plane, refresh_token: &str) -> (StatusCode, serde_json::Value) {
    asking(
        plane,
        support::REALM,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await
}

/// One login, one client, two codes. Keycloak keeps one client session per pair
/// and so must this: a second row for the same pair makes "the session's current
/// refresh token" ambiguous, and renewing with the newer token would find the
/// older row and read a legitimate renewal as a replay.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_second_code_for_one_client_does_not_fork_the_session() {
    let plane = Plane::with_actions(&[]).await;
    let first = spend_a_code(&plane, "openid").await;
    let second = spend_a_code(&plane, "openid").await;

    assert_eq!(
        renew(&plane, second["refresh_token"].as_str().unwrap())
            .await
            .0,
        StatusCode::OK,
        "the newest token was read against another row and taken for a replay"
    );
    assert!(
        plane.login_is_open(support::SESSION).await,
        "a legitimate second authorization ended the login"
    );
    // The first token belongs to the same pair, so it is the one that rotated
    // away and is now a replay.
    assert_eq!(
        renew(&plane, first["refresh_token"].as_str().unwrap())
            .await
            .1["error"],
        "invalid_grant"
    );
}
