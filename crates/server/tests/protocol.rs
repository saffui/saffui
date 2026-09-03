mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use data_encoding::BASE64;
use server::api::config::{Plane as Mounted, register};
use support::{Plane, cookie_value, pkce_pair, urlencode};

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
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
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

use support::REDIRECT;

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
    for never_in_an_id_token in ["typ", "scope"] {
        assert!(
            identity.get(never_in_an_id_token).is_none(),
            "an identity token carried '{never_in_an_id_token}', which no relying party asked for"
        );
    }
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

/// Where a login starts. Everything is in the query, so the helper takes pairs
/// and a test names only what it means to get wrong.
async fn authorize(plane: &Plane, query: &[(&str, &str)]) -> (StatusCode, String) {
    let (status, location, _) = authorize_with_cookies(plane, query).await;
    (status, location)
}

/// The same, with what the response asked the browser to keep.
async fn authorize_with_cookies(
    plane: &Plane,
    query: &[(&str, &str)],
) -> (StatusCode, String, Vec<String>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let asked = query
        .iter()
        .map(|(key, value)| format!("{key}={}", urlencode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let request = test::TestRequest::get()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/auth?{asked}",
            support::REALM
        ))
        .to_request();
    let response = test::call_service(&app, request).await;
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let set = response
        .headers()
        .get_all("set-cookie")
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    (status, location, set)
}

fn started(client_id: &str) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".to_owned()),
        ("client_id", client_id.to_owned()),
        ("redirect_uri", REDIRECT.to_owned()),
        ("scope", "openid".to_owned()),
        ("state", "opaque-state".to_owned()),
    ]
}

fn as_pairs<'a>(owned: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    owned
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect()
}

/// A request that checks out opens a login and sends the browser to it. The
/// identifier travels in the URL because there is no cookie to carry it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_request_that_checks_out_opens_a_login() {
    let plane = Plane::with_actions(&[]).await;
    let asked = started(support::CONFIDENTIAL);
    let (status, location, set) = authorize_with_cookies(&plane, &as_pairs(&asked)).await;

    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location, "https://login.test",
        "the browser was sent somewhere other than the configured login"
    );
    assert!(
        !location.contains("auth_session"),
        "the login's identifier travelled in a URL: {location}"
    );

    let binding = set
        .iter()
        .find(|header| header.starts_with(support::AUTH_SESSION_COOKIE))
        .expect("the browser was not bound to the login it just opened");
    for hardening in ["HttpOnly", "Secure", "SameSite=Lax"] {
        assert!(
            binding.contains(hardening),
            "{hardening} missing: {binding}"
        );
    }
    assert!(
        binding.contains(&format!("Path=/realms/{}", support::REALM)),
        "one realm's binding was offered to another: {binding}"
    );
}

/// What may never be redirected. RFC 6749 4.1.2.1: a request whose client or
/// redirect cannot be trusted is shown to the user, because sending it onward is
/// the open redirector.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_untrusted_redirect_is_shown_and_never_sent() {
    let plane = Plane::with_actions(&[]).await;

    for (label, client_id, redirect) in [
        ("no such client", "no-such-client", REDIRECT),
        (
            "a redirect the client never registered",
            support::CONFIDENTIAL,
            "https://attacker.example/collect",
        ),
        (
            "a redirect that only extends a registered one",
            support::CONFIDENTIAL,
            "https://app.example/callback/../../evil",
        ),
        ("no redirect at all", support::CONFIDENTIAL, ""),
    ] {
        let (status, location) = authorize(
            &plane,
            &[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", redirect),
                ("state", "opaque-state"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
        assert!(location.is_empty(), "{label} was redirected to {location}");
    }
}

/// Once the client and the redirect are established, a refusal travels to the
/// client, and carries the state it asked to have echoed.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_refusal_after_that_goes_to_the_client_with_its_state() {
    let plane = Plane::with_actions(&[]).await;

    let (status, location) = authorize(
        &plane,
        &[
            ("response_type", "token"),
            ("client_id", support::CONFIDENTIAL),
            ("redirect_uri", REDIRECT),
            ("scope", "openid"),
            ("state", "opaque state/&"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location.starts_with(REDIRECT),
        "the refusal did not reach the client: {location}"
    );
    assert!(
        location.contains("error=unsupported_response_type"),
        "{location}"
    );
    assert!(
        location.contains("state=opaque%20state%2F%26"),
        "the state was not echoed, or not encoded: {location}"
    );
}

/// A public client authenticates with nothing, so the challenge is the whole of
/// its proof. Asked for here rather than only at redemption, where it is too
/// late to have asked.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_public_client_starts_nothing_without_a_challenge() {
    let plane = Plane::with_actions(&[]).await;
    let (_, refused) = authorize(
        &plane,
        &[
            ("response_type", "code"),
            ("client_id", support::PUBLIC),
            ("redirect_uri", REDIRECT),
            ("scope", "openid"),
        ],
    )
    .await;
    assert!(refused.contains("error=invalid_request"), "{refused}");

    let (status, _, set) = authorize_with_cookies(
        &plane,
        &[
            ("response_type", "code"),
            ("client_id", support::PUBLIC),
            ("redirect_uri", REDIRECT),
            ("scope", "openid"),
            ("code_challenge", "a-challenge"),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        cookie_value(&set, support::AUTH_SESSION_COOKIE).is_some(),
        "a challenge was offered and no login was opened"
    );

    // A challenge with no method named. RFC 7636 §4.3 reads that as `plain`, so
    // accepting the omission accepts `plain` under another spelling and the
    // refusal of the word refuses nothing.
    let (_, unnamed) = authorize(
        &plane,
        &[
            ("response_type", "code"),
            ("client_id", support::PUBLIC),
            ("redirect_uri", REDIRECT),
            ("scope", "openid"),
            ("code_challenge", "a-challenge"),
        ],
    )
    .await;
    assert!(
        unnamed.contains("error=invalid_request"),
        "a challenge with no method named was accepted: {unnamed}"
    );

    // An unknown method must not be read as the weaker one.
    let (_, unknown) = authorize(
        &plane,
        &[
            ("response_type", "code"),
            ("client_id", support::PUBLIC),
            ("redirect_uri", REDIRECT),
            ("scope", "openid"),
            ("code_challenge", "a-challenge"),
            ("code_challenge_method", "S512"),
        ],
    )
    .await;
    assert!(unknown.contains("error=invalid_request"), "{unknown}");
}

/// Answer a login step, carrying the cookie that says which login it is.
async fn login_step(
    plane: &Plane,
    binding: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value, Vec<String>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut request = test::TestRequest::post()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/login",
            support::REALM
        ))
        .set_json(&body);
    if let Some(binding) = binding {
        request = request.insert_header((
            "cookie",
            format!("{}={binding}", support::AUTH_SESSION_COOKIE),
        ));
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    let set = response
        .headers()
        .get_all("set-cookie")
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    (status, test::read_body_json(response).await, set)
}

/// The whole loop, once: authorize, answer the step, spend the code. Every
/// piece was tested against a planted fixture before this; this is the first
/// time the pieces have to agree with each other.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_browser_logs_in_and_the_client_spends_what_it_carries() {
    let plane = Plane::with_actions(&[]).await;
    let asked = started(support::CONFIDENTIAL);
    let (_, _, opened) = authorize_with_cookies(&plane, &as_pairs(&asked)).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");

    let (status, told, signed_in) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "admitted");
    assert!(
        cookie_value(&signed_in, support::SSO_COOKIE).is_some(),
        "the browser was not bound to the login it just completed"
    );
    // Told to expire, not merely absent. A response that says nothing about it
    // leaves the browser offering a login that is gone.
    let expiring = signed_in
        .iter()
        .find(|header| header.starts_with(support::AUTH_SESSION_COOKIE))
        .expect("the login in progress was not told to expire");
    assert!(
        expiring.contains("Max-Age=0"),
        "the login in progress is over and its cookie outlived it: {expiring}"
    );

    let landing = told["redirect_to"].as_str().expect("somewhere to land");
    assert!(landing.starts_with(REDIRECT), "{landing}");
    assert!(
        landing.contains("state=opaque-state"),
        "the state was not echoed back: {landing}"
    );
    let code = landing
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();

    let (spent, granted) = asking(
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
    assert_eq!(spent, StatusCode::OK, "{granted}");
    assert_eq!(
        plane
            .claims_of(granted["access_token"].as_str().unwrap())
            .await["sub"],
        support::SUBJECT
    );
    assert!(granted.get("id_token").is_some(), "openid was asked for");
}

/// A wrong password refuses without ending the login, so the same login can be
/// answered again. Ending it would make one typo a fresh trip through
/// `/authorize`.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_wrong_answer_refuses_and_the_login_survives() {
    let plane = Plane::with_actions(&[]).await;
    let asked = started(support::CONFIDENTIAL);
    let (_, _, opened) = authorize_with_cookies(&plane, &as_pairs(&asked)).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");

    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": "not-the-password" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(told["status"], "refused");

    let (again, admitted, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(again, StatusCode::OK, "{admitted}");
    assert_eq!(admitted["status"], "admitted");
}

/// A login mints one code. Leaving the row behind would let the same answer be
/// replayed into a second code for one authorization.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn one_authorization_mints_one_code() {
    let plane = Plane::with_actions(&[]).await;
    let asked = started(support::CONFIDENTIAL);
    let (_, _, opened) = authorize_with_cookies(&plane, &as_pairs(&asked)).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let answer = serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD });

    assert_eq!(
        login_step(&plane, Some(&auth_session), answer.clone())
            .await
            .1["status"],
        "admitted"
    );

    let (status, told, _) = login_step(&plane, Some(&auth_session), answer).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(told["status"], "no-such-login");
}

/// A login nobody opened is answered the way one that expired is, and the same
/// way a realm this deployment does not hold is. None of the three is something
/// an unauthenticated caller gets to tell apart.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_login_nobody_opened_is_not_distinguishable() {
    let plane = Plane::with_actions(&[]).await;
    let (status, told, _) = login_step(
        &plane,
        Some("never-opened"),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(told["status"], "no-such-login");

    // And with no cookie at all, which is what a caller who read an identifier
    // off a log has.
    let (bare, refused, _) = login_step(
        &plane,
        None,
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(bare, StatusCode::NOT_FOUND);
    assert_eq!(refused["status"], "no-such-login");
}

async fn fetched(plane: &Plane, path: &str) -> (StatusCode, serde_json::Value, Vec<String>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
    let status = response.status();
    let headers = response
        .headers()
        .get_all("cache-control")
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    (status, test::read_body_json(response).await, headers)
}

/// What a relying party verifies with, and what the document that points at it
/// says. Read together, because a key set nobody can find is not published.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_realm_publishes_what_verifies_its_tokens() {
    let plane = Plane::with_actions(&[]).await;
    let (status, jwks, cached) = fetched(
        &plane,
        &format!("/realms/{}/protocol/openid-connect/certs", support::REALM),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let keys = jwks["keys"].as_array().expect("a key set");
    assert!(!keys.is_empty(), "the realm published nothing: {jwks}");
    let key = &keys[0];
    assert_eq!(key["kid"], support::KID);
    assert_eq!(key["use"], "sig", "a verifier has to guess which key signs");
    assert!(key.get("alg").is_some(), "no algorithm named: {key}");
    assert!(
        key.get("d").is_none(),
        "a private half reached the public set: {key}"
    );
    // A JWK a verifier can actually build a key from. RFC 7517 §4.1 makes `kty`
    // the only always-required member, and every family needs its own on top.
    assert_eq!(key["kty"], "EC", "{key}");
    for member in ["crv", "x", "y"] {
        assert!(
            key.get(member)
                .and_then(serde_json::Value::as_str)
                .is_some(),
            "an EC key with no {member}: {key}"
        );
    }
    assert!(
        cached.iter().any(|value| value.contains("max-age")),
        "the set a verifier reads on every token was made uncacheable"
    );
}

/// Everything advertised is derived. A document naming an endpoint this build
/// does not mount, or an algorithm the signer would refuse, configures every
/// client wrong at once and does it silently.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn discovery_advertises_only_what_is_there() {
    let plane = Plane::with_actions(&[]).await;
    let (status, document, _) = fetched(
        &plane,
        &format!(
            "/realms/{}/.well-known/openid-configuration",
            support::REALM
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let issuer = document["issuer"].as_str().expect("an issuer");
    assert_eq!(issuer, format!("https://id.test/realms/{}", support::REALM));

    // Every endpoint it names is one that answers, and every one it omits is one
    // that would have been a 404 the client reports as this realm being broken.
    for (named, path) in [
        ("authorization_endpoint", "/protocol/openid-connect/auth"),
        ("token_endpoint", "/protocol/openid-connect/token"),
        ("jwks_uri", "/protocol/openid-connect/certs"),
        ("userinfo_endpoint", "/protocol/openid-connect/userinfo"),
        ("end_session_endpoint", "/protocol/openid-connect/logout"),
        (
            "introspection_endpoint",
            "/protocol/openid-connect/introspect",
        ),
        ("revocation_endpoint", "/protocol/openid-connect/revoke"),
    ] {
        assert_eq!(
            document[named].as_str().unwrap(),
            format!("{issuer}{path}"),
            "{named}"
        );
    }
    assert!(
        document.get("registration_endpoint").is_none(),
        "registration_endpoint is advertised and does not answer"
    );

    // The algorithms come off the keys the realm holds, so a realm holding one
    // curve cannot advertise another.
    let (_, jwks, _) = fetched(
        &plane,
        &format!("/realms/{}/protocol/openid-connect/certs", support::REALM),
    )
    .await;
    let held: Vec<&str> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|key| key["alg"].as_str())
        .collect();
    let advertised = document["id_token_signing_alg_values_supported"]
        .as_array()
        .expect("an algorithm list");
    assert!(!advertised.is_empty());
    for alg in advertised {
        assert!(
            held.contains(&alg.as_str().unwrap()),
            "{alg} is advertised and no key holds it"
        );
    }

    // `plain` compares the verifier against a challenge that travelled in the
    // authorize request, and the endpoint refuses it.
    assert_eq!(
        document["code_challenge_methods_supported"]
            .as_array()
            .unwrap(),
        &vec![serde_json::json!("S256")]
    );

    // Discovery §3 reads an absent flag as a default that is not neutral, so
    // each is stated and each is what the endpoints do.
    for (named, expected) in [
        ("request_parameter_supported", true),
        ("request_uri_parameter_supported", true),
        ("require_pushed_authorization_requests", false),
        ("require_request_uri_registration", true),
        ("claims_parameter_supported", true),
        ("authorization_response_iss_parameter_supported", true),
    ] {
        assert_eq!(
            document[named].as_bool(),
            Some(expected),
            "{named} was left to a default that is not what this build does"
        );
    }
}

/// A request object is refused, not ignored. A client that sends one believes
/// it governs; reading the query instead hands back a code minted against
/// parameters the client never signed.
///
/// The two halves refuse differently on purpose. An object the client signed
/// arrives with a query whose `redirect_uri` is registered, so the error is
/// delivered there. A reference is the whole request, so one this server never
/// issued leaves nothing to deliver to and nothing to fetch.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_request_object_is_refused_rather_than_ignored() {
    let plane = Plane::with_actions(&[]).await;
    let sent = |named: &'static str| {
        [
            ("response_type", "code"),
            ("client_id", support::CONFIDENTIAL),
            ("redirect_uri", REDIRECT),
            ("state", "opaque-state"),
            (named, "https://app.example/object.jwt"),
        ]
    };

    // This client registered no signing algorithm, so it may not state one.
    let (status, location) = authorize(&plane, &sent("request")).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location.contains("error=request_not_supported"),
        "an object was ignored: {location}"
    );

    let (status, _, _) = authorize_with_cookies(&plane, &sent("request_uri")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a URL was fetched");
}

/// A realm this deployment does not hold publishes nothing. Its existence is not
/// what these two hide: which clients it holds and which users are, and neither
/// is answerable here.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn no_such_realm_publishes_nothing() {
    let plane = Plane::with_actions(&[]).await;
    for path in [
        "/realms/no-such-realm/protocol/openid-connect/certs",
        "/realms/no-such-realm/.well-known/openid-configuration",
    ] {
        assert_eq!(
            fetched(&plane, path).await.0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}
/// The same, carrying the cookie that says this browser is already signed in.
async fn authorize_signed_in(
    plane: &Plane,
    query: &[(&str, &str)],
    session: &str,
) -> (StatusCode, String) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let asked = query
        .iter()
        .map(|(key, value)| format!("{key}={}", urlencode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?{asked}",
                support::REALM
            ))
            .insert_header(("cookie", format!("{}={session}", support::SSO_COOKIE)))
            .to_request(),
    )
    .await;
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default();
    (status, location)
}

/// Single sign-on. A browser that already holds a login gets its code without
/// seeing a screen, and a second client is the point: without this every
/// `/authorize` is a fresh sign-in and the product is not one.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_browser_already_signed_in_sees_no_screen() {
    let plane = Plane::with_actions(&[]).await;

    // Sign in once, the long way.
    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, signed_in) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(told["status"], "admitted");
    let session = cookie_value(&signed_in, support::SSO_COOKIE).expect("a login");

    // A second client, same browser. No screen.
    let (status, landing) = authorize_signed_in(
        &plane,
        &[
            ("response_type", "code"),
            ("client_id", support::OTHER),
            ("redirect_uri", REDIRECT),
            ("scope", "openid"),
            ("state", "second-client"),
        ],
        &session,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        landing.starts_with(REDIRECT),
        "the browser was sent to a login it did not need: {landing}"
    );
    assert!(landing.contains("state=second-client"), "{landing}");

    // And the code it carries is one the second client can spend.
    let code = landing
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();
    let (spent, granted) = asking(
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
    assert_eq!(spent, StatusCode::OK, "{granted}");
    assert_eq!(
        plane
            .claims_of(granted["access_token"].as_str().unwrap())
            .await["sid"],
        session,
        "the second client's token names a different login"
    );
}

/// A cookie is a claim, not a fact. A login this realm has ended, or one it
/// never had, sends the browser to authenticate rather than minting anything.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_cookie_naming_no_live_login_starts_one() {
    let plane = Plane::with_actions(&[]).await;
    let owned = started(support::CONFIDENTIAL);
    let asked = as_pairs(&owned);

    for (label, session) in [
        ("a login nobody opened", "never-opened".to_owned()),
        (
            "the planted login, which is open",
            support::SESSION.to_owned(),
        ),
    ] {
        let (status, location) = authorize_signed_in(&plane, &asked, &session).await;
        assert_eq!(status, StatusCode::FOUND, "{label}");
        if session == "never-opened" {
            assert_eq!(location, "https://login.test", "{label}: {location}");
        } else {
            assert!(location.starts_with(REDIRECT), "{label}: {location}");
        }
    }

    // The code carries the login's own instant, not this one. A client asking
    // how recently the user authenticated is asking about the login, and a
    // freshly stamped value answers a question nobody asked.
    let authenticated_at = plane.backdate_authentication(support::SESSION, 3_600).await;
    let (_, landing) = authorize_signed_in(&plane, &asked, support::SESSION).await;
    let code = landing
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();
    let (_, granted) = asking(
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
    assert_eq!(
        plane
            .claims_of(granted["id_token"].as_str().expect("an id token"))
            .await["auth_time"],
        authenticated_at,
        "the code was stamped with the redemption rather than the login"
    );

    // Ended, and the browser still holds the cookie.
    plane.end_login().await;
    let (_, after) = authorize_signed_in(&plane, &asked, support::SESSION).await;
    assert_eq!(
        after, "https://login.test",
        "a login this realm ended still minted a code"
    );
}

async fn userinfo(plane: &Plane, bearer: Option<&str>) -> (StatusCode, serde_json::Value, String) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut request = test::TestRequest::get().uri(&format!(
        "/realms/{}/protocol/openid-connect/userinfo",
        support::REALM
    ));
    if let Some(bearer) = bearer {
        request = request.insert_header(("authorization", format!("Bearer {bearer}")));
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    let challenge = response
        .headers()
        .get("www-authenticate")
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default();
    (status, test::read_body_json(response).await, challenge)
}

/// The scope gate. A token granted `openid profile` yields a username; the same
/// token does not yield an address, because `email` is a scope this client is
/// not attached to and `/authorize` dropped it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_yields_what_its_scope_allows_and_nothing_else() {
    let plane = Plane::with_actions(&[]).await;
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid profile", None)
        .await;
    let (_, granted) = asking(
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

    let (status, told, _) = userinfo(&plane, granted["access_token"].as_str()).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["sub"], support::SUBJECT);
    assert_eq!(told["preferred_username"], support::SUBJECT);
    assert!(
        told.get("email").is_none(),
        "an address was released to a scope that did not ask for it: {told}"
    );
}

/// The scope a client asked for is not the scope it gets. Requesting `email`
/// when nothing attached it must not release the address, or the entitlement is
/// decoration.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_scope_the_client_is_not_attached_to_releases_nothing() {
    let plane = Plane::with_actions(&[]).await;
    let asked = vec![
        ("response_type", "code"),
        ("client_id", support::CONFIDENTIAL),
        ("redirect_uri", REDIRECT),
        ("scope", "openid profile email"),
        ("state", "s"),
    ];
    let (_, _, opened) = authorize_with_cookies(&plane, &asked).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    let landing = told["redirect_to"].as_str().expect("somewhere to land");
    let code = landing
        .split_once("code=")
        .unwrap()
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();

    let (_, granted) = asking(
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
    assert_eq!(
        granted["scope"], "openid profile",
        "the client was granted a scope nothing attached to it"
    );

    let (_, claims, _) = userinfo(&plane, granted["access_token"].as_str()).await;
    assert!(
        claims.get("email").is_none(),
        "asking for a scope was enough to get its claims: {claims}"
    );
}

/// What is not an acceptable token. An id token is a record of a login and names
/// the client as its audience: accepting one here would let anything that saw a
/// login read the person behind it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_an_access_token_of_this_realm_is_answered() {
    let plane = Plane::with_actions(&[]).await;
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid", None)
        .await;
    let (_, granted) = asking(
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

    for (label, presented) in [
        ("an id token", granted["id_token"].as_str()),
        ("a refresh token", granted["refresh_token"].as_str()),
        ("not a token at all", Some("not.a.token")),
        ("nothing", None),
    ] {
        let (status, told, challenge) = userinfo(&plane, presented).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{label}");
        assert_eq!(told["error"], "invalid_token", "{label}: {told}");
        // RFC 6750 §3: a bearer failure carries a challenge.
        assert!(
            challenge.starts_with("Bearer "),
            "{label} was refused without a challenge: {challenge:?}"
        );
    }
}

/// Sign in, and hand back the SSO session the browser now holds.
async fn signed_in_once(plane: &Plane) -> String {
    let (_, _, opened) =
        authorize_with_cookies(plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, signed_in) = login_step(
        plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(told["status"], "admitted", "{told}");
    cookie_value(&signed_in, support::SSO_COOKIE).expect("a login")
}

fn asking_for<'a>(extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut asked = vec![
        ("response_type", "code"),
        ("client_id", support::CONFIDENTIAL),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("state", "s"),
    ];
    asked.extend_from_slice(extra);
    asked
}

/// `prompt=login` is the client saying "prove it again". Honouring it only for
/// an old session would make it useless for the case it exists for.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn prompt_login_authenticates_again_however_fresh_the_session() {
    let plane = Plane::with_actions(&[]).await;
    let session = signed_in_once(&plane).await;

    // Without it, the same browser is admitted straight away.
    let (_, straight) = authorize_signed_in(&plane, &asking_for(&[]), &session).await;
    assert!(straight.starts_with(REDIRECT), "{straight}");

    let (status, sent) =
        authorize_signed_in(&plane, &asking_for(&[("prompt", "login")]), &session).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        sent, "https://login.test",
        "a session minutes old satisfied prompt=login"
    );
}

/// `max_age` asks how long ago the user authenticated, not how long ago the
/// session began. A session refreshed for an hour is not a recent
/// authentication, and conflating them is how `max_age` silently stops working.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn max_age_is_measured_against_the_authentication() {
    let plane = Plane::with_actions(&[]).await;
    let session = signed_in_once(&plane).await;

    // Backdated rather than raced. A test that leans on how long two requests
    // take measures the machine, not the rule.
    plane.backdate_authentication(&session, 3_600).await;

    let (_, generous) =
        authorize_signed_in(&plane, &asking_for(&[("max_age", "7200")]), &session).await;
    assert!(
        generous.starts_with(REDIRECT),
        "an authentication inside the window was refused: {generous}"
    );

    let (_, stale) = authorize_signed_in(&plane, &asking_for(&[("max_age", "60")]), &session).await;
    assert_eq!(
        stale, "https://login.test",
        "an authentication an hour old satisfied a one minute window"
    );
}

/// "Never interact" and "authenticate again" contradict each other, and the
/// contradiction is the client's to resolve.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn prompt_none_refuses_rather_than_showing_a_screen() {
    let plane = Plane::with_actions(&[]).await;

    // No session at all: there is nothing to be silent about.
    let (_, cold) = authorize(&plane, &asking_for(&[("prompt", "none")])).await;
    assert!(cold.contains("error=login_required"), "{cold}");

    // A session that satisfies the request is answered without a screen.
    let session = signed_in_once(&plane).await;
    let (_, warm) = authorize_signed_in(&plane, &asking_for(&[("prompt", "none")]), &session).await;
    assert!(warm.starts_with(REDIRECT), "{warm}");

    // One that does not is refused rather than sent to a screen it forbade.
    plane.backdate_authentication(&session, 3_600).await;
    let (_, stale) = authorize_signed_in(
        &plane,
        &asking_for(&[("prompt", "none"), ("max_age", "60")]),
        &session,
    )
    .await;
    assert!(stale.contains("error=login_required"), "{stale}");

    // `none` with anything else contradicts itself.
    let (_, both) = authorize(&plane, &asking_for(&[("prompt", "none login")])).await;
    assert!(both.contains("error=invalid_request"), "{both}");
}

/// A level this realm maps but nothing here reaches sends the user back to
/// authenticate; one it does not map at all is refused outright, because
/// authenticating first and failing afterwards wastes the user's time.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_level_above_what_was_reached_is_not_admitted() {
    let plane = Plane::with_actions(&[]).await;
    let session = signed_in_once(&plane).await;

    let (_, reached) = authorize_signed_in(
        &plane,
        &asking_for(&[("acr_values", support::PASSWORD_ACR)]),
        &session,
    )
    .await;
    assert!(reached.starts_with(REDIRECT), "{reached}");

    let (_, above) = authorize_signed_in(
        &plane,
        &asking_for(&[("acr_values", support::STRONG_ACR)]),
        &session,
    )
    .await;
    assert_eq!(
        above, "https://login.test",
        "a level the session never reached was admitted"
    );

    // Unmapped and voluntary: a hint the provider may ignore, so the login
    // proceeds at whatever level it reaches.
    let (_, unknown) = authorize_signed_in(
        &plane,
        &asking_for(&[("acr_values", "a-level-nobody-defined")]),
        &session,
    )
    .await;
    assert!(unknown.starts_with(REDIRECT), "{unknown}");
}

/// The claim reports what was reached, never what was asked for. A server that
/// echoes the request turns the mechanism into decoration, and a relying party
/// reads it to decide whether to release money.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_acr_claim_reports_what_was_reached() {
    let plane = Plane::with_actions(&[]).await;
    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    let landing = told["redirect_to"].as_str().expect("somewhere to land");
    let code = landing
        .split_once("code=")
        .unwrap()
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();

    let (_, granted) = asking(
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
    let identity = plane
        .claims_of(granted["id_token"].as_str().expect("an id token"))
        .await;
    assert_eq!(
        identity["acr"],
        support::PASSWORD_ACR,
        "the claim did not report the level a password reaches"
    );
    assert_ne!(
        identity["acr"],
        support::STRONG_ACR,
        "the claim reported a level nothing here can reach"
    );
}

/// A realm that maps levels advertises them weakest first, and the `acr` claim
/// with them. One that maps nothing omits both rather than publishing an empty
/// list, which would claim it supports no authentication contexts at all.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn discovery_advertises_the_levels_the_realm_maps() {
    let plane = Plane::with_actions(&[]).await;
    let (_, document, _) = fetched(
        &plane,
        &format!(
            "/realms/{}/.well-known/openid-configuration",
            support::REALM
        ),
    )
    .await;

    assert_eq!(
        document["acr_values_supported"].as_array().unwrap(),
        &vec![
            serde_json::json!(support::PASSWORD_ACR),
            serde_json::json!(support::STRONG_ACR),
        ],
        "the levels were not advertised weakest first"
    );
    assert!(
        document["claims_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("acr")),
        "levels are mapped and the claim is not advertised"
    );
}

/// A flag nobody set is not permission. Reading an absent
/// `standard_flow_enabled` as allowed opens every client registered before the
/// flag existed, which is every client an import brings.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_without_the_flow_enabled_starts_nothing() {
    let plane = Plane::with_actions(&[]).await;
    plane.set_standard_flow(support::CONFIDENTIAL, None).await;

    let (status, location) = authorize(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location.contains("error=unauthorized_client"),
        "a client with no flow flag was let through: {location}"
    );

    plane
        .set_standard_flow(support::CONFIDENTIAL, Some(false))
        .await;
    let (_, off) = authorize(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    assert!(off.contains("error=unauthorized_client"), "{off}");
}

/// The flag is read again where the code is spent. An operator who switches the
/// flow off expects the codes already in flight to stop working, and a check
/// that only guards the mint leaves them spendable.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_code_minted_before_the_flow_was_switched_off_is_not_spendable() {
    let plane = Plane::with_actions(&[]).await;
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid", None)
        .await;
    plane
        .set_standard_flow(support::CONFIDENTIAL, Some(false))
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
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unauthorized_client", "{body}");
}

/// `openid` is what says a request is an OpenID Connect one. The cost is stated
/// rather than hidden: a client that never asks for it is refused here, and
/// refused with the code that says which parameter was wrong.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_request_that_never_asks_for_openid_is_refused() {
    let plane = Plane::with_actions(&[]).await;

    for (label, scope) in [
        ("no scope at all", None),
        ("a scope that is not openid", Some("profile")),
        // Whole values, never prefixes.
        ("a longer name that starts the same", Some("openid_extra")),
    ] {
        let mut asked = vec![
            ("response_type", "code"),
            ("client_id", support::CONFIDENTIAL),
            ("redirect_uri", REDIRECT),
            ("state", "s"),
        ];
        if let Some(scope) = scope {
            asked.push(("scope", scope));
        }
        let (status, location) = authorize(&plane, &asked).await;
        assert_eq!(status, StatusCode::FOUND, "{label}");
        assert!(
            location.contains("error=invalid_scope"),
            "{label}: {location}"
        );
    }
}

/// What `profile` releases, and what it does not. The suite only requires `sub`
/// and forbids claims a scope did not ask for, but a provider that answers a
/// `profile` request with a username alone is one no relying party can build a
/// screen from.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_profile_scope_releases_the_claims_it_names() {
    let plane = Plane::with_actions(&[]).await;
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid profile", None)
        .await;
    let (_, granted) = asking(
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

    let (status, told, _) = userinfo(&plane, granted["access_token"].as_str()).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["sub"], support::SUBJECT);
    assert_eq!(told["preferred_username"], support::SUBJECT);
    assert_eq!(told["given_name"], support::GIVEN_NAME);
    assert_eq!(told["family_name"], support::FAMILY_NAME);
    assert_eq!(
        told["name"],
        format!("{} {}", support::GIVEN_NAME, support::FAMILY_NAME),
        "the full name was not composed from the halves the realm holds"
    );

    // Absent rather than empty. A claim released blank is one a relying party
    // reads as a value and shows.
    for unheld in ["nickname", "gender", "birthdate"] {
        assert!(
            told.get(unheld).is_none(),
            "{unheld} was released for an attribute the realm does not hold: {told}"
        );
    }
    // And nothing another scope gates. This is what the conformance suite
    // actually asserts.
    assert!(told.get("email").is_none(), "{told}");
    assert!(told.get("phone_number").is_none(), "{told}");
}

/// A scope granted without `profile` releases none of it, which is the negative
/// the conformance suite checks.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_without_the_profile_scope_carries_no_name() {
    let plane = Plane::with_actions(&[]).await;
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid", None)
        .await;
    let (_, granted) = asking(
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

    let (_, told, _) = userinfo(&plane, granted["access_token"].as_str()).await;
    for withheld in ["name", "given_name", "family_name", "preferred_username"] {
        assert!(
            told.get(withheld).is_none(),
            "{withheld} was released to a token that never asked for profile: {told}"
        );
    }
    assert_eq!(told["sub"], support::SUBJECT, "sub is always released");
}

/// The page's answer: the same request, posted, with the person's yes.
async fn logout_confirmed(
    plane: &Plane,
    form: &[(&str, &str)],
    session: Option<&str>,
) -> (StatusCode, String, Vec<String>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut fields: Vec<(&str, &str)> = form.to_vec();
    fields.push(("confirmed", "yes"));
    let mut request = test::TestRequest::post()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/logout",
            support::REALM
        ))
        .set_form(fields);
    if let Some(session) = session {
        request = request.insert_header(("cookie", format!("{}={session}", support::SSO_COOKIE)));
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let set = response
        .headers()
        .get_all("set-cookie")
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    (status, location, set)
}

async fn logout(
    plane: &Plane,
    query: &[(&str, &str)],
    session: Option<&str>,
) -> (StatusCode, String, Vec<String>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let asked = query
        .iter()
        .map(|(key, value)| format!("{key}={}", urlencode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let mut request = test::TestRequest::get().uri(&format!(
        "/realms/{}/protocol/openid-connect/logout?{asked}",
        support::REALM
    ));
    if let Some(session) = session {
        request = request.insert_header(("cookie", format!("{}={session}", support::SSO_COOKIE)));
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let set = response
        .headers()
        .get_all("set-cookie")
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    (status, location, set)
}

/// A logout ends the login and stops everything hanging off it: the browser is
/// no longer signed in, and the refresh token minted from that login renews
/// nothing.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn logging_out_ends_the_login_and_what_hangs_off_it() {
    let plane = Plane::with_actions(&[]).await;
    let session = signed_in_once(&plane).await;

    // A token family from *that* login. Minted through `/authorize` carrying the
    // cookie, because a code the fixture plants names the planted session and
    // would hang the family off a login this test never ends.
    let (_, landing) = authorize_signed_in(&plane, &asking_for(&[]), &session).await;
    let code = landing
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();
    let (_, granted) = asking(
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

    // Nothing vouched for the request, so the person is asked and nothing
    // has ended yet.
    let (status, _, cleared) = logout(&plane, &[], Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !cleared
            .iter()
            .any(|header| header.starts_with(support::SSO_COOKIE)),
        "the browser was told to forget a login that was not ended"
    );
    assert!(plane.login_is_open(&session).await, "ended without asking");

    // The identity token the client holds names this very login: vouched.
    let hint = granted["id_token"].as_str().expect("an id token");
    let (status, _, cleared) = logout(&plane, &[("id_token_hint", hint)], Some(&session)).await;
    assert_eq!(status, StatusCode::OK);
    let expiring = cleared
        .iter()
        .find(|header| header.starts_with(support::SSO_COOKIE))
        .expect("the browser was not told to forget its login");
    assert!(expiring.contains("Max-Age=0"), "{expiring}");

    assert!(
        !plane.login_is_open(&session).await,
        "the row still says the user is signed in"
    );
    // Transitioned, not deleted: a session that ended is not one that never
    // happened, and the row is the record of it.
    assert!(
        plane.login_exists(&session).await,
        "the record of the login was destroyed rather than closed"
    );

    assert_eq!(
        renew(&plane, granted["refresh_token"].as_str().unwrap())
            .await
            .1["error"],
        "invalid_grant",
        "a refresh token outlived the logout"
    );
    assert_eq!(
        userinfo(&plane, granted["access_token"].as_str()).await.0,
        StatusCode::UNAUTHORIZED,
        "an access token outlived the logout"
    );
}

/// Idempotent. No cookie, an unknown session, an already-ended one: all succeed.
/// Reporting "no such session" would answer a question about somebody else's
/// login to whoever asks, and a user clicking twice has still achieved theirs.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn logging_out_says_the_same_thing_however_little_there_was_to_end() {
    let plane = Plane::with_actions(&[]).await;
    let session = signed_in_once(&plane).await;

    for (label, carried) in [
        ("no cookie at all", None),
        ("a session nobody opened", Some("never-opened")),
        ("a live one", Some(session.as_str())),
        ("the same one again", Some(session.as_str())),
    ] {
        let (status, location, _) = logout(&plane, &[], carried).await;
        assert_eq!(status, StatusCode::OK, "{label}");
        assert!(location.is_empty(), "{label} redirected to {location}");
        let (status, location, _) = logout_confirmed(&plane, &[], carried).await;
        assert_eq!(status, StatusCode::OK, "{label}, confirmed");
        assert!(location.is_empty(), "{label} redirected to {location}");
    }
    assert!(!plane.login_is_open(&session).await);
}

/// Where it sends you afterwards is the strict half. An unvalidated redirect
/// here would be an open redirector on an endpoint everyone links to.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_landing_place_is_honoured_only_when_the_client_registered_it() {
    let plane = Plane::with_actions(&[]).await;
    let session = signed_in_once(&plane).await;

    let (status, landing, _) = logout_confirmed(
        &plane,
        &[
            ("post_logout_redirect_uri", support::AFTER_LOGOUT),
            ("client_id", support::CONFIDENTIAL),
            ("state", "opaque state/&"),
        ],
        Some(&session),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(landing.starts_with(support::AFTER_LOGOUT), "{landing}");
    assert!(
        landing.contains("state=opaque%20state%2F%26"),
        "the state was not echoed, or not encoded: {landing}"
    );

    for (label, asked, client) in [
        (
            "somewhere nobody registered",
            "https://attacker.example/collect",
            support::CONFIDENTIAL,
        ),
        // The login callback is registered, and not for this.
        (
            "the callback rather than the landing page",
            REDIRECT,
            support::CONFIDENTIAL,
        ),
        (
            "a client that registered no landing page",
            support::AFTER_LOGOUT,
            "no-such-client",
        ),
    ] {
        let (status, location, _) = logout(
            &plane,
            &[("post_logout_redirect_uri", asked), ("client_id", client)],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{label}");
        assert!(location.is_empty(), "{label} redirected to {location}");
    }

    // And with no client named at all there is nothing to validate against.
    let (status, location, _) = logout(
        &plane,
        &[("post_logout_redirect_uri", support::AFTER_LOGOUT)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(location.is_empty(), "{location}");
}

/// The code the subject's authenticator app showed at that instant.
fn code_at(unix_seconds: u64) -> String {
    use crypto::provider::CryptoProvider as _;
    let provider =
        crypto::provider::openssl::OpenSslProvider::new(&crypto::provider::CryptoConfig {
            fips_required: false,
            pkcs11: None,
        })
        .expect("a software provider");
    let secret = data_encoding::BASE32_NOPAD
        .decode(support::TOTP_SECRET.as_bytes())
        .expect("a base32 secret");
    let code = crypto::otp::totp::totp_at(
        provider.hmac(),
        &secrecy::SecretBox::new(Box::new(secret)),
        unix_seconds,
        crypto::otp::totp::TotpParams::new(crypto::provider::HashAlg::Sha1),
    )
    .expect("a code");
    crypto::otp::totp::format_code(code, 6)
}

/// The code the subject's authenticator app would show right now.
fn current_code() -> String {
    code_for(support::TOTP_SECRET)
}

/// The code an app holding this base32 secret shows right now.
fn code_for(secret: &str) -> String {
    use crypto::provider::CryptoProvider as _;
    let provider =
        crypto::provider::openssl::OpenSslProvider::new(&crypto::provider::CryptoConfig {
            fips_required: false,
            pkcs11: None,
        })
        .expect("a software provider");
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret.as_bytes())
        .expect("a base32 secret");
    let code = crypto::otp::totp::totp_now(
        provider.hmac(),
        &secrecy::SecretBox::new(Box::new(secret)),
        crypto::otp::totp::TotpParams::new(crypto::provider::HashAlg::Sha1),
    )
    .expect("a code");
    crypto::otp::totp::format_code(code, 6)
}

/// A flow of two steps asks for both, and admits only once both are answered.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_second_factor_is_asked_for_and_answered() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .bind_browser_flow(support::CONFIDENTIAL, support::STRONG_FLOW)
        .await;

    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");

    // The password alone is not enough: the code step is still waiting.
    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        told["status"], "challenge",
        "a flow with an unanswered second factor admitted anyway"
    );

    let (status, admitted, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "totp": current_code(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{admitted}");
    assert_eq!(admitted["status"], "admitted");
}

/// RFC 6238 §5.2: a code accepted once is refused when presented again. Without
/// it, intercepting one code buys the whole acceptance window to reuse it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_code_already_spent_is_refused() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .bind_browser_flow(support::CONFIDENTIAL, support::STRONG_FLOW)
        .await;
    let code = current_code();

    let answer = |session: String, code: String| {
        let plane = &plane;
        async move {
            login_step(
                plane,
                Some(&session),
                serde_json::json!({
                    "username": support::SUBJECT,
                    "password": support::PASSWORD,
                    "totp": code,
                }),
            )
            .await
        }
    };

    let (_, _, first) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let one = cookie_value(&first, support::AUTH_SESSION_COOKIE).expect("a binding");
    assert_eq!(answer(one, code.clone()).await.1["status"], "admitted");

    // A second login, same code, still inside its window.
    let (_, _, second) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let two = cookie_value(&second, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (status, told, _) = answer(two, code).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(
        told["status"], "refused",
        "a code spent moments ago was accepted again"
    );
}

/// A code from a step *below* the one already spent is still inside the window,
/// so it has to be refused too. Comparing for difference rather than for order
/// would let an intercepted earlier code through after a later one landed.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_older_code_still_in_its_window_is_refused() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .bind_browser_flow(support::CONFIDENTIAL, support::STRONG_FLOW)
        .await;

    // The step before this one. Still acceptable on its own, since the window
    // reaches either side of now.
    let previous = code_at(chrono::Utc::now().timestamp() as u64 - 30);

    let (_, _, first) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let one = cookie_value(&first, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&one),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "totp": current_code(),
        }),
    )
    .await;
    assert_eq!(told["status"], "admitted", "{told}");

    let (_, _, second) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let two = cookie_value(&second, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (status, replayed, _) = login_step(
        &plane,
        Some(&two),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "totp": previous,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{replayed}");
    assert_eq!(
        replayed["status"], "refused",
        "a code from before the one already spent was accepted"
    );
}

/// A wrong code refuses, and the digits are read the way an app renders them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_code_is_read_as_typed_and_wrong_ones_refuse() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .bind_browser_flow(support::CONFIDENTIAL, support::STRONG_FLOW)
        .await;

    for wrong in ["000000", "not-a-code", ""] {
        let (_, _, opened) =
            authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
        let session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
        let (_, told, _) = login_step(
            &plane,
            Some(&session),
            serde_json::json!({
                "username": support::SUBJECT,
                "password": support::PASSWORD,
                "totp": wrong,
            }),
        )
        .await;
        assert_ne!(told["status"], "admitted", "{wrong} was accepted: {told}");
    }

    // Spaces, as an authenticator app renders them.
    let spaced = current_code();
    let spaced = format!("{} {}", &spaced[..3], &spaced[3..]);
    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "totp": spaced,
        }),
    )
    .await;
    assert_eq!(
        told["status"], "admitted",
        "a code with the spaces an app shows was refused: {told}"
    );
}

/// The level reported is the highest of what actually ran. A flow that reached a
/// second factor is stronger than the password that opened it, and reading only
/// the first would report a level the login exceeded.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn two_factors_reach_the_level_two_factors_are_worth() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .bind_browser_flow(support::CONFIDENTIAL, support::STRONG_FLOW)
        .await;

    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "totp": current_code(),
        }),
    )
    .await;
    let landing = told["redirect_to"].as_str().expect("somewhere to land");
    let code = landing
        .split_once("code=")
        .unwrap()
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();

    let (_, granted) = asking(
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
    assert_eq!(
        plane
            .claims_of(granted["id_token"].as_str().expect("an id token"))
            .await["acr"],
        support::STRONG_ACR,
        "a login that ran two factors reported the level of one"
    );
}

/// A password step issues nothing. The form is the caller's own and the server
/// keeps no state in it, so a body claiming a challenge would have the caller
/// wait for a device nobody asked for.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_password_step_issues_no_challenge() {
    let plane = Plane::with_actions(&[]).await;
    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");

    let (_, told, _) = login_step(&plane, Some(&auth_session), serde_json::json!({})).await;
    assert_eq!(told["status"], "challenge");
    assert!(
        told.get("asks").is_none(),
        "a password form was announced as a challenge: {told}"
    );
}

/// The whole key ceremony, end to end: the challenge is handed out, its other
/// half is remembered, an authenticator answers it, and the login it admits
/// reaches the level a second factor is worth.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_key_answers_the_challenge_it_was_issued() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .bind_browser_flow(support::CONFIDENTIAL, support::KEYED_FLOW)
        .await;
    let mut key = plane.enrol_soft_passkey().await;

    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");

    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "challenge");
    let asks = told.get("asks").expect("a key step issues a challenge");
    assert!(
        asks.get("publicKey").is_some(),
        "not what a browser hands navigator.credentials.get: {asks}"
    );
    // The half the verification will need reached the store, under the step's
    // own name.
    let remembered = plane.login_notes(&auth_session).await;
    assert!(
        remembered.get("webauthn").is_some(),
        "a challenge was handed out and not remembered: {remembered}"
    );

    let (status, admitted, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "webauthn": key.answer(asks, support::ORIGIN),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{admitted}");
    assert_eq!(admitted["status"], "admitted");

    let landing = admitted["redirect_to"].as_str().expect("somewhere to land");
    let code = landing
        .split_once("code=")
        .unwrap()
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();
    let (_, granted) = asking(
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
    assert_eq!(
        plane
            .claims_of(granted["id_token"].as_str().expect("an id token"))
            .await["acr"],
        support::STRONG_ACR,
        "a login that ran a key reported less than a second factor"
    );
}

/// An assertion that does not verify is refused. The signature is flipped
/// rather than dropped, so what fails is the verification and not the parse.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_tampered_assertion_is_refused() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .bind_browser_flow(support::CONFIDENTIAL, support::KEYED_FLOW)
        .await;
    let mut key = plane.enrol_soft_passkey().await;

    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    let asks = told.get("asks").expect("a challenge");

    let mut answer: serde_json::Value =
        serde_json::from_str(&key.answer(asks, support::ORIGIN)).unwrap();
    let signature = answer["response"]["signature"]
        .as_str()
        .expect("a signature")
        .to_owned();
    let mut flipped: Vec<char> = signature.chars().collect();
    flipped[10] = if flipped[10] == 'A' { 'B' } else { 'A' };
    answer["response"]["signature"] = serde_json::json!(flipped.iter().collect::<String>());

    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "webauthn": answer.to_string(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(told["status"], "refused");
}

/// A challenge is bound to the login it was issued for. A valid answer to one
/// login's challenge, presented to another, is a replay of something seen
/// elsewhere.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_answer_to_another_logins_challenge_is_refused() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .bind_browser_flow(support::CONFIDENTIAL, support::KEYED_FLOW)
        .await;
    let mut key = plane.enrol_soft_passkey().await;

    let (_, _, first) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let overheard = cookie_value(&first, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&overheard),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    let answer = key.answer(told.get("asks").expect("a challenge"), support::ORIGIN);

    let (_, _, second) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&second, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert!(
        told.get("asks").is_some(),
        "the second login has its own challenge"
    );

    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "webauthn": answer,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(told["status"], "refused");
}

/// An authenticator's counter only goes up. One that repeats is the signature
/// of a clone being used beside the original, and the whole point of keeping
/// the counter is that this login fails.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_key_that_repeats_its_counter_is_refused() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .bind_browser_flow(support::CONFIDENTIAL, support::KEYED_FLOW)
        .await;
    let mut key = plane.enrol_soft_passkey().await;

    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    let (status, admitted, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "webauthn": key.answer(told.get("asks").expect("a challenge"), support::ORIGIN),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{admitted}");

    // The clone: same key, same state, a counter that has not moved.
    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    key.counter = 0;
    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "webauthn": key.answer(told.get("asks").expect("a challenge"), support::ORIGIN),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(told["status"], "refused");
}

/// A flow that requires a key nobody enrolled refuses rather than asks: a
/// challenge no key can answer is a screen the user waits at forever.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_key_step_with_nothing_enrolled_refuses() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .bind_browser_flow(support::CONFIDENTIAL, support::KEYED_FLOW)
        .await;

    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(told["status"], "refused");
}

/// The realm told this user to enrol a key, so the login pauses after the flow
/// admits: creation options out, attestation in, credential kept, instruction
/// struck. Then the proof that it was all real: the key that was just enrolled
/// answers a keyed flow's challenge and gets its holder in.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_required_key_is_enrolled_and_then_lets_the_subject_in() {
    use models::entities::user::RequiredAction;

    let plane = Plane::with_actions(&[]).await;
    plane
        .require_of_subject(RequiredAction::ConfigureWebauthn)
        .await;
    let mut key = support::soft_key::SoftKey::new();

    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");

    // The password admits the flow, but the login is not over: the realm's
    // instruction runs first.
    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "challenge");
    assert_eq!(told["execution"], "webauthn-register");
    let asks = told.get("asks").expect("creation options");
    assert!(
        asks["publicKey"].get("user").is_some(),
        "not the create ceremony: {asks}"
    );
    assert!(
        plane
            .login_notes(&auth_session)
            .await
            .get("webauthn-register")
            .is_some(),
        "the registration state was not remembered"
    );

    let (status, admitted, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "webauthn_register": key.attest(asks, support::ORIGIN).to_string(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{admitted}");
    assert_eq!(admitted["status"], "admitted");
    assert_eq!(plane.subject_owes().await, vec![], "the instruction stands");
    assert_eq!(
        plane.subject_keys().await,
        vec![key.credential_id.clone()],
        "the ceremony's credential is not what the store holds"
    );

    // The enrolled key is a working credential, not just a row.
    plane
        .bind_browser_flow(support::CONFIDENTIAL, support::KEYED_FLOW)
        .await;
    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "webauthn": key.answer(told.get("asks").expect("a challenge"), support::ORIGIN),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        told["status"], "admitted",
        "a key enrolled through the ceremony could not log in"
    );
}

/// An attestation that does not verify enrols nothing: the login fails, the
/// instruction stands, and no credential reaches the store.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_forged_attestation_is_refused_and_the_instruction_stands() {
    use models::entities::user::RequiredAction;

    let plane = Plane::with_actions(&[]).await;
    plane
        .require_of_subject(RequiredAction::ConfigureWebauthn)
        .await;
    let key = support::soft_key::SoftKey::new();

    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;

    let mut attested = key.attest(told.get("asks").expect("creation options"), support::ORIGIN);
    let blob = attested["response"]["attestationObject"]
        .as_str()
        .expect("an attestation object")
        .to_owned();
    let mut flipped: Vec<char> = blob.chars().collect();
    flipped[10] = if flipped[10] == 'A' { 'B' } else { 'A' };
    attested["response"]["attestationObject"] =
        serde_json::json!(flipped.iter().collect::<String>());

    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "webauthn_register": attested.to_string(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(told["status"], "refused");
    assert_eq!(
        plane.subject_owes().await,
        vec![RequiredAction::ConfigureWebauthn],
        "a forged attestation struck the instruction"
    );
    assert_eq!(
        plane.subject_keys().await,
        Vec::<Vec<u8>>::new(),
        "a forged attestation left a credential behind"
    );
}

/// What is already enrolled is excluded from a new enrolment, so a browser
/// offers the user their unregistered keys rather than the one it finds first.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_enrolment_excludes_what_is_already_held() {
    use models::entities::user::RequiredAction;

    let plane = Plane::with_actions(&[]).await;
    let held = plane.enrol_soft_passkey().await;
    plane
        .require_of_subject(RequiredAction::ConfigureWebauthn)
        .await;

    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;

    let excluded: Vec<String> = told["asks"]["publicKey"]["excludeCredentials"]
        .as_array()
        .expect("an exclude list")
        .iter()
        .filter_map(|entry| entry["id"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(
        excluded,
        vec![data_encoding::BASE64URL_NOPAD.encode(&held.credential_id)],
        "the key already held is not excluded from re-enrolment"
    );
}

/// An instruction this build has no ceremony for leaves the login alone: the
/// debt stays recorded on the user, and the realm is not locked out of fixing
/// its own configuration.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_instruction_without_a_ceremony_leaves_the_login_alone() {
    use models::entities::user::RequiredAction;

    let plane = Plane::with_actions(&[]).await;
    plane.require_of_subject(RequiredAction::VerifyEmail).await;

    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "admitted");
    assert_eq!(
        plane.subject_owes().await,
        vec![RequiredAction::VerifyEmail],
        "an unrunnable instruction was struck by a login that did not run it"
    );
}

/// OIDC Core §3.1.2.1: the authorization request arrives by GET or by POST,
/// with the same parameters, and nothing a client can tell apart.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_login_may_be_asked_for_with_a_form_post() {
    let plane = Plane::with_actions(&[]).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let asked = started(support::CONFIDENTIAL);
    let form: Vec<(&str, &str)> = as_pairs(&asked);
    let request = test::TestRequest::post()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/auth",
            support::REALM
        ))
        .set_form(&form)
        .to_request();
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let set = response
        .headers()
        .get_all("set-cookie")
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert!(
        cookie_value(&set, support::AUTH_SESSION_COOKIE).is_some(),
        "a login asked for by POST was not bound to the browser"
    );
}

/// A refusal with nowhere to go is shown where the caller stands: a page to a
/// browser, JSON to anything else, and the same refusal in both.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_refusal_with_nowhere_to_go_is_a_page_for_a_browser() {
    let plane = Plane::with_actions(&[]).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let unregistered = format!(
        "/realms/{}/protocol/openid-connect/auth?response_type=code&client_id={}&scope=openid&redirect_uri=https://elsewhere.example/cb",
        support::REALM,
        support::CONFIDENTIAL
    );

    let browser = test::TestRequest::get()
        .uri(&unregistered)
        .insert_header(("accept", "text/html,application/xhtml+xml"))
        .to_request();
    let response = test::call_service(&app, browser).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/html"),
        "a browser was shown JSON"
    );
    let page = String::from_utf8(test::read_body(response).await.to_vec()).unwrap();
    assert!(
        page.contains("could not start") && page.contains("invalid_request"),
        "the page does not say what was refused: {page}"
    );

    let client = test::TestRequest::get().uri(&unregistered).to_request();
    let response = test::call_service(&app, client).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let told: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(told["error"], "invalid_request");
}

/// RFC 6750 §2.2: the token may ride in the form body. §2: never in two places
/// at once, so a request carrying both is refused rather than read twice.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_may_ride_in_the_form_body_and_never_in_two_places() {
    let plane = Plane::with_actions(&[]).await;
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid profile", None)
        .await;
    let (_, granted) = asking(
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
    let access = granted["access_token"].as_str().expect("an access token");
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let path = format!(
        "/realms/{}/protocol/openid-connect/userinfo",
        support::REALM
    );

    let in_body = test::TestRequest::post()
        .uri(&path)
        .set_form([("access_token", access)])
        .to_request();
    let response = test::call_service(&app, in_body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let told: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(told["sub"], support::SUBJECT);

    let twice = test::TestRequest::post()
        .uri(&path)
        .insert_header(("authorization", format!("Bearer {access}")))
        .set_form([("access_token", access)])
        .to_request();
    let response = test::call_service(&app, twice).await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a token presented twice over was accepted"
    );
}

/// The page is served at the URL it posts to, with its script and style as
/// files of their own, under a policy that allows nothing inline.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_login_page_is_served_where_it_posts() {
    let plane = Plane::with_actions(&[]).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;

    for (asset, content_type, marker) in [
        ("login", "text/html; charset=utf-8", "<form"),
        (
            "login.js",
            "text/javascript; charset=utf-8",
            "navigator.credentials",
        ),
        ("login.css", "text/css; charset=utf-8", "main"),
    ] {
        let request = test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/{asset}",
                support::REALM
            ))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK, "{asset}");
        let header = |named: &str| {
            response
                .headers()
                .get(named)
                .map(|value| value.to_str().unwrap().to_owned())
                .unwrap_or_default()
        };
        assert_eq!(header("content-type"), content_type, "{asset}");
        assert!(
            header("content-security-policy").contains("script-src 'self'"),
            "{asset} is served without the policy that forbids inline code"
        );
        assert_eq!(header("cache-control"), "no-store", "{asset}");
        assert_eq!(header("x-content-type-options"), "nosniff", "{asset}");
        let body = String::from_utf8(test::read_body(response).await.to_vec()).unwrap();
        assert!(body.contains(marker), "{asset} does not carry {marker}");
    }
}

/// A deployment naming no page of its own lands the browser on this server's,
/// bound the same way it would be to any other.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_start_with_no_page_named_lands_on_this_servers_page() {
    let plane = Plane::with_actions(&[]).await;
    let mut without = mounted(&plane);
    without.login_ui = config::serving::LoginUi::none();
    let app = test::init_service(App::new().configure(register(&without))).await;

    let started = started(support::CONFIDENTIAL);
    let asked = as_pairs(&started)
        .iter()
        .map(|(key, value)| format!("{key}={}", urlencode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let request = test::TestRequest::get()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/auth?{asked}",
            support::REALM
        ))
        .to_request();
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap(),
        format!(
            "{}/realms/{}/protocol/openid-connect/login",
            support::ORIGIN,
            support::REALM
        ),
        "the browser was sent somewhere other than this server's own page"
    );
    let set = response
        .headers()
        .get_all("set-cookie")
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert!(
        cookie_value(&set, support::AUTH_SESSION_COOKIE).is_some(),
        "the login was not bound to the browser it sent away"
    );
}

/// A browser running no script posts the form and is sent on: to the client
/// with a code when admitted, back to the page with the outcome in the
/// fragment when not. A blank field is a field not answered.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_form_is_answered_by_being_sent_on() {
    let plane = Plane::with_actions(&[]).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let path = format!("/realms/{}/protocol/openid-connect/login", support::REALM);
    let post = |form: &'static [(&'static str, &'static str)]| {
        test::TestRequest::post()
            .uri(&path)
            .insert_header((
                "cookie",
                format!("{}={auth_session}", support::AUTH_SESSION_COOKIE),
            ))
            .set_form(form)
            .to_request()
    };

    let refused = test::call_service(
        &app,
        post(&[
            ("username", support::SUBJECT),
            ("password", "not-the-password"),
            ("totp", ""),
        ]),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        refused.headers().get("location").unwrap().to_str().unwrap(),
        format!("{path}#refused"),
        "a refusal did not send the browser back to the page"
    );

    let admitted = test::call_service(
        &app,
        post(&[
            ("username", support::SUBJECT),
            ("password", support::PASSWORD),
            ("totp", ""),
        ]),
    )
    .await;
    assert_eq!(admitted.status(), StatusCode::SEE_OTHER);
    let landing = admitted
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        landing.starts_with(REDIRECT) && landing.contains("code="),
        "an admission did not send the browser to the client with a code: {landing}"
    );
    let set = admitted
        .headers()
        .get_all("set-cookie")
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert!(
        cookie_value(&set, support::SSO_COOKIE).is_some(),
        "the browser was sent on without being signed in"
    );
}

/// RFC 6749 §4.1.2: a code presented twice is refused, and what its first
/// presentation bought is taken back: the access token stops opening
/// `/userinfo`, and the refresh token stops renewing.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_replayed_code_takes_back_what_it_bought() {
    let plane = Plane::with_actions(&[]).await;
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid profile", None)
        .await;
    let redeem = [
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT),
    ];
    let client = Some((support::CONFIDENTIAL, support::CLIENT_SECRET));

    let (status, granted) = asking(&plane, support::REALM, &redeem, client).await;
    assert_eq!(status, StatusCode::OK, "{granted}");
    let access = granted["access_token"].as_str().expect("an access token");
    let refresh = granted["refresh_token"].as_str().expect("a refresh token");
    assert_eq!(
        userinfo(&plane, Some(access)).await.0,
        StatusCode::OK,
        "the token did not work before the replay"
    );

    let (status, told) = asking(&plane, support::REALM, &redeem, client).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(told["error"], "invalid_grant");

    assert_eq!(
        userinfo(&plane, Some(access)).await.0,
        StatusCode::UNAUTHORIZED,
        "the access token bought by a replayed code still works"
    );
    let (status, told) = asking(
        &plane,
        support::REALM,
        &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
        client,
    )
    .await;
    assert_eq!(
        (status, told["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant")),
        "the refresh token bought by a replayed code still renews"
    );
}

/// A browser already signed in is told to prove it again, does, and the code
/// that second login mints spends like the first: `prompt=login` opens a new
/// login, not a broken one.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_second_login_in_the_same_browser_mints_a_code_that_spends() {
    let plane = Plane::with_actions(&[]).await;
    let client = Some((support::CONFIDENTIAL, support::CLIENT_SECRET));

    // First login: the browser ends up signed in, and the code spends.
    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, admitted, set) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    let sso = cookie_value(&set, support::SSO_COOKIE).expect("signed in");
    let first = code_in(admitted["redirect_to"].as_str().unwrap());
    let (status, _) = asking(
        &plane,
        support::REALM,
        &[
            ("grant_type", "authorization_code"),
            ("code", &first),
            ("redirect_uri", REDIRECT),
        ],
        client,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Second login, forced, in the same browser.
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let mut again = started(support::CONFIDENTIAL);
    again.push(("prompt", "login".to_owned()));
    let asked = as_pairs(&again)
        .iter()
        .map(|(key, value)| format!("{key}={}", urlencode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?{asked}",
                support::REALM
            ))
            .insert_header(("cookie", format!("{}={sso}", support::SSO_COOKIE)))
            .to_request(),
    )
    .await;
    let set = response
        .headers()
        .get_all("set-cookie")
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let auth_session = cookie_value(&set, support::AUTH_SESSION_COOKIE)
        .expect("prompt=login opened a second login");
    let (status, admitted, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{admitted}");
    let second = code_in(admitted["redirect_to"].as_str().unwrap());

    let (status, told) = asking(
        &plane,
        support::REALM,
        &[
            ("grant_type", "authorization_code"),
            ("code", &second),
            ("redirect_uri", REDIRECT),
        ],
        client,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the code a forced second login minted does not spend: {told}"
    );
}

fn code_in(landing: &str) -> String {
    landing
        .split_once("code=")
        .expect("a code in the landing")
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned()
}

/// Everything OIDC Core §5.4 puts behind `profile`, when the realm holds it.
/// Fourteen claims, the last of them the record's own stamp.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_profile_scope_releases_everything_the_realm_holds_of_it() {
    use models::entities::attributes::AttributeValue;
    use models::entities::user::profile;

    let plane = Plane::with_actions(&[]).await;
    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(
                &mut connection,
                &store::tenancy::TenantContext::new(support::TENANT, support::REALM),
            )
            .await;
        let mut user = store::providers::users::load(&transaction, support::SUBJECT)
            .await
            .unwrap()
            .expect("the subject");
        let held = user.attributes.get_or_insert_with(Default::default);
        for (named, value) in [
            (profile::MIDDLE_NAME, "Augusta"),
            (profile::NICK_NAME, "ada"),
            (profile::PROFILE_PAGE, "https://example.test/ada"),
            (profile::PICTURE, "https://example.test/ada.png"),
            (profile::WEBSITE, "https://example.test"),
            (profile::GENDER, "female"),
            (profile::BIRTH_DATE, "1815-12-10"),
            (profile::ZONEINFO, "Europe/London"),
            (profile::LOCALE, "en-GB"),
        ] {
            held.insert(named.to_owned(), AttributeValue::Str(value.to_owned()));
        }
        store::providers::users::update(&transaction, &user)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }

    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid profile", None)
        .await;
    let (_, granted) = asking(
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
    let (status, told, _) = userinfo(&plane, granted["access_token"].as_str()).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    for claim in [
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
    ] {
        assert!(
            told.get(claim).is_some(),
            "the profile scope left out '{claim}': {told}"
        );
    }
    assert_eq!(
        told["name"],
        format!("{} {}", support::GIVEN_NAME, support::FAMILY_NAME)
    );
    assert!(
        told["updated_at"].is_i64(),
        "updated_at is not seconds: {}",
        told["updated_at"]
    );
}

/// The whole loop with extra authorization parameters: start, log in, and
/// spend the code. What the token endpoint granted.
async fn granted_through_login(plane: &Plane, extra: &[(&'static str, &str)]) -> serde_json::Value {
    let mut asked = started(support::CONFIDENTIAL);
    for (key, value) in extra {
        // Replaced, not repeated: a parameter twice over is a different
        // request, and one the endpoint is right to refuse.
        asked.retain(|(named, _)| named != key);
        asked.push((key, (*value).to_owned()));
    }
    let (status, location, opened) = authorize_with_cookies(plane, &as_pairs(&asked)).await;
    assert_eq!(status, StatusCode::FOUND, "{location}");
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (status, admitted, _) = login_step(
        plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{admitted}");
    let code = code_in(admitted["redirect_to"].as_str().expect("a landing"));
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

/// OIDC Core §5.5: a claim named in the request is released without the
/// scope that would have named it, within what the client may have at all.
/// The client here may have `profile` and not `email`, so naming `name` works
/// and naming `email` is not a way around the registration.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_claim_asked_by_name_is_released_within_what_the_client_may_have() {
    let plane = Plane::with_actions(&[]).await;
    let granted = granted_through_login(
        &plane,
        &[
            ("scope", "openid"),
            (
                "claims",
                r#"{"userinfo": {"name": {"essential": true}, "email": {"essential": true}}}"#,
            ),
        ],
    )
    .await;
    let (status, told, _) = userinfo(&plane, granted["access_token"].as_str()).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        told["name"],
        format!("{} {}", support::GIVEN_NAME, support::FAMILY_NAME),
        "a claim asked for by name was not released: {told}"
    );
    assert!(
        told.get("email").is_none(),
        "naming a claim of a scope the client may not have released it: {told}"
    );
}

/// A claim asked for the identity token rides in it, at the redemption and
/// again at every renewal, read from what the realm holds now, and within
/// what the client may have.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_claim_asked_for_the_id_token_rides_in_it_and_on_renewal() {
    let plane = Plane::with_actions(&[]).await;
    let granted = granted_through_login(
        &plane,
        &[
            ("scope", "openid"),
            (
                "claims",
                r#"{"id_token": {"email": null, "given_name": null, "family_name": null}}"#,
            ),
        ],
    )
    .await;
    let identity = plane
        .claims_of(granted["id_token"].as_str().expect("an id token"))
        .await;
    assert_eq!(identity["given_name"], support::GIVEN_NAME, "{identity}");
    assert_eq!(identity["family_name"], support::FAMILY_NAME);
    assert!(
        identity.get("email").is_none(),
        "a claim of a scope the client may not have rode in the id token: {identity}"
    );

    let (status, renewed) = asking(
        &plane,
        support::REALM,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", granted["refresh_token"].as_str().unwrap()),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{renewed}");
    let identity = plane
        .claims_of(renewed["id_token"].as_str().expect("a renewed id token"))
        .await;
    assert_eq!(
        identity["given_name"],
        support::GIVEN_NAME,
        "a renewal dropped what the request asked for: {identity}"
    );
}

/// §5.5.1: a claim asked with a value the realm does not hold is left out,
/// never an error; asked with the value it holds, it is released.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_claim_asked_with_a_value_is_released_only_when_the_value_matches() {
    let plane = Plane::with_actions(&[]).await;
    let granted = granted_through_login(
        &plane,
        &[
            ("scope", "openid"),
            (
                "claims",
                r#"{"userinfo": {"email": {"value": "somebody-else@example.test"},
                                 "given_name": {"values": ["Grace", "Ada"]}}}"#,
            ),
        ],
    )
    .await;
    let (status, told, _) = userinfo(&plane, granted["access_token"].as_str()).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert!(
        told.get("email").is_none(),
        "a claim whose value the client would not take was released: {told}"
    );
    assert_eq!(told["given_name"], support::GIVEN_NAME);
}

/// §3.1.2.2: a request for one subject is answered for that subject or not
/// at all. A session somebody else holds is not reused, and a login by
/// somebody else ends at the client with an error and no session.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_request_for_another_subject_is_not_answered_for_this_one() {
    let plane = Plane::with_actions(&[]).await;
    let session = signed_in_once(&plane).await;
    let for_grace = asking_for(&[("claims", r#"{"id_token": {"sub": {"value": "grace"}}}"#)]);

    // The live session is ada's, so it does not answer: a login starts.
    let (status, sent) = authorize_signed_in(&plane, &for_grace, &session).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        sent.starts_with("https://login.test"),
        "a session of another subject answered a request naming grace: {sent}"
    );

    // Ada logs in anyway. The client hears, and nobody is signed in.
    let (_, _, opened) = authorize_with_cookies(&plane, &for_grace).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (status, told, set) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "sent_back");
    let landing = told["redirect_to"].as_str().expect("somewhere to land");
    assert!(
        landing.starts_with(REDIRECT) && landing.contains("error=login_required"),
        "{landing}"
    );
    assert!(
        cookie_value(&set, support::SSO_COOKIE).is_none(),
        "a login for the wrong subject signed the browser in"
    );
}

/// A `claims` parameter that cannot be read is a request whose wishes are
/// unknown, refused rather than guessed at.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_unreadable_claims_parameter_is_refused() {
    let plane = Plane::with_actions(&[]).await;
    let mut asked = started(support::CONFIDENTIAL);
    asked.push(("claims", r#"{"userinfo": ["name"]}"#.to_owned()));
    let (status, location, _) = authorize_with_cookies(&plane, &as_pairs(&asked)).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location.starts_with(REDIRECT) && location.contains("error=invalid_request"),
        "{location}"
    );
}

/// §5.5.1.1: an `acr` asked as essential with values the realm cannot reach
/// fails the request, before anybody is asked to log in for nothing.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_essential_context_the_realm_cannot_reach_fails_the_request() {
    let plane = Plane::with_actions(&[]).await;
    let mut asked = started(support::CONFIDENTIAL);
    asked.push((
        "claims",
        r#"{"id_token": {"acr": {"essential": true, "values": ["platinum"]}}}"#.to_owned(),
    ));
    let (status, location, _) = authorize_with_cookies(&plane, &as_pairs(&asked)).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location.contains("error=unmet_authentication_requirements"),
        "{location}"
    );

    // The same values, voluntary: a hint, and the login proceeds.
    let mut asked = started(support::CONFIDENTIAL);
    asked.push((
        "claims",
        r#"{"id_token": {"acr": {"values": ["platinum"]}}}"#.to_owned(),
    ));
    let (status, location, _) = authorize_with_cookies(&plane, &as_pairs(&asked)).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location.starts_with("https://login.test"),
        "a voluntary context the realm cannot reach refused the login: {location}"
    );
}

/// OIDC Core §5.1.1: the `address` scope releases one object, of whichever
/// components the realm holds, as strings. Asked for by scope, and by name.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_address_scope_releases_one_object_of_what_is_held() {
    use models::entities::attributes::AttributeValue;
    use models::entities::user::address;

    let plane = Plane::with_actions(&[]).await;
    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(
                &mut connection,
                &store::tenancy::TenantContext::new(support::TENANT, support::REALM),
            )
            .await;
        let mut user = store::providers::users::load(&transaction, support::SUBJECT)
            .await
            .unwrap()
            .expect("the subject");
        let held = user.attributes.get_or_insert_with(Default::default);
        for (named, value) in [
            (address::STREET_ADDRESS, "1 Saint James's Square"),
            (address::LOCALITY, "London"),
            (address::POSTAL_CODE, "SW1Y 4JH"),
            (address::COUNTRY, "United Kingdom"),
        ] {
            held.insert(named.to_owned(), AttributeValue::Str(value.to_owned()));
        }
        store::providers::users::update(&transaction, &user)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }

    let by_scope = granted_through_login(&plane, &[("scope", "openid address")]).await;
    let (status, told, _) = userinfo(&plane, by_scope["access_token"].as_str()).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        told["address"],
        serde_json::json!({
            "street_address": "1 Saint James's Square",
            "locality": "London",
            "postal_code": "SW1Y 4JH",
            "country": "United Kingdom",
        }),
        "{told}"
    );
    assert!(
        told.get("region").is_none() && told["address"].get("region").is_none(),
        "a component the realm does not hold was released: {told}"
    );

    let by_name = granted_through_login(
        &plane,
        &[
            ("scope", "openid"),
            ("claims", r#"{"id_token": {"address": null}}"#),
        ],
    )
    .await;
    let identity = plane
        .claims_of(by_name["id_token"].as_str().expect("an id token"))
        .await;
    assert_eq!(identity["address"]["locality"], "London", "{identity}");
}

/// RP-Initiated Logout §2: a hint that is not this realm's, or names another
/// login, vouches for nothing, and the person is asked before anything ends.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_hint_for_another_login_or_a_forged_one_asks_first() {
    let plane = Plane::with_actions(&[]).await;
    let session = signed_in_once(&plane).await;
    let other = signed_in_once(&plane).await;
    let (_, landing) = authorize_signed_in(&plane, &asking_for(&[]), &other).await;
    let code = landing
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();
    let (_, granted) = asking(
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
    let others_hint = granted["id_token"]
        .as_str()
        .expect("an id token")
        .to_owned();
    let mut forged: Vec<char> = others_hint.chars().collect();
    let last = forged.len() - 1;
    forged[last] = if forged[last] == 'A' { 'B' } else { 'A' };
    let forged: String = forged.into_iter().collect();

    for (label, hint) in [
        ("another login's hint", others_hint.as_str()),
        ("a forged hint", forged.as_str()),
    ] {
        let (status, location, cleared) = logout(
            &plane,
            &[
                ("id_token_hint", hint),
                ("post_logout_redirect_uri", support::AFTER_LOGOUT),
            ],
            Some(&session),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{label}");
        assert!(location.is_empty(), "{label} was sent to {location}");
        assert!(
            !cleared
                .iter()
                .any(|header| header.starts_with(support::SSO_COOKIE)),
            "{label} ended a login it did not vouch for"
        );
    }
    assert!(plane.login_is_open(&session).await);
    assert!(plane.login_is_open(&other).await);
}

/// A landing this realm will not vouch for keeps the browser here, and says
/// so: the login ends, the redirect does not happen.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_refused_landing_keeps_the_browser_here_and_says_so() {
    let plane = Plane::with_actions(&[]).await;
    let session = signed_in_once(&plane).await;

    let (status, location, cleared) = logout_confirmed(
        &plane,
        &[
            (
                "post_logout_redirect_uri",
                "https://attacker.example/collect",
            ),
            ("client_id", support::CONFIDENTIAL),
        ],
        Some(&session),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(location.is_empty(), "{location}");
    assert!(
        cleared
            .iter()
            .any(|header| header.starts_with(support::SSO_COOKIE)),
        "the login was not ended"
    );
    assert!(!plane.login_is_open(&session).await);
}

/// A browser is asked in a page whose form carries the request back, and is
/// told in a page when it is over.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_browser_is_asked_in_a_page_and_told_in_one() {
    let plane = Plane::with_actions(&[]).await;
    let session = signed_in_once(&plane).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let path = format!(
        "/realms/{}/protocol/openid-connect/logout?client_id={}&post_logout_redirect_uri={}&state=s1",
        support::REALM,
        support::CONFIDENTIAL,
        urlencode(support::AFTER_LOGOUT)
    );

    let asked = test::TestRequest::get()
        .uri(&path)
        .insert_header(("accept", "text/html"))
        .insert_header(("cookie", format!("{}={session}", support::SSO_COOKIE)))
        .to_request();
    let response = test::call_service(&app, asked).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = String::from_utf8(test::read_body(response).await.to_vec()).unwrap();
    assert!(
        page.contains("Sign out?") && page.contains("method=\"post\""),
        "{page}"
    );
    assert!(
        page.contains("name=\"confirmed\" value=\"yes\"")
            && page.contains("name=\"state\" value=\"s1\"")
            && page.contains("name=\"client_id\""),
        "the form does not carry the request back: {page}"
    );
    assert!(
        plane.login_is_open(&session).await,
        "a page ended the login"
    );

    let answered = test::TestRequest::post()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/logout",
            support::REALM
        ))
        .insert_header(("accept", "text/html"))
        .insert_header(("cookie", format!("{}={session}", support::SSO_COOKIE)))
        .set_form([("confirmed", "yes")])
        .to_request();
    let response = test::call_service(&app, answered).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = String::from_utf8(test::read_body(response).await.to_vec()).unwrap();
    assert!(page.contains("You are signed out"), "{page}");
    assert!(!plane.login_is_open(&session).await);
}

/// The header of a token, which names how it was signed.
fn header_of(token: &str) -> serde_json::Value {
    let head = token.split('.').next().expect("a compact token");
    serde_json::from_slice(
        &data_encoding::BASE64URL_NOPAD
            .decode(head.as_bytes())
            .unwrap(),
    )
    .unwrap()
}

/// An identity token is signed as the client registered, RS256 when it did
/// not say (OIDC Core §2), and with nothing else when it asked for something
/// the realm does not have. The access token keeps the realm's own choice.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_identity_token_is_signed_as_the_client_registered() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .publish_key(&support::SigningKey::generate_rsa("kid-rsa"))
        .await;

    let granted = granted_through_login(&plane, &[("scope", "openid")]).await;
    assert_eq!(
        header_of(granted["id_token"].as_str().expect("an id token"))["alg"],
        "RS256",
        "a client that registered nothing did not get the default"
    );
    assert_eq!(
        header_of(granted["access_token"].as_str().expect("an access token"))["alg"],
        "ES256",
        "the access token did not keep the realm's own choice"
    );

    plane
        .register_id_token_alg(
            support::CONFIDENTIAL,
            Some(crypto::provider::SignAlg::Es256),
        )
        .await;
    let granted = granted_through_login(&plane, &[("scope", "openid")]).await;
    assert_eq!(
        header_of(granted["id_token"].as_str().expect("an id token"))["alg"],
        "ES256",
        "what the client registered was not honoured"
    );

    plane
        .register_id_token_alg(
            support::CONFIDENTIAL,
            Some(crypto::provider::SignAlg::Ps256),
        )
        .await;
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid", None)
        .await;
    let (status, told) = asking(
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
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "signed with something other than what the client registered: {told}"
    );
}

/// One call to a client-authenticated endpoint under the protocol scope.
async fn asking_at(
    plane: &Plane,
    endpoint: &str,
    form: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> (StatusCode, serde_json::Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut request = test::TestRequest::post()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/{endpoint}",
            support::REALM
        ))
        .set_form(form);
    if let Some((client_id, secret)) = basic {
        let encoded = BASE64.encode(format!("{client_id}:{secret}").as_bytes());
        request = request.insert_header(("authorization", format!("Basic {encoded}")));
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    let told = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
    };
    (status, told)
}

/// RFC 7662: a live token says what it carries; every way of being dead is
/// `active: false` and nothing more, and a client that cannot keep a secret
/// is not told anything.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_is_introspected_live_and_dead_alike() {
    let plane = Plane::with_actions(&[]).await;
    let session = signed_in_once(&plane).await;
    let (_, landing) = authorize_signed_in(&plane, &asking_for(&[]), &session).await;
    let code = landing
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();
    let (_, granted) = asking(
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
    let access = granted["access_token"].as_str().expect("an access token");
    let refresh = granted["refresh_token"].as_str().expect("a refresh token");
    let id_token = granted["id_token"].as_str().expect("an id token");
    let me = Some((support::CONFIDENTIAL, support::CLIENT_SECRET));

    let (status, told) = asking_at(&plane, "introspect", &[("token", access)], me).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["active"], true, "{told}");
    assert_eq!(told["client_id"], support::CONFIDENTIAL);
    assert_eq!(told["token_type"], "Bearer");
    assert_eq!(told["sub"], support::SUBJECT);
    assert!(
        told.get("exp").is_some() && told.get("scope").is_some(),
        "{told}"
    );

    // Any confidential client of the realm may ask: a resource server is
    // rarely the client a token was minted for.
    let (_, told) = asking_at(
        &plane,
        "introspect",
        &[("token", access)],
        Some((support::OTHER, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(
        told["active"], true,
        "another confidential client was refused"
    );

    let (_, told) = asking_at(&plane, "introspect", &[("token", refresh)], me).await;
    assert_eq!(
        told["active"], true,
        "a current refresh token is live: {told}"
    );
    let (_, renewed) = renew(&plane, refresh).await;
    let (_, told) = asking_at(&plane, "introspect", &[("token", refresh)], me).await;
    assert_eq!(
        told,
        serde_json::json!({ "active": false }),
        "a rotated-out refresh token is dead however unexpired"
    );
    let successor = renewed["refresh_token"].as_str().expect("a successor");
    let (_, told) = asking_at(&plane, "introspect", &[("token", successor)], me).await;
    assert_eq!(told["active"], true);

    for (label, dead) in [("an identity token", id_token), ("garbage", "not-a-token")] {
        let (status, told) = asking_at(&plane, "introspect", &[("token", dead)], me).await;
        assert_eq!(status, StatusCode::OK, "{label}");
        assert_eq!(told, serde_json::json!({ "active": false }), "{label}");
    }

    let (status, told) = asking_at(
        &plane,
        "introspect",
        &[("token", access), ("client_id", support::PUBLIC)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(told["error"], "invalid_client");
    let (status, _) = asking_at(&plane, "introspect", &[("token", access)], None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "asked by nobody");

    logout_confirmed(&plane, &[], Some(&session)).await;
    let (_, told) = asking_at(&plane, "introspect", &[("token", access)], me).await;
    assert_eq!(
        told,
        serde_json::json!({ "active": false }),
        "a token of an ended login is still live"
    );
}

/// One grant's tokens, minted for the confidential client.
async fn grant(plane: &Plane) -> serde_json::Value {
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid profile", None)
        .await;
    asking(
        plane,
        support::REALM,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
        ],
        Some((support::CONFIDENTIAL, support::CLIENT_SECRET)),
    )
    .await
    .1
}

/// RFC 7009: a client takes back what it was issued, and with it every renewal
/// of the same grant; what it was not issued is refused; what cannot be read
/// is taken back without complaint.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_takes_back_its_own_tokens_and_nobody_elses() {
    let plane = Plane::with_actions(&[]).await;
    let me = Some((support::CONFIDENTIAL, support::CLIENT_SECRET));

    // An access token taken back stops opening userinfo, and the refresh
    // token of the same grant stops renewing.
    let granted = grant(&plane).await;
    let access = granted["access_token"].as_str().unwrap();
    let refresh = granted["refresh_token"].as_str().unwrap();
    let (status, _) = asking_at(&plane, "revoke", &[("token", access)], me).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        userinfo(&plane, Some(access)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(renew(&plane, refresh).await.1["error"], "invalid_grant");

    // A refresh token taken back stops renewing.
    let granted = grant(&plane).await;
    let refresh = granted["refresh_token"].as_str().unwrap();
    let (status, _) = asking_at(&plane, "revoke", &[("token", refresh)], me).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(renew(&plane, refresh).await.1["error"], "invalid_grant");

    // Somebody else's token is refused, and left alone.
    let granted = grant(&plane).await;
    let access = granted["access_token"].as_str().unwrap();
    let (status, told) = asking_at(
        &plane,
        "revoke",
        &[("token", access)],
        Some((support::OTHER, support::CLIENT_SECRET)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "unauthorized_client");
    assert_eq!(userinfo(&plane, Some(access)).await.0, StatusCode::OK);

    for (label, unreadable) in [
        ("garbage", "not-a-token"),
        ("an identity token", granted["id_token"].as_str().unwrap()),
    ] {
        let (status, _) = asking_at(&plane, "revoke", &[("token", unreadable)], me).await;
        assert_eq!(status, StatusCode::OK, "{label} was complained about");
    }
    // A public client may revoke, but only its own: this one is not its.
    let (status, told) = asking_at(
        &plane,
        "revoke",
        &[("token", access), ("client_id", support::PUBLIC)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["error"], "unauthorized_client");
}

/// The realm told this user to set up an authenticator app: after the flow
/// admits, a fresh secret is shown once, the code the app derives from it
/// proves the app, the credential is kept with that step spent, and the
/// instruction is struck. A wrong code keeps it standing and keeps nothing.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_required_authenticator_app_is_set_up_inside_the_login() {
    use models::entities::user::RequiredAction;

    let plane = Plane::with_actions(&[]).await;
    plane
        .require_of_subject(RequiredAction::ConfigureTotp)
        .await;
    let before = plane.subject_totp_secrets().await;

    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "challenge");
    assert_eq!(told["execution"], "totp-register");
    let secret = told["asks"]["secret"]
        .as_str()
        .expect("a secret to enter")
        .to_owned();
    let otpauth = told["asks"]["otpauth"].as_str().expect("a URI to scan");
    assert!(
        otpauth.starts_with("otpauth://totp/") && otpauth.contains(&format!("secret={secret}")),
        "{otpauth}"
    );

    // A wrong code proves nothing: the instruction stands, nothing is kept.
    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "totp_register": "000000",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(
        plane.subject_owes().await,
        vec![RequiredAction::ConfigureTotp]
    );
    assert_eq!(plane.subject_totp_secrets().await, before);

    // The right one, from a fresh login since the refused one is over.
    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let (_, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    let secret = told["asks"]["secret"]
        .as_str()
        .expect("a secret")
        .to_owned();
    let (status, admitted, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "totp_register": code_for(&secret),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{admitted}");
    assert_eq!(admitted["status"], "admitted");
    assert_eq!(plane.subject_owes().await, vec![], "the instruction stands");
    let after = plane.subject_totp_secrets().await;
    assert_eq!(after.len(), before.len() + 1);
    assert!(
        after.contains(&secret),
        "the secret shown is not the one kept"
    );
}

/// A client's ear: one HTTP request accepted on a port of its own, its body
/// handed back, a 200 sent. What a relying party's back-channel endpoint is.
fn listening_client() -> (String, std::sync::mpsc::Receiver<String>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("a caller");
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).unwrap_or(0);
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..read]);
            let text = String::from_utf8_lossy(&raw).to_string();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length: usize = head
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .or_else(|| {
                        head.lines()
                            .find_map(|line| line.strip_prefix("content-length: "))
                    })
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                if body.len() >= length {
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    let _ = sender.send(body[..length].to_owned());
                    break;
                }
            }
        }
    });
    (format!("http://127.0.0.1:{port}/logout-token"), receiver)
}

/// Back-Channel Logout 1.0: when a login ends, every client that took part
/// and said where is posted a logout token naming the session, signed as
/// that client reads identity tokens, with the event and without a nonce.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_is_told_when_the_login_it_took_part_in_ends() {
    let plane = Plane::with_actions(&[]).await;
    let (uri, received) = listening_client();
    plane
        .register_backchannel(support::CONFIDENTIAL, &uri)
        .await;

    let session = signed_in_once(&plane).await;
    let (_, landing) = authorize_signed_in(&plane, &asking_for(&[]), &session).await;
    let code = landing
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();
    let (_, granted) = asking(
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
    let hint = granted["id_token"].as_str().expect("an id token");

    let (status, _, _) = logout(&plane, &[("id_token_hint", hint)], Some(&session)).await;
    assert_eq!(status, StatusCode::OK);

    let body = received
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the client was never told");
    let token = body
        .split('&')
        .find_map(|pair| pair.strip_prefix("logout_token="))
        .expect("a logout token in the form");
    // A compact token is base64url and dots, which a form leaves as they are.
    let token = token.to_owned();

    assert_eq!(header_of(&token)["typ"], "logout+jwt");
    let claims = plane.claims_of(&token).await;
    assert_eq!(claims["iss"], support::origin().issuer(support::REALM));
    assert_eq!(claims["sub"], support::SUBJECT);
    assert_eq!(claims["aud"], support::CONFIDENTIAL);
    assert_eq!(claims["sid"], session);
    assert!(
        claims.get("jti").is_some() && claims.get("iat").is_some() && claims.get("exp").is_some()
    );
    assert!(
        claims["events"]
            .get("http://schemas.openid.net/event/backchannel-logout")
            .is_some(),
        "{claims}"
    );
    assert!(
        claims.get("nonce").is_none(),
        "a logout token must carry no nonce"
    );
}

/// Front-Channel Logout 1.0: a client that registered a frame is loaded in
/// the browser when a login it took part in ends, with `iss` and `sid` and
/// nothing else, and the landing is reached from that page rather than by a
/// redirect the browser follows before the frames load.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_is_loaded_in_the_browser_when_the_login_ends() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .register_frontchannel(support::CONFIDENTIAL, "https://app.example/logout-frame")
        .await;
    let session = signed_in_once(&plane).await;
    let (_, landing) = authorize_signed_in(&plane, &asking_for(&[]), &session).await;
    let code = landing
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();
    let (_, granted) = asking(
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
    let hint = granted["id_token"].as_str().expect("an id token");

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let asked = format!(
        "/realms/{}/protocol/openid-connect/logout?id_token_hint={hint}&post_logout_redirect_uri={}&state=s",
        support::REALM,
        urlencode(support::AFTER_LOGOUT)
    );
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&asked)
            .insert_header(("accept", "text/html"))
            .insert_header(("cookie", format!("{}={session}", support::SSO_COOKIE)))
            .to_request(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a redirect outran the frames"
    );
    let page = String::from_utf8(test::read_body(response).await.to_vec()).unwrap();
    assert!(page.contains("<iframe"), "no frame was loaded: {page}");
    assert!(
        page.contains(&format!("sid={session}")) && page.contains("iss=https"),
        "the frame does not name the login: {page}"
    );
    assert!(
        page.contains(&format!("2;url={}", support::AFTER_LOGOUT)),
        "the browser is never sent on: {page}"
    );
    assert!(!plane.login_is_open(&session).await);
}

/// An authorization request the client signed. OIDC Core §6.1: what the object
/// carries governs, the query fills what it left out, and the redirect it
/// names is checked like any other.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_signed_request_object_governs_the_request() {
    let plane = Plane::with_actions(&[]).await;
    let key = support::SigningKey::generate("client-key");
    plane
        .register_client_keys(
            support::CONFIDENTIAL,
            &key,
            crypto::provider::SignAlg::Es256,
        )
        .await;

    let object = |change: &dyn Fn(&mut crypto::jose::jwt::JwtPayload)| {
        let mut payload = crypto::jose::jwt::JwtPayload::new();
        for (named, value) in [
            ("iss", support::CONFIDENTIAL),
            ("aud", &support::origin().issuer(support::REALM)),
            ("client_id", support::CONFIDENTIAL),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT),
            ("scope", "openid profile"),
            ("state", "signed-state"),
            ("nonce", "signed-nonce"),
        ] {
            payload
                .set_claim(named, Some(serde_json::json!(value)))
                .expect("a claim");
        }
        change(&mut payload);
        key.sign(&payload, "client-key")
    };

    // The query carries only what the endpoint needs to find the client; the
    // object carries the rest, and what it says is what the code is minted on.
    let signed = object(&|_| {});
    let (status, landing, opened) = authorize_with_cookies(
        &plane,
        &[
            ("client_id", support::CONFIDENTIAL),
            ("response_type", "code"),
            ("scope", "openid"),
            ("request", signed.as_str()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "{landing}");
    let binding = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a login");
    let (_, told, _) = login_step(
        &plane,
        Some(&binding),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    let landing = told["redirect_to"].as_str().expect("somewhere to land");
    assert!(
        landing.starts_with(REDIRECT) && landing.contains("state=signed-state"),
        "the object's own parameters were not honoured: {landing}"
    );
    let code = landing
        .split_once("code=")
        .unwrap()
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();
    let (_, granted) = asking(
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
    let identity = plane
        .claims_of(granted["id_token"].as_str().expect("an id token"))
        .await;
    assert_eq!(identity["nonce"], "signed-nonce", "{identity}");
    assert_eq!(
        granted["scope"], "openid profile",
        "the object's scope was not used"
    );

    // Every way of not being this client's object.
    let mut forged: Vec<char> = signed.chars().collect();
    let last = forged.len() - 1;
    forged[last] = if forged[last] == 'A' { 'B' } else { 'A' };
    let forged: String = forged.into_iter().collect();
    let elsewhere = object(&|payload| {
        payload
            .set_claim("aud", Some(serde_json::json!("https://elsewhere.example")))
            .expect("a claim");
    });
    let nested = object(&|payload| {
        payload
            .set_claim("request", Some(serde_json::json!("another.object.here")))
            .expect("a claim");
    });
    let disagreeing = object(&|payload| {
        payload
            .set_claim("response_type", Some(serde_json::json!("token")))
            .expect("a claim");
    });
    for (label, raw) in [
        ("a forged signature", forged.as_str()),
        ("an object for another issuer", elsewhere.as_str()),
        ("an object carrying another", nested.as_str()),
        (
            "a response_type that disagrees with the query",
            disagreeing.as_str(),
        ),
    ] {
        let (status, landing, _) = authorize_with_cookies(
            &plane,
            &[
                ("client_id", support::CONFIDENTIAL),
                ("response_type", "code"),
                ("scope", "openid"),
                ("request", raw),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::FOUND, "{label}");
        assert!(
            landing.contains("error=invalid_request_object"),
            "{label} was not refused: {landing}"
        );
    }

    // A client that registered nothing cannot sign one.
    let (_, landing, _) = authorize_with_cookies(
        &plane,
        &[
            ("client_id", support::OTHER),
            ("response_type", "code"),
            ("scope", "openid"),
            ("request", signed.as_str()),
        ],
    )
    .await;
    assert!(
        landing.contains("error=request_not_supported"),
        "an unregistered client was allowed an object: {landing}"
    );
}

/// RFC 9126: a client pushes its request here and sends the browser with a
/// reference. What was pushed is what governs, the reference is spent once,
/// and it belongs to the client that pushed it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_pushed_request_is_spent_once_by_the_client_that_pushed_it() {
    let plane = Plane::with_actions(&[]).await;
    let me = Some((support::CONFIDENTIAL, support::CLIENT_SECRET));
    let pushing = [
        ("response_type", "code"),
        ("client_id", support::CONFIDENTIAL),
        ("redirect_uri", REDIRECT),
        ("scope", "openid profile"),
        ("state", "pushed-state"),
        ("nonce", "pushed-nonce"),
    ];

    let (status, told) = asking_at(&plane, "par", &pushing, me).await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let handle = told["request_uri"]
        .as_str()
        .expect("a reference")
        .to_owned();
    assert!(
        handle.starts_with("urn:ietf:params:oauth:request_uri:"),
        "not a reference this server issued: {handle}"
    );
    assert!(told["expires_in"].as_i64().is_some_and(|held| held > 0));

    // The browser carries the reference and nothing else of the request.
    let (status, _, opened) = authorize_with_cookies(
        &plane,
        &[
            ("client_id", support::CONFIDENTIAL),
            ("request_uri", &handle),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let binding = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a login");
    let (_, admitted, _) = login_step(
        &plane,
        Some(&binding),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    let landing = admitted["redirect_to"].as_str().expect("somewhere to land");
    assert!(
        landing.starts_with(REDIRECT) && landing.contains("state=pushed-state"),
        "what was pushed did not govern: {landing}"
    );

    // §4: one use.
    let (status, again, _) = authorize_with_cookies(
        &plane,
        &[
            ("client_id", support::CONFIDENTIAL),
            ("request_uri", &handle),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{again}");
    assert!(
        again.contains("invalid_request_uri") || again.is_empty(),
        "{again}"
    );

    // Somebody else's reference, and a reference nobody issued.
    let (_, told) = asking_at(&plane, "par", &pushing, me).await;
    let held = told["request_uri"]
        .as_str()
        .expect("a reference")
        .to_owned();
    let (status, _, _) = authorize_with_cookies(
        &plane,
        &[("client_id", support::OTHER), ("request_uri", &held)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "another client spent it");
    let (status, _, _) = authorize_with_cookies(
        &plane,
        &[
            ("client_id", support::CONFIDENTIAL),
            ("request_uri", "https://attacker.example/request"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a URL was fetched");

    // §2.2: a reference outlives its request by nothing.
    let (_, told) = asking_at(&plane, "par", &pushing, me).await;
    let stale = told["request_uri"]
        .as_str()
        .expect("a reference")
        .to_owned();
    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(
                &mut connection,
                &store::tenancy::TenantContext::new(support::TENANT, support::REALM),
            )
            .await;
        transaction
            .execute(
                "UPDATE pushed_requests SET pushed_at = now() - interval '2 minutes', \
                 expires_at = now() - interval '1 second'",
                &[],
            )
            .await
            .expect("an ageing");
        transaction.commit().await.expect("the ageing kept");
    }
    let (status, _, _) = authorize_with_cookies(
        &plane,
        &[
            ("client_id", support::CONFIDENTIAL),
            ("request_uri", &stale),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an expired reference was spent"
    );

    // Pushing is a client's own act: no client, no push.
    let (status, _) = asking_at(&plane, "par", &pushing, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // And a client cannot push a request naming another.
    let (status, told) = asking_at(
        &plane,
        "par",
        &[("response_type", "code"), ("client_id", support::OTHER)],
        me,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    // §2.1: nor a request that carries a reference to another one.
    let (status, told) = asking_at(
        &plane,
        "par",
        &[
            ("response_type", "code"),
            ("client_id", support::CONFIDENTIAL),
            ("request_uri", &held),
        ],
        me,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
}

/// The enrolment challenge hands everything a person needs to add the app:
/// the image to scan, the URI behind it, and the key to type by hand.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_authenticator_enrolment_hands_the_scannable_code() {
    use models::entities::user::RequiredAction;
    let plane = Plane::with_actions(&[]).await;
    plane
        .require_of_subject(RequiredAction::ConfigureTotp)
        .await;

    let (_, _, opened) =
        authorize_with_cookies(&plane, &as_pairs(&started(support::CONFIDENTIAL))).await;
    let auth_session = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");

    let (status, told, _) = login_step(
        &plane,
        Some(&auth_session),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "challenge", "{told}");
    assert_eq!(told["execution"], "totp-register", "{told}");
    let asks = told.get("asks").expect("an enrolment issues a challenge");
    let secret = asks["secret"].as_str().expect("a key to type by hand");
    assert!(!secret.is_empty());
    assert!(
        asks["otpauth"]
            .as_str()
            .expect("a URI for the app")
            .starts_with("otpauth://totp/"),
        "{asks}"
    );
    let drawn = asks["qr"].as_str().expect("an image to scan");
    assert!(
        drawn.starts_with("<?xml") || drawn.starts_with("<svg"),
        "not an SVG: {drawn}"
    );
}
