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
        (
            vec![("grant_type", "authorization_code")],
            "unsupported_grant_type",
        ),
        (
            vec![("grant_type", "refresh_token")],
            "unsupported_grant_type",
        ),
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
