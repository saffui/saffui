//! What the authorization endpoint hands back itself, OIDC Core §3.2 and §3.3.

mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use server::api::config::{Plane as Mounted, register};
use support::{Plane, cookie_value, urlencode};

const REDIRECT: &str = "https://app.example/callback";

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
        sealing: support::sealing(),
    }
}

/// Ask, and hand back what the authorization endpoint said.
async fn asked(plane: &Plane, extra: &[(&str, &str)]) -> (StatusCode, String, Vec<String>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut query = format!(
        "client_id={}&redirect_uri={}&state=s",
        support::CONFIDENTIAL,
        urlencode(REDIRECT),
    );
    if !extra.iter().any(|(named, _)| *named == "scope") {
        query.push_str("&scope=openid");
    }
    for (named, value) in extra {
        query.push_str(&format!("&{named}={}", urlencode(value)));
    }
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?{query}",
                support::REALM
            ))
            .to_request(),
    )
    .await;
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let cookies = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    (status, location, cookies)
}

/// Answer the login and hand back where the browser was sent.
async fn signed_in(plane: &Plane, binding: &str) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/login",
                support::REALM
            ))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .set_form([
                ("username", support::SUBJECT),
                ("password", support::PASSWORD),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

/// What came back after the `#`, by name.
fn in_fragment<'a>(landing: &'a str, named: &str) -> Option<&'a str> {
    landing
        .split_once('#')?
        .1
        .split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{named}=")))
}

/// Sign in for this response type, and hand back the landing.
async fn through(plane: &Plane, response_type: &str) -> String {
    through_with(plane, response_type, "openid").await
}

async fn through_with(plane: &Plane, response_type: &str, scope: &str) -> String {
    let (status, _, cookies) = asked(
        plane,
        &[
            ("response_type", response_type),
            ("nonce", "n-0S6"),
            ("scope", scope),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "{response_type} did not open a login"
    );
    let binding = cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login");
    signed_in(plane, &binding).await
}

/// Every response type hands back what it names, in the part of the URL that
/// never reaches a server.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn each_response_type_hands_back_what_it_names() {
    let plane = Plane::with_actions(&[]).await;
    plane.allow_implicit(support::CONFIDENTIAL).await;

    for (named, code, id_token, token) in [
        ("id_token", false, true, false),
        ("id_token token", false, true, true),
        ("code id_token", true, true, false),
        ("code token", true, false, true),
        ("code id_token token", true, true, true),
    ] {
        let landing = through(&plane, named).await;
        assert!(
            landing.contains('#'),
            "{named} did not answer in a fragment: {landing}"
        );
        assert!(
            !landing
                .split('#')
                .next()
                .unwrap_or_default()
                .contains("token="),
            "{named}: {landing}"
        );
        assert_eq!(
            in_fragment(&landing, "code").is_some(),
            code,
            "{named}: {landing}"
        );
        assert_eq!(
            in_fragment(&landing, "id_token").is_some(),
            id_token,
            "{named}: {landing}"
        );
        assert_eq!(
            in_fragment(&landing, "access_token").is_some(),
            token,
            "{named}: {landing}"
        );
        assert_eq!(
            in_fragment(&landing, "state"),
            Some("s"),
            "{named}: {landing}"
        );
        if token {
            assert_eq!(
                in_fragment(&landing, "token_type"),
                Some("Bearer"),
                "{named}"
            );
        }
    }
}

/// The hashes say the two came back together. A client holding two values with
/// no way to pair them is one an attacker hands one of its own.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_came_back_together_says_so() {
    let plane = Plane::with_actions(&[]).await;
    plane.allow_implicit(support::CONFIDENTIAL).await;

    let landing = through(&plane, "code id_token token").await;
    let claims = plane
        .claims_of(in_fragment(&landing, "id_token").expect("an identity token"))
        .await;
    let access = in_fragment(&landing, "access_token").expect("an access token");
    let code = in_fragment(&landing, "code").expect("a code");

    let provider = support::provider();
    assert_eq!(
        claims["at_hash"].as_str(),
        services::detached::half_hash(&provider, crypto::provider::SignAlg::Es256, access)
            .as_deref(),
        "the access token's hash is not of the access token"
    );
    assert_eq!(
        claims["c_hash"].as_str(),
        services::detached::half_hash(&provider, crypto::provider::SignAlg::Es256, code).as_deref(),
        "the code's hash is not of the code"
    );
    assert_eq!(claims["nonce"], "n-0S6");

    // And where only one comes back beside it, only that one is named.
    let landing = through(&plane, "code id_token").await;
    let claims = plane
        .claims_of(in_fragment(&landing, "id_token").expect("an identity token"))
        .await;
    assert!(claims["c_hash"].is_string(), "{claims}");
    assert!(claims.get("at_hash").is_none(), "{claims}");
}

/// A client that may exchange a code has not thereby been allowed a token
/// through a browser.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn exchanging_a_code_is_not_being_allowed_a_token() {
    let plane = Plane::with_actions(&[]).await;

    for named in ["id_token", "code id_token", "code token"] {
        let (_, landing, _) = asked(&plane, &[("response_type", named), ("nonce", "n-0S6")]).await;
        assert!(
            landing.contains("error=unauthorized_client"),
            "{named} was allowed: {landing}"
        );
    }
    // And the code flow, which it may, still works.
    let (status, _, _) = asked(&plane, &[("response_type", "code")]).await;
    assert_eq!(status, StatusCode::FOUND);
}

/// Nothing minted here travels on a query, whatever the client asks for.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_query_never_carries_what_is_minted_here() {
    let plane = Plane::with_actions(&[]).await;
    plane.allow_implicit(support::CONFIDENTIAL).await;

    let (_, landing, _) = asked(
        &plane,
        &[
            ("response_type", "id_token"),
            ("nonce", "n-0S6"),
            ("response_mode", "query"),
        ],
    )
    .await;
    assert!(
        landing.contains("error=unsupported_response_mode"),
        "{landing}"
    );
}

/// An identity token minted here is bound to the request by its nonce, and
/// nothing else binds it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_identity_token_minted_here_needs_a_nonce() {
    let plane = Plane::with_actions(&[]).await;
    plane.allow_implicit(support::CONFIDENTIAL).await;

    for named in [
        "id_token",
        "id_token token",
        "code id_token",
        "code id_token token",
    ] {
        let (_, landing, _) = asked(&plane, &[("response_type", named)]).await;
        assert!(
            landing.contains("error=invalid_request"),
            "{named}: {landing}"
        );
    }
    // A code token mints no identity token, so it needs none.
    let (status, _, _) = asked(&plane, &[("response_type", "code token")]).await;
    assert_eq!(status, StatusCode::FOUND);
}

/// `token` alone is OAuth's and not OpenID's, and a value no response type
/// uses is not one either.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_response_type_openid_does_not_name_is_refused() {
    let plane = Plane::with_actions(&[]).await;
    plane.allow_implicit(support::CONFIDENTIAL).await;

    for named in ["token", "none", "code none", ""] {
        let (_, landing, _) = asked(&plane, &[("response_type", named), ("nonce", "n-0S6")]).await;
        assert!(
            landing.contains("error=unsupported_response_type"),
            "{named:?} was allowed: {landing}"
        );
    }
}

/// An implicit request gets nothing to redeem: a code minted anyway would be a
/// spendable credential nobody comes back for.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_implicit_request_leaves_no_code_behind() {
    let plane = Plane::with_actions(&[]).await;
    plane.allow_implicit(support::CONFIDENTIAL).await;
    through(&plane, "id_token token").await;

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &store::tenancy::TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    let minted: i64 = transaction
        .query_one("SELECT count(*) FROM oidc_auth_codes", &[])
        .await
        .expect("a count")
        .get(0);
    assert_eq!(
        minted, 0,
        "a code was minted for a request that asked for none"
    );
}

/// A refusal travels the way the answer would have. A client reading a
/// fragment never learns of one left on the query.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_refusal_goes_where_the_answer_would_have() {
    let plane = Plane::with_actions(&[]).await;
    plane.allow_implicit(support::CONFIDENTIAL).await;

    // Refused for want of a nonce, which is a refusal every hybrid type can
    // be given without arranging anything else.
    for named in ["code id_token", "id_token", "code id_token token"] {
        let (_, landing, _) = asked(&plane, &[("response_type", named)]).await;
        assert_eq!(
            in_fragment(&landing, "error"),
            Some("invalid_request"),
            "{named} was refused on the query: {landing}"
        );
        assert_eq!(in_fragment(&landing, "state"), Some("s"), "{named}");
        assert!(
            !landing
                .split('#')
                .next()
                .unwrap_or_default()
                .contains("error="),
            "{named} was refused twice: {landing}"
        );
    }

    // And a code request, which is answered on the query, is refused there.
    let (_, landing, _) = asked(&plane, &[("response_type", "code"), ("prompt", "none")]).await;
    assert!(
        landing.contains("?error=login_required") && !landing.contains('#'),
        "{landing}"
    );
}

/// A client that only ever came through here still took part in the login.
/// Without a row against it, a logout has no one to tell and an administrator
/// sees a login with no clients in it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_is_minted_here_is_a_grant_the_login_holds() {
    let plane = Plane::with_actions(&[]).await;
    plane.allow_implicit(support::CONFIDENTIAL).await;

    for named in ["id_token", "id_token token", "code id_token token"] {
        let landing = through(&plane, named).await;
        let minted = in_fragment(&landing, "id_token").expect(named);
        let session_id = plane.claims_of(minted).await["sid"]
            .as_str()
            .expect("a session")
            .to_owned();

        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(
                &mut connection,
                &store::tenancy::TenantContext::new(support::TENANT, support::REALM),
            )
            .await;
        let held = store::providers::sessions::clients_of(&transaction, &session_id)
            .await
            .expect("the clients of this login");
        assert_eq!(
            held,
            vec![support::CONFIDENTIAL.to_owned()],
            "{named} left the login with no grant against it"
        );
    }
}

/// §5.4: what a scope names comes from the userinfo endpoint, except where
/// the response type is `id_token`. Nothing is minted there to reach userinfo
/// with, so the token carries them or the client never gets them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_identity_token_alone_carries_what_the_scope_names() {
    let plane = Plane::with_actions(&[]).await;
    plane.allow_implicit(support::CONFIDENTIAL).await;

    let landing = through_with(&plane, "id_token", "openid profile").await;
    let carried = plane
        .claims_of(in_fragment(&landing, "id_token").expect("an identity token"))
        .await;
    for (named, value) in [
        ("given_name", support::GIVEN_NAME),
        ("family_name", support::FAMILY_NAME),
        ("preferred_username", support::SUBJECT),
    ] {
        assert_eq!(carried[named].as_str(), Some(value), "{named}: {carried}");
    }
    assert_eq!(
        carried["name"].as_str(),
        Some(format!("{} {}", support::GIVEN_NAME, support::FAMILY_NAME)).as_deref()
    );
    // A scope the request never named releases nothing, whatever the realm
    // holds and whatever the person is.
    assert!(carried.get("email").is_none(), "{carried}");

    // With anything else beside it, userinfo is reachable, so it answers:
    // here for a token minted now, and after a redeemed code for the rest.
    for named in ["id_token token", "code id_token", "code id_token token"] {
        let landing = through_with(&plane, named, "openid profile").await;
        let carried = plane
            .claims_of(in_fragment(&landing, "id_token").expect("an identity token"))
            .await;
        for claim in ["given_name", "family_name", "name", "preferred_username"] {
            assert!(
                carried.get(claim).is_none(),
                "{named} minted {claim} where userinfo answers: {carried}"
            );
        }
    }
}
