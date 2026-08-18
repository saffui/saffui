//! The admin plane, from an HTTP request to a decision.
//!
//! The unit tests around `decide` hand it a `Presented` that was never a token.
//! Everything between the two is what this covers: the bearer, the issuer that
//! names a realm, the key identifier that picks one published key, the
//! algorithm taken from that key rather than from the token, the roles read out
//! of the database, and the route table that says what the path costs.
//!
//! Every refusal answers the same way on purpose, so these assert the status
//! and then assert the cause by arranging exactly one thing wrong at a time.

mod support;

use std::time::{Duration, SystemTime};

use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use server::app::{Plane as Mounted, mount};
use server::guard::AdminPolicy;
use support::{AUDIENCE, KID, Plane, SCOPE, SECOND_KID, SigningKey, claims};

fn policy() -> AdminPolicy {
    AdminPolicy {
        audiences: vec![AUDIENCE.to_owned()],
        scope: SCOPE.to_owned(),
    }
}

/// Mount the plane against this database, and send one request.
async fn request(plane: &Plane, method: Method, path: &str, bearer: Option<&str>) -> StatusCode {
    let mounted = Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: policy(),
    };
    let app = test::init_service(mount(App::new(), &mounted)).await;

    let mut builder = test::TestRequest::with_uri(path).method(method);
    if let Some(bearer) = bearer {
        builder = builder.insert_header(("authorization", format!("Bearer {bearer}")));
    }

    test::call_service(&app, builder.to_request())
        .await
        .status()
}

/// The whole plane, with nothing arranged wrong: a token this realm signed,
/// held by a user whose role carries the action the route declares.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_the_realm_signed_opens_the_route_its_holder_may_use() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;
    let bearer = plane.token(&claims());

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::OK
    );
}

/// A valid token whose holder does not hold what the route costs. The token is
/// the same one that opened the listing, so what is being tested is the action
/// and not the token.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_route_costs_what_the_table_says_and_not_what_the_token_is_worth() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;
    let bearer = plane.token(&claims());

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::OK,
        "the action the role carries did not open its own route"
    );
    assert_eq!(
        request(&plane, Method::GET, "/admin/realms/main", Some(&bearer)).await,
        StatusCode::FORBIDDEN,
        "listing realms paid for reading one"
    );
}

/// A caller holding a role that grants nothing is refused, and refused the same
/// way as one holding no role. Both are answers about what may be done, and
/// neither is an answer about what exists.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_role_that_grants_nothing_opens_nothing() {
    let plane = Plane::with_actions(&[]).await;
    let bearer = plane.token(&claims());

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::FORBIDDEN
    );
}

/// No bearer at all is actionable and says so. A caller with no token can go
/// and get one, and telling it so reveals nothing about what it could then do.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_request_with_no_token_is_told_to_get_one() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some("")).await,
        StatusCode::UNAUTHORIZED,
        "an empty bearer was read as a token"
    );
    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some("not-a-token")).await,
        StatusCode::UNAUTHORIZED
    );
}

/// The signature is what is checked, not the shape. This token is well formed,
/// names the realm's published key in its header, and was signed by a key the
/// realm never published.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_signed_by_a_key_the_realm_never_published_is_refused() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;

    // Signed elsewhere, and claiming to be the realm's own key.
    let elsewhere = SigningKey::generate(KID);
    let forged = elsewhere.sign(&claims(), KID);

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&forged)).await,
        StatusCode::UNAUTHORIZED,
        "a token signed by an unpublished key was accepted"
    );
}

/// One key is tried, the one the header names, and this is the test that can
/// tell that apart from trying whichever key accepts. The realm publishes two.
/// The same signature is presented twice: named as the key that made it, it is
/// accepted; named as the other published key, it is refused. Trying each key
/// in turn would accept both, which is how a retired key keeps signing long
/// after it stopped being the one in use.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_the_key_the_header_names_is_tried() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;

    let honest = plane.second.sign(&claims(), SECOND_KID);
    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&honest)).await,
        StatusCode::OK,
        "the second published key did not verify under its own name"
    );

    let misnamed = plane.second.sign(&claims(), KID);
    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&misnamed)).await,
        StatusCode::UNAUTHORIZED,
        "a signature was accepted under the name of a different published key"
    );
}

/// A token naming a key this realm has never published reaches no key at all.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_naming_a_key_the_realm_does_not_have_is_refused() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;
    let unknown = plane.second.sign(&claims(), "no-such-kid");

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&unknown)).await,
        StatusCode::UNAUTHORIZED
    );
}

/// The issuer picks which realm's keys to fetch, and it is the only thing taken
/// from an unverified payload. One naming no realm reaches no keys.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_issued_by_no_realm_this_deployment_has_is_refused() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;

    let mut elsewhere = claims();
    elsewhere.set_issuer("some-other-realm");
    let bearer = plane.token(&elsewhere);

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::UNAUTHORIZED
    );
}

/// A token this realm signed, for somebody else's ears. Refused before the
/// route is consulted, so which actions exist is not something an unaccepted
/// token learns from the shape of its refusal.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_for_another_audience_is_refused() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;

    let mut elsewhere = claims();
    elsewhere.set_audience(vec!["some-app"]);
    let bearer = plane.token(&elsewhere);

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::FORBIDDEN
    );
}

/// A signature is not a lifetime. The realm keeps a rotated key passive so the
/// tokens it already signed keep verifying, which means rotation retires no
/// token and `exp` is the only thing that does. These three are what would
/// otherwise be a bearer credential nothing can withdraw.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_outside_the_window_it_states_is_refused() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;

    let mut expired = claims();
    expired.set_expires_at(&(SystemTime::now() - Duration::from_secs(1)));
    let bearer = plane.token(&expired);
    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::UNAUTHORIZED,
        "a token that expired a second ago was accepted"
    );

    let mut early = claims();
    early.set_not_before(&(SystemTime::now() + Duration::from_secs(600)));
    let bearer = plane.token(&early);
    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::UNAUTHORIZED,
        "a token not yet valid was accepted"
    );
}

/// A token that states no expiry is refused rather than read as one that never
/// expires. The validator reads a time claim only when the token carries it, so
/// omitting the claim would satisfy every bound it never stated.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_that_states_no_expiry_is_refused() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;

    let mut forever = claims();
    forever
        .set_claim("exp", None)
        .expect("a payload with no expiry");
    let bearer = plane.token(&forever);

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::UNAUTHORIZED,
        "a token with no expiry was accepted, and nothing would ever withdraw it"
    );
}

/// The admin scope is matched whole. A token carrying `administrator` does not
/// carry `admin`, and a substring test would say it does.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_admin_scope_is_matched_whole() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;

    for scope in ["openid", "administrator", "adminread", ""] {
        let mut carrying = claims();
        carrying
            .set_claim("scope", Some(serde_json::json!(scope)))
            .expect("a scope claim");
        let bearer = plane.token(&carrying);

        assert_eq!(
            request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
            StatusCode::FORBIDDEN,
            "{scope} was accepted as the admin scope"
        );
    }
}

/// A route nobody declared is refused, even to a caller holding everything, and
/// refused by the guard rather than by the router.
///
/// The guard wraps the scope, so it answers before routing resolves a method.
/// That is the point: what closes the door is the absence of a declaration, not
/// the absence of a handler, and the two would otherwise diverge the moment
/// somebody mounted a handler and forgot to declare it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_undeclared_route_is_refused_to_a_caller_holding_everything() {
    let plane = Plane::with_actions(AdminAction::ALL).await;
    let bearer = plane.token(&claims());

    assert_eq!(
        request(&plane, Method::DELETE, "/admin/realms/main", Some(&bearer)).await,
        StatusCode::FORBIDDEN,
        "an undeclared method was answered by the router instead of the guard"
    );
    assert_eq!(
        request(&plane, Method::GET, "/admin/realms/main", Some(&bearer)).await,
        StatusCode::OK,
        "a caller holding everything was refused a declared route"
    );
}
