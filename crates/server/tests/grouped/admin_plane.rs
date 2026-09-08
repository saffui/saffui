#[allow(unused_imports)]
use super::support;
use std::time::{Duration, SystemTime};

use super::support::{
    AUDIENCE, KID, PARTY, Plane, REALM, SCOPE, SECOND_KID, SUBJECT, SigningKey, claims,
    cookie_value, pkce_pair, urlencode,
};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use chrono::Utc;
use models::entities::authz::AdminAction;
use server::api::config::{Plane as Mounted, register};
use server::middleware::admin_policy::AdminPolicy;
use store::tenancy::TenantContext;

fn policy() -> AdminPolicy {
    AdminPolicy {
        audiences: vec![AUDIENCE.to_owned()],
        parties: vec![PARTY.to_owned()],
        scope: SCOPE.to_owned(),
    }
}

/// What a deployment can actually configure, as against what the suite hands
/// `decide` directly.
///
/// The audience is the console's own client id because that is the only value a
/// minted token can carry: an access token names the client that asked for it,
/// and nothing adds a second audience. A deployment naming anything else here
/// has configured a plane its own console cannot reach.
fn console_policy() -> AdminPolicy {
    AdminPolicy {
        audiences: vec![PARTY.to_owned()],
        parties: vec![PARTY.to_owned()],
        scope: SCOPE.to_owned(),
    }
}

fn mounted(plane: &Plane, policy: &AdminPolicy) -> Mounted {
    Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: policy.clone(),
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    }
}

/// Mount the plane against this database, and send one request.
async fn request(plane: &Plane, method: Method, path: &str, bearer: Option<&str>) -> StatusCode {
    request_under(plane, &policy(), method, path, bearer).await
}

/// The same, under a policy the caller names.
async fn request_under(
    plane: &Plane,
    policy: &AdminPolicy,
    method: Method,
    path: &str,
    bearer: Option<&str>,
) -> StatusCode {
    let app = test::init_service(App::new().configure(register(&mounted(plane, policy)))).await;

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
/// from an unverified payload. One this deployment did not mint reaches no keys.
///
/// The prefix is what carries this. Without it `iss` is a string the gate routes
/// on and nobody verifies, so anything ending in a realm name this deployment
/// holds would resolve, whoever wrote it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_issued_by_no_realm_this_deployment_has_is_refused() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;

    for foreign in [
        // No realm of that name anywhere.
        "https://id.test/realms/some-other-realm",
        // The right realm, somebody else's deployment.
        "https://elsewhere.test/realms/main",
        // The realm name alone, which is what tokens used to carry.
        "main",
        // A prefix that only looks like ours.
        "https://id.test.attacker.example/realms/main",
        // Past the segment the issuer names.
        "https://id.test/realms/main/../other",
    ] {
        let mut elsewhere = claims();
        elsewhere.set_issuer(foreign);
        let bearer = plane.token(&elsewhere);

        assert_eq!(
            request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
            StatusCode::UNAUTHORIZED,
            "{foreign} reached a realm on this deployment"
        );
    }
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

/// The plane now asks the realm about the caller, not only the token about
/// itself. Switching an account off left every role in place and every route
/// open, because nothing between the signature and the decision ever looked.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_subject_the_realm_switched_off_is_refused() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;
    let bearer = plane.token(&claims());

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::OK,
        "the caller was refused before being switched off, so what follows proves nothing"
    );

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new("acme", REALM))
        .await;
    let mut user = store::providers::users::load(&transaction, SUBJECT)
        .await
        .unwrap()
        .unwrap();
    user.enabled = false;
    user.metadata = models::auditable::AuditableModel::from_updater("acme".into(), "root".into());
    store::providers::users::update(&transaction, &user)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::UNAUTHORIZED,
        "a disabled account still held every capability it was granted"
    );
}

/// A capability granted inside an organization is spent inside it. Claiming an
/// organization the caller does not belong to is refused, and a caller acting
/// across the realm does not carry what an organization granted it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_organization_grant_is_spent_where_it_was_made() {
    let plane = Plane::with_actions(&[]).await;

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new("acme", REALM))
        .await;
    store::providers::organizations::create(
        &transaction,
        &models::entities::organization::OrganizationModel {
            org_id: "north".into(),
            realm_id: REALM.into(),
            name: "north".into(),
            display_name: "North".into(),
            description: String::new(),
            enabled: true,
            domains: Vec::new(),
            redirect_url: None,
            attributes: None,
            metadata: models::auditable::AuditableModel::from_creator("acme".into(), "root".into()),
        },
    )
    .await
    .unwrap();
    store::providers::organizations::add_member(
        &transaction,
        &models::entities::organization::OrganizationMemberModel {
            realm_id: REALM.into(),
            org_id: "north".into(),
            user_id: SUBJECT.into(),
            membership_type: models::entities::organization::OrgMembershipType::Managed,
            roles: Vec::new(),
            joined_at: None,
            metadata: models::auditable::AuditableModel::from_creator("acme".into(), "root".into()),
        },
    )
    .await
    .unwrap();
    let lister = models::entities::authz::RoleMutationModel {
        name: "org-lister".into(),
        display_name: "Org lister".into(),
        description: String::new(),
        client_id: None,
        admin_actions: Some(vec![AdminAction::RealmList]),
    }
    .into_model(
        "org-lister".into(),
        REALM.into(),
        models::auditable::AuditableModel::from_creator("acme".into(), "root".into()),
    );
    store::providers::roles::create(&transaction, &lister)
        .await
        .unwrap();
    store::providers::organizations::grant_role(&transaction, "north", SUBJECT, "org-lister")
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    // Acting across the realm, the organization's grant is not held.
    let bearer = plane.token(&claims());
    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::FORBIDDEN,
        "a grant made inside an organization answered for the whole realm"
    );

    // Acting within it, and confirmed to belong, the grant counts.
    let mut inside = claims();
    inside
        .set_claim("org_id", Some(serde_json::json!("north")))
        .expect("an organization claim");
    let bearer = plane.token(&inside);
    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::OK
    );

    // Claiming one it does not belong to is refused before any capability is read.
    let mut elsewhere = claims();
    elsewhere
        .set_claim("org_id", Some(serde_json::json!("south")))
        .expect("an organization claim");
    let bearer = plane.token(&elsewhere);
    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::UNAUTHORIZED,
        "a caller confined itself to an organization it is not in"
    );
}

/// A window says when a token stops on its own, and nothing about withdrawing
/// one before then. A signature cannot be taken back and an expiry cannot be
/// brought forward, so revocation is the only lever there is, and it has to be
/// pulled here or it is not pulled at all.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_whose_identifier_was_revoked_is_refused() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;

    let mut identified = claims();
    identified.set_jwt_id("jti-1");
    let bearer = plane.token(&identified);

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::OK,
        "an unrevoked token was refused, so the test that follows proves nothing"
    );

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new("acme", REALM))
        .await;
    store::providers::oidc::revoke(
        &transaction,
        "jti-1",
        Utc::now() + chrono::Duration::hours(1),
        "logged out",
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    assert_eq!(
        request(&plane, Method::GET, "/admin/realms", Some(&bearer)).await,
        StatusCode::UNAUTHORIZED,
        "a revoked token still opened the plane"
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
        request(&plane, Method::DELETE, "/admin/realms", Some(&bearer)).await,
        StatusCode::FORBIDDEN,
        "an undeclared method was answered by the router instead of the guard"
    );
    assert_eq!(
        request(&plane, Method::GET, "/admin/realms/main", Some(&bearer)).await,
        StatusCode::OK,
        "a caller holding everything was refused a declared route"
    );
}

/// One client walking the browser loop, and how it proves itself at the end.
struct Walking<'a> {
    client_id: &'a str,
    redirect_uri: &'a str,
    /// What it asks `/authorize` for, which is not what it gets.
    asking: &'a str,
    /// A confidential client presents this. A public one has none, and proves
    /// the code was minted for it with a challenge instead.
    secret: Option<&'a str>,
}

/// Authorize, answer the password step, spend the code, and hand back what the
/// token endpoint answered.
///
/// One mounted app throughout, because a browser talks to one deployment: a
/// cookie set by one and offered to another would prove nothing about either.
async fn walk(plane: &Plane, policy: &AdminPolicy, who: &Walking<'_>) -> serde_json::Value {
    let app = test::init_service(App::new().configure(register(&mounted(plane, policy)))).await;
    let (verifier, challenge) = pkce_pair();

    let mut query = vec![
        ("response_type", "code"),
        ("client_id", who.client_id),
        ("redirect_uri", who.redirect_uri),
        ("scope", who.asking),
        ("state", "opaque-state"),
    ];
    if who.secret.is_none() {
        query.push(("code_challenge", challenge.as_str()));
        query.push(("code_challenge_method", "S256"));
    }
    let asked = query
        .iter()
        .map(|(key, value)| format!("{key}={}", urlencode(value)))
        .collect::<Vec<_>>()
        .join("&");

    let opened = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/auth?{asked}"
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        opened.status(),
        StatusCode::FOUND,
        "the request did not open a login"
    );
    let set = opened
        .headers()
        .get_all("set-cookie")
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let binding = cookie_value(&set, support::AUTH_SESSION_COOKIE)
        .expect("the browser was not bound to the login it just opened");

    let answered = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/login"))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .set_json(serde_json::json!({
                "username": SUBJECT,
                "password": support::PASSWORD,
            }))
            .to_request(),
    )
    .await;
    assert_eq!(answered.status(), StatusCode::OK);
    let told: serde_json::Value = test::read_body_json(answered).await;
    let landing = told["redirect_to"]
        .as_str()
        .unwrap_or_else(|| panic!("the login admitted nobody: {told}"));
    let code = landing
        .split_once("code=")
        .unwrap_or_else(|| panic!("no code came back: {landing}"))
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();

    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", who.redirect_uri),
    ];
    let mut spending =
        test::TestRequest::post().uri(&format!("/realms/{REALM}/protocol/openid-connect/token"));
    match who.secret {
        Some(secret) => {
            let credentials =
                data_encoding::BASE64.encode(format!("{}:{secret}", who.client_id).as_bytes());
            spending = spending.insert_header(("authorization", format!("Basic {credentials}")));
        }
        None => {
            form.push(("client_id", who.client_id));
            form.push(("code_verifier", verifier.as_str()));
        }
    }

    let spent = test::call_service(&app, spending.set_form(&form).to_request()).await;
    let status = spent.status();
    let granted: serde_json::Value = test::read_body_json(spent).await;
    assert_eq!(status, StatusCode::OK, "the code was not spent: {granted}");
    granted
}

/// Whether a granted scope carries one value, matched whole.
fn carries(granted: &serde_json::Value, wanted: &str) -> bool {
    granted["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .any(|held| held == wanted)
}

/// A token obtained the way a console obtains one, and the plane it opens.
///
/// Every other test here signs its own token, which says what `decide` does with
/// a payload and nothing about whether that payload is one this deployment can
/// mint. It could not: nothing created the scope the plane requires, so
/// `/authorize` dropped it from every request that named it, and `/admin` was
/// reachable only by a token written by hand.
///
/// The console asks for nothing but `openid` here, the way an admin UI that
/// knows only OIDC would. What puts the scope on the token is the attachment.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_console_reaches_the_plane_with_a_token_the_protocol_minted() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;
    let policy = console_policy();

    let granted = walk(
        &plane,
        &policy,
        &Walking {
            client_id: PARTY,
            redirect_uri: support::CONSOLE_REDIRECT,
            asking: "openid",
            secret: None,
        },
    )
    .await;

    // Asserted on the response as well as through the door below, so a failure
    // says which of the two halves broke.
    assert!(
        carries(&granted, SCOPE),
        "the console was granted no admin scope: {granted}"
    );

    assert_eq!(
        request_under(
            &plane,
            &policy,
            Method::GET,
            "/admin/realms",
            granted["access_token"].as_str(),
        )
        .await,
        StatusCode::OK,
        "a token this deployment minted did not open the plane it was minted for"
    );
}

/// Asking is not holding. The scope now exists in the realm, so a client that is
/// not the console can name it, and naming it must not be enough: the console is
/// the only thing attached to it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn asking_for_the_admin_scope_is_not_holding_it() {
    let plane = Plane::with_actions(&[AdminAction::RealmList]).await;
    let policy = console_policy();

    let granted = walk(
        &plane,
        &policy,
        &Walking {
            client_id: support::CONFIDENTIAL,
            redirect_uri: support::REDIRECT,
            asking: &format!("openid {SCOPE}"),
            secret: Some(support::CLIENT_SECRET),
        },
    )
    .await;

    assert!(
        !carries(&granted, SCOPE),
        "a client nothing attached to the admin scope was granted it: {granted}"
    );
    // Refused for the audience, and refused before the scope is ever read: an
    // access token names the client that asked for it, and this one is not the
    // console. Every refusal past the token renders the same, which is what
    // keeps the shape of this plane out of the answer.
    assert_eq!(
        request_under(
            &plane,
            &policy,
            Method::GET,
            "/admin/realms",
            granted["access_token"].as_str(),
        )
        .await,
        StatusCode::FORBIDDEN,
        "asking for the admin scope was enough to reach the plane"
    );
}

/// The same, answering with the body so a listing can be read.
async fn fetched(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
) -> (StatusCode, serde_json::Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane, &policy())))).await;
    let request = test::TestRequest::with_uri(path)
        .method(method)
        .insert_header(("authorization", format!("Bearer {bearer}")))
        .to_request();
    let response = test::call_service(&app, request).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

/// A user's keys are listed by what recognises and revokes them, and the
/// stored credential stays home: a response is not an export.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_users_keys_are_listed_and_the_stored_credential_stays_home() {
    let plane = Plane::with_actions(&[AdminAction::UserRead]).await;
    let key = plane.enrol_soft_passkey().await;
    let bearer = plane.token(&claims());

    let (status, listed) = fetched(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/users/{SUBJECT}/keys"),
        &bearer,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let items = listed.as_array().expect("a list");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["credential_id"],
        data_encoding::BASE64URL_NOPAD.encode(&key.credential_id),
        "not the identifier the revocation path spells"
    );
    assert!(
        items[0].get("passkey").is_none(),
        "the stored credential went on the wire: {listed}"
    );

    let (status, told) = fetched(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/users/nobody/keys"),
        &bearer,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
}

/// A revoked key is gone from the store, so the next keyed login has nothing
/// to present. Revoking it again is a miss, and a user nobody has is told
/// apart from a credential nobody has.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_revoked_key_is_gone_and_a_second_revocation_misses() {
    let plane = Plane::with_actions(&[AdminAction::UserRead, AdminAction::UserWrite]).await;
    let key = plane.enrol_soft_passkey().await;
    let bearer = plane.token(&claims());
    let spelled = data_encoding::BASE64URL_NOPAD.encode(&key.credential_id);

    assert_eq!(
        request(
            &plane,
            Method::DELETE,
            &format!("/admin/realms/{REALM}/users/{SUBJECT}/keys/{spelled}"),
            Some(&bearer),
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        plane.subject_keys().await,
        Vec::<Vec<u8>>::new(),
        "the revoked key is still in the store"
    );
    assert_eq!(
        request(
            &plane,
            Method::DELETE,
            &format!("/admin/realms/{REALM}/users/{SUBJECT}/keys/{spelled}"),
            Some(&bearer),
        )
        .await,
        StatusCode::NOT_FOUND,
        "revoking what is already gone reported a success"
    );
    assert_eq!(
        request(
            &plane,
            Method::DELETE,
            &format!("/admin/realms/{REALM}/users/nobody/keys/{spelled}"),
            Some(&bearer),
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            &plane,
            Method::DELETE,
            &format!("/admin/realms/{REALM}/users/{SUBJECT}/keys/not-base64url!"),
            Some(&bearer),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "a malformed identifier read as a credential that happens to be absent"
    );
}

/// Reading a user does not authorize disarming one: the listing and the
/// revocation cost what the table says, separately.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn reading_keys_does_not_authorize_revoking_one() {
    let plane = Plane::with_actions(&[AdminAction::UserRead]).await;
    let key = plane.enrol_soft_passkey().await;
    let bearer = plane.token(&claims());
    let spelled = data_encoding::BASE64URL_NOPAD.encode(&key.credential_id);

    assert_eq!(
        request(
            &plane,
            Method::DELETE,
            &format!("/admin/realms/{REALM}/users/{SUBJECT}/keys/{spelled}"),
            Some(&bearer),
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        plane.subject_keys().await,
        vec![key.credential_id.clone()],
        "a refused revocation went through anyway"
    );
}

/// A write to the plane, with a JSON body, answered with status and body.
async fn written(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane, &policy())))).await;
    let request = test::TestRequest::with_uri(path)
        .method(method)
        .insert_header(("authorization", format!("Bearer {bearer}")))
        .set_json(body)
        .to_request();
    let response = test::call_service(&app, request).await;
    let status = response.status();
    let raw = test::read_body(response).await;
    let told = if raw.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&raw).unwrap_or(serde_json::Value::Null)
    };
    (status, told)
}

/// The whole life of a client over the plane: registered with a secret shown
/// once and never again, read back, reshaped, its secret rotated, and gone.
/// The secret it was given is one the token endpoint accepts.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_is_born_reshaped_and_retired_over_the_plane() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/clients");

    let (status, born) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "client_id": "shop",
            "name": "The shop",
            "confidential": true,
            "redirect_uris": ["https://shop.example/cb"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let secret = born["client_secret"]
        .as_str()
        .expect("the secret, this once")
        .to_owned();
    assert_eq!(born["confidential"], true);

    // What the plane told is what the token endpoint believes.
    let app = test::init_service(App::new().configure(register(&mounted(&plane, &policy())))).await;
    let basic = data_encoding::BASE64.encode(format!("shop:{secret}").as_bytes());
    let asking = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
        .insert_header(("authorization", format!("Basic {basic}")))
        .set_form([("grant_type", "authorization_code"), ("code", "none")])
        .to_request();
    let response = test::call_service(&app, asking).await;
    let told: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(
        told["error"], "invalid_grant",
        "the client was not established with its own secret: {told}"
    );

    let (status, read) = fetched(&plane, Method::GET, &format!("{base}/shop"), &bearer).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        read.get("client_secret").is_none(),
        "a read showed the secret: {read}"
    );
    assert_eq!(
        read["redirect_uris"],
        serde_json::json!(["https://shop.example/cb"])
    );

    let (status, again) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({ "client_id": "shop", "redirect_uris": ["https://shop.example/cb"] }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{again}");

    let (status, bad) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({ "client_id": "shop2", "redirect_uris": ["shop.example/cb#frag"] }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");

    let (status, reshaped) = written(
        &plane,
        Method::PUT,
        &format!("{base}/shop"),
        &bearer,
        serde_json::json!({ "post_logout_redirect_uris": ["https://shop.example/bye"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reshaped}");
    assert_eq!(
        reshaped["redirect_uris"],
        serde_json::json!(["https://shop.example/cb"]),
        "a list left out was not left alone"
    );
    assert_eq!(
        reshaped["post_logout_redirect_uris"],
        serde_json::json!(["https://shop.example/bye"])
    );

    let (status, rotated) = written(
        &plane,
        Method::POST,
        &format!("{base}/shop/secret"),
        &bearer,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    assert_ne!(rotated["client_secret"].as_str().unwrap(), secret);

    let (status, listed) =
        fetched(&plane, Method::GET, &format!("{base}?count=true"), &bearer).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["client_id"] == "shop"),
        "{listed}"
    );

    assert_eq!(
        request(
            &plane,
            Method::DELETE,
            &format!("{base}/shop"),
            Some(&bearer)
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(
            &plane,
            Method::DELETE,
            &format!("{base}/shop"),
            Some(&bearer)
        )
        .await,
        StatusCode::NOT_FOUND
    );
}

/// A person created over the plane, with a password, can sign in with it;
/// reshaped and retired after. Reading people does not authorize writing them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_is_created_signs_in_and_is_retired_over_the_plane() {
    let plane = Plane::with_actions(&[AdminAction::UserRead, AdminAction::UserWrite]).await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/users");

    let (status, born) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "user_name": "grace",
            "email": "grace@example.test",
            "given_name": "Grace",
            "family_name": "Hopper",
            "password": "a-fresh-password-of-decent-length",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    assert_eq!(born["given_name"], "Grace");
    assert!(born.get("password").is_none() && born.get("credentials").is_none());

    // The password the plane was given is one the login accepts.
    let app = test::init_service(App::new().configure(register(&mounted(&plane, &policy())))).await;
    let (_, _, opened) = {
        let asked = format!(
            "/realms/{REALM}/protocol/openid-connect/auth?response_type=code&client_id={}&scope=openid&redirect_uri={}&state=s",
            support::CONFIDENTIAL,
            support::REDIRECT
        );
        let response =
            test::call_service(&app, test::TestRequest::get().uri(&asked).to_request()).await;
        let set = response
            .headers()
            .get_all("set-cookie")
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        (response.status(), (), set)
    };
    let binding = cookie_value(&opened, support::AUTH_SESSION_COOKIE).expect("a binding");
    let answered = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect/login"))
        .insert_header(("cookie", format!("{}={binding}", support::AUTH_SESSION_COOKIE)))
        .set_json(serde_json::json!({ "username": "grace", "password": "a-fresh-password-of-decent-length" }))
        .to_request();
    let response = test::call_service(&app, answered).await;
    let told: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(told["status"], "admitted", "{told}");

    let (status, reshaped) = written(
        &plane,
        Method::PUT,
        &format!("{base}/grace"),
        &bearer,
        serde_json::json!({ "enabled": false, "phone_number": "+33100000000" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reshaped}");
    assert_eq!(reshaped["enabled"], false);
    assert_eq!(
        reshaped["given_name"], "Grace",
        "a field left out was not left alone"
    );
    assert_eq!(reshaped["phone_number"], "+33100000000");

    let (status, again) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({ "user_name": "grace" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{again}");

    assert_eq!(
        request(
            &plane,
            Method::DELETE,
            &format!("{base}/grace"),
            Some(&bearer)
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let (status, _) = fetched(&plane, Method::GET, &format!("{base}/grace"), &bearer).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Reading people is not writing them: the table charges the two apart.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn reading_people_does_not_authorize_writing_them() {
    let plane = Plane::with_actions(&[AdminAction::UserRead]).await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/users");

    let (status, _) = fetched(&plane, Method::GET, &base, &bearer).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({ "user_name": "nobody" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
/// The realm-wide listing sees the logins, and ending them empties it.
///
/// Half of a breach answer. The other half is the realm's cut, which refuses
/// tokens already minted and is checked where a real token exists.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn every_login_in_the_realm_is_listed_and_can_be_ended_at_once() {
    let plane = Plane::with_actions(&[AdminAction::UserRead, AdminAction::UserWrite]).await;
    let bearer = plane.token(&claims());
    let listing = format!("/admin/realms/{REALM}/sessions");

    let (status, listed) = fetched(&plane, Method::GET, &listing, &bearer).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let rows = listed["items"].as_array().expect("a page").clone();
    assert!(
        rows.iter().any(|row| row["login_username"] == SUBJECT),
        "the realm listing did not name the live login: {listed}"
    );
    // No grants on a realm-wide row: the listing is read to find something in a
    // realm that may hold thousands, and a query per row would make the screen
    // somebody opens during a breach the slowest in the console.
    assert!(
        rows.iter().all(|row| row.get("grants").is_none()),
        "a realm-wide row paid for its grants: {listed}"
    );

    let (status, ended) = fetched(&plane, Method::DELETE, &listing, &bearer).await;
    assert_eq!(status, StatusCode::OK, "{ended}");
    assert!(
        ended["ended"].as_u64().is_some_and(|held| held > 0),
        "{ended}"
    );
    // Said in the answer rather than left for somebody to discover.
    assert_eq!(
        ended["tokens_still_valid_until_their_span"], true,
        "{ended}"
    );

    // Every login means every login, the operator's own included: their token
    // is bound to a session that no longer exists, so the very next call is
    // refused. Worth knowing before pressing it, and worth keeping true: a
    // lever that spared whoever pulled it would not be the lever it claims.
    let (status, refused) = fetched(&plane, Method::GET, &listing, &bearer).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}");
}

/// The grants an operator turns on, over the plane and then in the engines.
///
/// Three keys the engines already read; what was missing was a hand on them.
/// The proof that matters is not that the write landed but that the engine
/// answers differently afterwards, so the device endpoint is asked both ways.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_grants_an_operator_opens_are_the_ones_the_engines_serve() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/clients");

    // Born with nothing opened: a client inherits no grant by asking.
    let (status, born) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "client_id": "kiosk",
            "confidential": true,
            "description": "the one in the lobby",
            "client_uri": "https://kiosk.example/welcome",
            "redirect_uris": ["https://kiosk.example/cb"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let secret = born["client_secret"]
        .as_str()
        .expect("the secret, this once")
        .to_owned();
    assert_eq!(born["device_grant"], false, "{born}");
    assert_eq!(born["token_exchange"], false, "{born}");
    assert_eq!(born["ciba_delivery"], "off", "{born}");
    assert_eq!(born["description"], "the one in the lobby", "{born}");
    assert_eq!(
        born["client_uri"], "https://kiosk.example/welcome",
        "{born}"
    );

    let device_endpoint = format!("/realms/{REALM}/protocol/openid-connect/device-authorization");
    async fn ask_device(plane: &Plane, uri: &str, secret: &str) -> (StatusCode, serde_json::Value) {
        let app =
            test::init_service(App::new().configure(register(&mounted(plane, &policy())))).await;
        // Established the way the client would establish itself. A refusal for
        // want of a secret looks like a refusal for want of the grant, and this
        // test would then pass without the gate existing at all.
        let basic = data_encoding::BASE64.encode(format!("kiosk:{secret}").as_bytes());
        let asking = test::TestRequest::post()
            .uri(uri)
            .insert_header(("authorization", format!("Basic {basic}")))
            .set_form([("scope", "openid")])
            .to_request();
        let response = test::call_service(&app, asking).await;
        let status = response.status();
        // A refusal need not be JSON, and a test that insists on it fails at
        // the parse rather than at the thing it came to check.
        let raw = test::read_body(response).await;
        let told = serde_json::from_slice(&raw).unwrap_or(serde_json::Value::Null);
        (status, told)
    }

    // Closed: the engine turns it away.
    let (status, refused) = ask_device(&plane, &device_endpoint, &secret).await;
    assert_ne!(status, StatusCode::OK, "a closed grant answered: {refused}");
    assert_eq!(
        refused["error"], "unauthorized_client",
        "the refusal was not the grant's: {refused}"
    );

    // Opened over the plane.
    let (status, opened) = written(
        &plane,
        Method::PUT,
        &format!("{base}/kiosk"),
        &bearer,
        serde_json::json!({ "device_grant": true, "token_exchange": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    assert_eq!(opened["device_grant"], true, "{opened}");
    assert_eq!(opened["token_exchange"], true, "{opened}");
    // Naming the grants left the rest of the registration alone.
    assert_eq!(
        opened["redirect_uris"],
        serde_json::json!(["https://kiosk.example/cb"]),
        "{opened}"
    );
    assert_eq!(opened["description"], "the one in the lobby", "{opened}");

    // The engine now answers: the same call gets a code.
    let (status, served) = ask_device(&plane, &device_endpoint, &secret).await;
    assert_eq!(status, StatusCode::OK, "{served}");
    assert!(served["device_code"].is_string(), "{served}");

    // Shut again, and the engine shuts with it.
    let (status, shut) = written(
        &plane,
        Method::PUT,
        &format!("{base}/kiosk"),
        &bearer,
        serde_json::json!({ "device_grant": false }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shut}");
    assert_eq!(shut["device_grant"], false, "{shut}");
    assert_eq!(
        shut["token_exchange"], true,
        "shutting one grant shut another: {shut}"
    );
    let (status, refused) = ask_device(&plane, &device_endpoint, &secret).await;
    assert_ne!(status, StatusCode::OK, "a shut grant answered: {refused}");
    assert_eq!(
        refused["error"], "unauthorized_client",
        "the refusal was not the grant's: {refused}"
    );
}

/// RFC 8705's one name over the plane: set in one form, moved whole to
/// another, refused in words when two ride one body, and cleared by an
/// empty string. At most one key ever stands, because the verifier admits
/// exactly one and refuses a plural bag.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_carries_at_most_one_tls_name() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/clients");

    let (status, born) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "client_id": "mtls-till",
            "confidential": true,
            "redirect_uris": ["https://till.example/cb"],
            "tls_san_dns": "till.example",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    assert_eq!(born["tls_san_dns"], "till.example", "{born}");
    assert_eq!(born["tls_subject_dn"], serde_json::Value::Null, "{born}");

    // Moved to another form: the old key does not linger beside the new.
    let (status, moved) = written(
        &plane,
        Method::PUT,
        &format!("{base}/mtls-till"),
        &bearer,
        serde_json::json!({ "tls_subject_dn": "CN=till,O=Acme" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["tls_subject_dn"], "CN=till,O=Acme", "{moved}");
    assert_eq!(
        moved["tls_san_dns"],
        serde_json::Value::Null,
        "the old name lingered beside the new: {moved}"
    );

    // Two in one body is a client that could never authenticate again.
    let (status, refused) = written(
        &plane,
        Method::PUT,
        &format!("{base}/mtls-till"),
        &bearer,
        serde_json::json!({ "tls_san_dns": "till.example", "tls_san_uri": "spiffe://till" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
    assert!(
        refused["message"]
            .as_str()
            .unwrap_or_default()
            .contains("exactly one TLS name"),
        "the refusal does not say the rule: {refused}"
    );

    // An empty string turns certificate authentication off.
    let (status, off) = written(
        &plane,
        Method::PUT,
        &format!("{base}/mtls-till"),
        &bearer,
        serde_json::json!({ "tls_subject_dn": "" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{off}");
    for key in ["tls_san_dns", "tls_san_uri", "tls_subject_dn"] {
        assert_eq!(
            off[key],
            serde_json::Value::Null,
            "{key} survived the clearing: {off}"
        );
    }
}

/// The backchannel opt-in is the delivery mode, so half of one is refused
/// rather than written and then read back as nothing.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_ping_without_an_endpoint_is_refused_at_the_door() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/clients");

    let (status, _) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "client_id": "till",
            "confidential": true,
            "redirect_uris": ["https://till.example/cb"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    for asked in [
        serde_json::json!({ "ciba_delivery": "ping" }),
        serde_json::json!({ "ciba_delivery": "ping", "ciba_notification_endpoint": "http://till.example/ciba" }),
        serde_json::json!({ "ciba_delivery": "carrier-pigeon" }),
    ] {
        let (status, told) = written(
            &plane,
            Method::PUT,
            &format!("{base}/till"),
            &bearer,
            asked.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{asked} was taken: {told}"
        );
    }

    // The whole opt-in, and it reads back whole.
    let (status, told) = written(
        &plane,
        Method::PUT,
        &format!("{base}/till"),
        &bearer,
        serde_json::json!({
            "ciba_delivery": "ping",
            "ciba_notification_endpoint": "https://till.example/ciba",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["ciba_delivery"], "ping", "{told}");
    assert_eq!(
        told["ciba_notification_endpoint"], "https://till.example/ciba",
        "{told}"
    );

    // Off takes the endpoint with it: a mode without one is not a mode.
    let (_, told) = written(
        &plane,
        Method::PUT,
        &format!("{base}/till"),
        &bearer,
        serde_json::json!({ "ciba_delivery": "off" }),
    )
    .await;
    assert_eq!(told["ciba_delivery"], "off", "{told}");
    assert_eq!(
        told["ciba_notification_endpoint"],
        serde_json::Value::Null,
        "{told}"
    );
}

/// The realm's password policy applies wherever a password enters, not only
/// where a person walks in themselves.
///
/// It was read at self-service signup and at a mailed reset, and nowhere else.
/// An administrator, and a directory pushing over SCIM, could plant anything a
/// realm had declared it would not have, while the realm went on refusing the
/// same password to the person who owns the account.
///
/// The rule about a birth date is checked here too, because it could never
/// refuse anything before: both callers that consulted the policy passed no
/// birth date, though the profile has held one all along.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_password_policy_is_read_at_every_door_a_password_enters_by() {
    let plane = Plane::with_actions(&[AdminAction::UserRead, AdminAction::UserWrite]).await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/users");

    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let mut realm = store::providers::realms::load(&transaction, REALM)
            .await
            .expect("the realms table")
            .expect("a planted realm");
        realm.password_policy = Some(models::entities::realm::PasswordPolicy {
            min_length: Some(12),
            not_username: Some(true),
            not_birthdate: Some(true),
            ..Default::default()
        });
        store::providers::realms::update(&transaction, &realm)
            .await
            .expect("the realms table");
        transaction.commit().await.expect("the policy kept");
    }

    // Creation: refused in the realm's own words, not flattened into a 500.
    let (status, told) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "user_name": "grace",
            "email": "grace@example.test",
            "password": "short",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|said| said.contains("too short")),
        "the refusal did not say which rule: {told}"
    );

    let (status, born) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "user_name": "grace",
            "email": "grace@example.test",
            "password": "a-fresh-password-of-decent-length",
            "attributes": { "user.profile.birthdate": "1906-12-09" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");

    // Setting one afterwards: the same policy, the same words.
    let (status, told) = written(
        &plane,
        Method::PUT,
        &format!("{base}/grace/password"),
        &bearer,
        serde_json::json!({ "password": "short" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // The person's own name, which needs the person to be loaded to refuse.
    let (status, told) = written(
        &plane,
        Method::PUT,
        &format!("{base}/grace/password"),
        &bearer,
        serde_json::json!({ "password": "grace" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // The birth date off the profile. This rule was unreachable until now: the
    // two callers that read the policy passed no birth date at all.
    let (status, told) = written(
        &plane,
        Method::PUT,
        &format!("{base}/grace/password"),
        &bearer,
        serde_json::json!({ "password": "1906-12-09" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a password that is the person's birth date was taken: {told}"
    );

    // And one the policy has nothing against still lands.
    let (status, told) = written(
        &plane,
        Method::PUT,
        &format!("{base}/grace/password"),
        &bearer,
        serde_json::json!({ "password": "another-decent-length-one" }),
    )
    .await;
    assert!(status.is_success(), "{told}");
}

/// A realm that asks for a password history gets one, and a policy no password
/// can satisfy is refused at the door rather than at every registration.
///
/// The PasswordHistory credential type has existed since the third migration
/// with nothing ever writing one, so the setting could be turned on and the
/// history stayed empty for ever. The standing password counts as the first
/// remembered: refusing the last few and taking the current one back would be a
/// rule with a hole the width of the likeliest password.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_password_this_account_wore_before_is_refused() {
    let plane = Plane::with_actions(&[
        AdminAction::UserRead,
        AdminAction::UserWrite,
        AdminAction::RealmRead,
        AdminAction::RealmWrite,
    ])
    .await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/users");
    let realm = format!("/admin/realms/{REALM}");

    // A history deeper than anybody remembers is more hashing than a password
    // change can pay for, and it is refused where the policy is written.
    let (status, told) = written(
        &plane,
        Method::PUT,
        &realm,
        &bearer,
        serde_json::json!({ "password_policy": { "history_look_back": 100 } }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // So is one no password at all can satisfy. This was writable until now:
    // the function that reads it back had no caller.
    let (status, told) = written(
        &plane,
        Method::PUT,
        &realm,
        &bearer,
        serde_json::json!({ "password_policy": { "min_length": 20, "max_length": 8 } }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, told) = written(
        &plane,
        Method::PUT,
        &realm,
        &bearer,
        serde_json::json!({ "password_policy": { "min_length": 12, "history_look_back": 3 } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let (status, born) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "user_name": "grace",
            "email": "grace@example.test",
            "password": "the-first-one-of-decent-length",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");

    let set = |password: &'static str| {
        let plane = &plane;
        let bearer = bearer.clone();
        let base = base.clone();
        async move {
            written(
                plane,
                Method::PUT,
                &format!("{base}/grace/password"),
                &bearer,
                serde_json::json!({ "password": password }),
            )
            .await
        }
    };

    // The standing one is the first remembered.
    let (status, told) = set("the-first-one-of-decent-length").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|said| said.contains("used before")),
        "{told}"
    );

    // Change twice, and both are remembered.
    for password in [
        "the-second-one-of-decent-length",
        "the-third-one-of-decent-length",
    ] {
        let (status, told) = set(password).await;
        assert!(status.is_success(), "{password}: {told}");
    }
    for worn in [
        "the-first-one-of-decent-length",
        "the-second-one-of-decent-length",
        "the-third-one-of-decent-length",
    ] {
        let (status, told) = set(worn).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{worn}: {told}");
    }

    // One nobody has worn still lands.
    let (status, told) = set("a-fourth-one-of-decent-length").await;
    assert!(status.is_success(), "{told}");
}

/// The not-before doors, client and realm alike, take the past and refuse the
/// future: a cut is an answer to a leak that already happened, and a future
/// instant would refuse every token still to be minted, the console's own
/// included. Striking, reading back, and lifting all ride the ordinary
/// update; nothing new to learn under pressure.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_cut_is_struck_in_the_past_and_never_in_the_future() {
    let plane = Plane::with_actions(&[
        AdminAction::ClientRead,
        AdminAction::ClientWrite,
        AdminAction::RealmRead,
        AdminAction::RealmWrite,
    ])
    .await;
    let bearer = plane.token(&claims());
    let clients = format!("/admin/realms/{REALM}/clients");
    let realm = format!("/admin/realms/{REALM}");

    let now = chrono::Utc::now().timestamp();
    let (status, told) = written(
        &plane,
        Method::PUT,
        &format!("{clients}/{}", support::CONFIDENTIAL),
        &bearer,
        serde_json::json!({ "not_before": now }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (_, read) = fetched(
        &plane,
        Method::GET,
        &format!("{clients}/{}", support::CONFIDENTIAL),
        &bearer,
    )
    .await;
    assert_eq!(read["not_before"], now, "{read}");

    // 0 lifts it, and a rewrite naming nothing leaves it alone.
    let (status, told) = written(
        &plane,
        Method::PUT,
        &format!("{clients}/{}", support::CONFIDENTIAL),
        &bearer,
        serde_json::json!({ "not_before": 0 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (_, read) = fetched(
        &plane,
        Method::GET,
        &format!("{clients}/{}", support::CONFIDENTIAL),
        &bearer,
    )
    .await;
    assert!(read["not_before"].is_null(), "{read}");

    // The future is refused at both doors, in words naming why.
    for (path, body) in [
        (
            format!("{clients}/{}", support::CONFIDENTIAL),
            serde_json::json!({ "not_before": now + 3600 }),
        ),
        (realm, serde_json::json!({ "not_before": now + 3600 })),
    ] {
        let (status, told) = written(&plane, Method::PUT, &path, &bearer, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert!(
            told["message"]
                .as_str()
                .unwrap_or_default()
                .contains("revokes the past"),
            "{told}"
        );
    }
}

/// The subject-request register, end to end: the clock is counted from the
/// statute and answers with its citation, a jurisdiction that fixes no
/// window demands a date, the lifecycle refuses what the law refuses, and
/// lodging against an unknown identifier answers exactly like a known one,
/// so the register is not a way to ask which addresses hold accounts.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_subject_request_walks_its_lifecycle_and_the_clock_is_cited() {
    let plane = Plane::with_actions(&[AdminAction::DsarRead, AdminAction::DsarWrite]).await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/subject-requests");

    // Kenya's seven days, counted and cited.
    let (status, lodged) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "subject_identifier": "ada",
            "kind": "erasure",
            "jurisdiction": "ke",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{lodged}");
    assert_eq!(lodged["stage"], "received", "{lodged}");
    assert_eq!(
        lodged["due_at"].as_i64(),
        lodged["received_at"].as_i64().map(|at| at + 7 * 86_400),
        "{lodged}"
    );
    assert!(
        lodged["deadline_source"]
            .as_str()
            .unwrap_or_default()
            .contains("seven days"),
        "{lodged}"
    );
    assert_eq!(lodged["user_id"], "ada", "{lodged}");
    let request_id = lodged["request_id"].as_str().expect("an id").to_owned();

    // An identifier nobody answers to is lodged in exactly the same shape.
    let (status, stranger) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "subject_identifier": "nobody@example.test",
            "kind": "access",
            "jurisdiction": "ke",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{stranger}");
    assert!(stranger["user_id"].is_null(), "{stranger}");
    let keys = |told: &serde_json::Value| {
        let mut named: Vec<String> = told
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        named.sort();
        named
    };
    assert_eq!(
        keys(&lodged),
        keys(&stranger),
        "the two answers differ in shape"
    );

    // A jurisdiction that fixes no window refuses to invent one.
    let (status, told) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "subject_identifier": "ada",
            "kind": "access",
            "jurisdiction": "ng",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .unwrap_or_default()
            .contains("fixes no window"),
        "{told}"
    );
    let (status, dated) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "subject_identifier": "ada",
            "kind": "access",
            "jurisdiction": "ng",
            "due_at": 4_102_444_800i64,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{dated}");
    assert_eq!(dated["due_at"], 4_102_444_800i64, "{dated}");

    // The register reads back, tightest clock first.
    let (status, listed) = fetched(&plane, Method::GET, &base, &bearer).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed.as_array().map(Vec::len), Some(3), "{listed}");
    assert!(
        listed[0]["due_at"].as_i64() <= listed[1]["due_at"].as_i64()
            && listed[1]["due_at"].as_i64() <= listed[2]["due_at"].as_i64(),
        "{listed}"
    );
    assert_eq!(listed[2]["jurisdiction"], "ng", "{listed}");

    // The lifecycle: proven, not provable twice, then closed with a reason.
    let (status, verified) = written(
        &plane,
        Method::POST,
        &format!("{base}/{request_id}/verify"),
        &bearer,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    assert_eq!(verified["stage"], "verified", "{verified}");
    let (status, again) = written(
        &plane,
        Method::POST,
        &format!("{base}/{request_id}/verify"),
        &bearer,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{again}");
    let (status, told) = written(
        &plane,
        Method::POST,
        &format!("{base}/{request_id}/refuse"),
        &bearer,
        serde_json::json!({ "reason": "  " }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let (status, refused) = written(
        &plane,
        Method::POST,
        &format!("{base}/{request_id}/refuse"),
        &bearer,
        serde_json::json!({ "reason": "legal hold" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refused}");
    assert_eq!(refused["stage"], "refused", "{refused}");
    assert_eq!(refused["reason"], "legal hold", "{refused}");

    // Another realm's register is another realm's, and the isolation is
    // now stated a step earlier than it used to be: this once answered an
    // empty list, which meant the rows did not cross. The read itself is
    // refused, so there is no list to be empty.
    plane.plant_realm("mirror").await;
    let (status, elsewhere) = fetched(
        &plane,
        Method::GET,
        "/admin/realms/mirror/subject-requests",
        &bearer,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{elsewhere}");

    // An id nobody holds answers as absent, not as an error to tell apart.
    let (status, told) = fetched(&plane, Method::GET, &format!("{base}/unknown"), &bearer).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
}

/// The one verb the register withheld arrives with the execution that makes
/// it true. An erasure fells what no cascade reaches, deletes the account
/// with everything keyed to it, and leaves exactly one thing behind on its
/// way out: the event the connectors and receivers de-provision by. The
/// other kinds say their execution has not shipped instead of pretending;
/// an identifier nobody holds fulfils as "nothing to erase"; and the account
/// whose own session is asking is refused, because the erasure would end
/// that session mid-walk and lock its holder out.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_erasure_erases_and_tells_the_world_on_its_way_out() {
    let plane = Plane::with_actions(&[AdminAction::DsarRead, AdminAction::DsarWrite]).await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/subject-requests");

    // The subject is a third person, seeded with everything an account
    // gathers, the rows no cascade reaches included.
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let grace = models::entities::user::UserCreateModel {
            user_name: "grace".into(),
            enabled: true,
            email: "grace@example.test".into(),
            email_verified: Some(true),
            phone_number: None,
            phone_number_verified: None,
            required_actions: None,
            not_before: None,
            user_storage: None,
            attributes: None,
            is_service_account: None,
            service_account_client_link: None,
        }
        .into_model(
            "grace".into(),
            REALM.into(),
            models::auditable::AuditableModel::from_creator(
                support::TENANT.to_owned(),
                "root".to_owned(),
            ),
        );
        store::providers::users::create(&transaction, &grace)
            .await
            .unwrap();
        transaction
            .execute(
                "INSERT INTO backchannel_requests \
                 (tenant, realm_id, request_digest, client_id, user_id, scope, \
                  interval_secs, expires_at) \
                 VALUES ($1, $2, decode(repeat('ab', 32), 'hex'), $3, 'grace', 'openid', 5, \
                         now() + interval '1 hour')",
                &[&support::TENANT, &REALM, &support::CONFIDENTIAL],
            )
            .await
            .unwrap();
        transaction
            .execute(
                "INSERT INTO oidc_device_codes \
                 (tenant, realm_id, device_digest, user_code, client_id, scope, \
                  user_id, interval_secs, expires_at) \
                 VALUES ($1, $2, decode(repeat('cd', 32), 'hex'), 'BCDF-GHJK', $3, 'openid', \
                         'grace', 5, now() + interval '1 hour')",
                &[&support::TENANT, &REALM, &support::CONFIDENTIAL],
            )
            .await
            .unwrap();
        store::providers::outbox::emit(
            &transaction,
            store::providers::outbox::USER_UPDATED,
            "grace",
            &serde_json::json!({ "email": "grace@example.test" }),
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }

    let lodge = |kind: &'static str, identifier: &'static str| {
        let plane = &plane;
        let bearer = &bearer;
        let base = &base;
        async move {
            let (status, told) = written(
                plane,
                Method::POST,
                base,
                bearer,
                serde_json::json!({
                    "subject_identifier": identifier,
                    "kind": kind,
                    "jurisdiction": "eu",
                }),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{told}");
            told["request_id"].as_str().expect("an id").to_owned()
        }
    };
    let advance = |request_id: String, step: &'static str| {
        let plane = &plane;
        let bearer = &bearer;
        let base = &base;
        async move {
            written(
                plane,
                Method::POST,
                &format!("{base}/{request_id}/{step}"),
                bearer,
                serde_json::json!({}),
            )
            .await
        }
    };

    // Unproven, nothing irreversible runs.
    let erasure = lodge("erasure", "grace").await;
    let (status, told) = advance(erasure.clone(), "fulfil").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .unwrap_or_default()
            .contains("must not be executed before"),
        "{told}"
    );

    // Every kind executes now; what still refuses is an execution asked
    // with nothing to do.
    let pending = lodge("rectification", "grace").await;
    advance(pending.clone(), "verify").await;
    let (status, told) = advance(pending, "fulfil").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .unwrap_or_default()
            .contains("names what to correct"),
        "{told}"
    );

    // The account whose own session is asking is refused in words.
    let own = lodge("erasure", "ada").await;
    advance(own.clone(), "verify").await;
    let (status, told) = advance(own, "fulfil").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .unwrap_or_default()
            .contains("its own session"),
        "{told}"
    );

    // Proven, the erasure runs whole.
    advance(erasure.clone(), "verify").await;
    let (status, done) = advance(erasure, "fulfil").await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(done["stage"], "fulfilled", "{done}");
    assert!(
        done["outcome"]
            .as_str()
            .unwrap_or_default()
            .contains("were erased"),
        "{done}"
    );

    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        assert!(
            store::providers::users::load(&transaction, "grace")
                .await
                .unwrap()
                .is_none(),
            "the account survived its erasure"
        );
        let orphans: i64 = transaction
            .query_one(
                "SELECT (SELECT count(*) FROM backchannel_requests WHERE user_id = 'grace') \
                      + (SELECT count(*) FROM oidc_device_codes WHERE user_id = 'grace') \
                      + (SELECT count(*) FROM user_credentials WHERE user_id = 'grace') \
                      + (SELECT count(*) FROM user_sessions WHERE user_id = 'grace')",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(orphans, 0, "rows outlived the erasure");
        // Exactly one thing leaves on the way out, and it is not the profile.
        let outgoing = transaction
            .query("SELECT kind FROM event_outbox WHERE user_id = 'grace'", &[])
            .await
            .unwrap();
        let kinds: Vec<String> = outgoing.iter().map(|row| row.get(0)).collect();
        assert_eq!(
            kinds,
            vec![store::providers::outbox::USER_DELETED.to_owned()],
            "the outbox holds more than the parting word"
        );
    }

    // An identifier nobody holds fulfils honestly: nothing to erase.
    let ghost = lodge("erasure", "nobody@example.test").await;
    advance(ghost.clone(), "verify").await;
    let (status, done) = advance(ghost, "fulfil").await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(
        done["outcome"]
            .as_str()
            .unwrap_or_default()
            .contains("nothing to erase"),
        "{done}"
    );
}

/// The copy an access request hands over: everything the realm holds about
/// the person, drawn once into the fulfilling answer and never stored, with
/// the one thing that is nobody's to receive kept out of it entirely: the
/// hashes that verify credentials. Portability draws the narrower copy, only
/// what the person provided; and a copy is not readable back later, because
/// producing another is fulfilling again, which the lifecycle refuses.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_access_copy_holds_everything_and_no_secret_rides_it() {
    let plane = Plane::with_actions(&[AdminAction::DsarRead, AdminAction::DsarWrite]).await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/subject-requests");
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::consents::keep(
            &transaction,
            support::SUBJECT,
            support::CONFIDENTIAL,
            &["openid".to_owned(), "profile".to_owned()],
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }
    let walk = |kind: &'static str| {
        let plane = &plane;
        let bearer = &bearer;
        let base = &base;
        async move {
            let (status, told) = written(
                plane,
                Method::POST,
                base,
                bearer,
                serde_json::json!({
                    "subject_identifier": "ada",
                    "kind": kind,
                    "jurisdiction": "eu",
                }),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{told}");
            let id = told["request_id"].as_str().expect("an id").to_owned();
            written(
                plane,
                Method::POST,
                &format!("{base}/{id}/verify"),
                bearer,
                serde_json::json!({}),
            )
            .await;
            let (status, told) = written(
                plane,
                Method::POST,
                &format!("{base}/{id}/fulfil"),
                bearer,
                serde_json::json!({}),
            )
            .await;
            (status, told, id)
        }
    };

    let (status, copied, access_id) = walk("access").await;
    assert_eq!(status, StatusCode::OK, "{copied}");
    let bundle = &copied["bundle"];
    assert_eq!(bundle["held"], true, "{copied}");
    assert_eq!(bundle["account"]["user_name"], "ada", "{copied}");
    let credential_kinds: Vec<String> = bundle["credentials"]
        .as_array()
        .expect("credentials")
        .iter()
        .map(|held| held["kind"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(
        credential_kinds.contains(&"password".to_owned()),
        "{copied}"
    );
    assert!(
        !bundle["sessions"].as_array().expect("sessions").is_empty(),
        "{copied}"
    );
    assert_eq!(
        bundle["consents"][0]["client_id"],
        support::CONFIDENTIAL,
        "{copied}"
    );
    // The whole answer, byte for byte: no hash, no secret, ever.
    let whole = copied.to_string();
    assert!(
        !whole.contains("argon2") && !whole.contains("secret"),
        "a secret rode the copy: {whole}"
    );

    // The copy rode that one answer; the register keeps only the fact.
    let (status, read_back) =
        fetched(&plane, Method::GET, &format!("{base}/{access_id}"), &bearer).await;
    assert_eq!(status, StatusCode::OK, "{read_back}");
    assert!(read_back.get("bundle").is_none(), "{read_back}");
    assert!(
        read_back["outcome"]
            .as_str()
            .unwrap_or_default()
            .contains("handed over"),
        "{read_back}"
    );

    // Portability draws only what the person provided.
    let (status, carried, _) = walk("portability").await;
    assert_eq!(status, StatusCode::OK, "{carried}");
    assert_eq!(
        carried["bundle"]["account"]["user_name"], "ada",
        "{carried}"
    );
    assert!(
        carried["bundle"].get("sessions").is_none()
            && carried["bundle"].get("credentials").is_none(),
        "the realm's own records rode the portable copy: {carried}"
    );

    // Every kind executes now; an empty rectification still refuses in words.
    let (status, told, _) = walk("rectification").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .unwrap_or_default()
            .contains("names what to correct"),
        "{told}"
    );
}

/// The last two kinds become true. A rectification moves exactly the fields
/// the subject named, through the same user update every door uses, and the
/// register records the names of what moved and nothing of what it moved
/// to; a corrected address stops being a proven one. An objection stops
/// what this server can stop per person: the standing consents, one
/// client's or all of them, and says plainly when nothing stood.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_rectification_moves_named_fields_and_an_objection_withdraws_consents() {
    let plane = Plane::with_actions(&[AdminAction::DsarRead, AdminAction::DsarWrite]).await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/subject-requests");
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::consents::keep(
            &transaction,
            support::SUBJECT,
            support::CONFIDENTIAL,
            &["openid".to_owned()],
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }
    let opened = |kind: &'static str| {
        let plane = &plane;
        let bearer = &bearer;
        let base = &base;
        async move {
            let (status, told) = written(
                plane,
                Method::POST,
                base,
                bearer,
                serde_json::json!({
                    "subject_identifier": "ada",
                    "kind": kind,
                    "jurisdiction": "eu",
                }),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{told}");
            let id = told["request_id"].as_str().expect("an id").to_owned();
            written(
                plane,
                Method::POST,
                &format!("{base}/{id}/verify"),
                bearer,
                serde_json::json!({}),
            )
            .await;
            id
        }
    };

    // Naming nothing to correct is refused before anything runs.
    let rectify = opened("rectification").await;
    let (status, told) = written(
        &plane,
        Method::POST,
        &format!("{base}/{rectify}/fulfil"),
        &bearer,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .unwrap_or_default()
            .contains("names what to correct"),
        "{told}"
    );

    // The named fields move; their values stay out of the register.
    let (status, done) = written(
        &plane,
        Method::POST,
        &format!("{base}/{rectify}/fulfil"),
        &bearer,
        serde_json::json!({
            "email": "ada@corrected.example",
            "family_name": "Byron",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    let outcome = done["outcome"].as_str().unwrap_or_default();
    assert!(
        outcome.contains("email") && outcome.contains("family_name"),
        "{done}"
    );
    assert!(
        !outcome.contains("corrected.example") && !outcome.contains("Byron"),
        "a corrected value rode the register: {done}"
    );
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let person = store::providers::users::load(&transaction, support::SUBJECT)
            .await
            .unwrap()
            .expect("ada stands");
        assert_eq!(person.email, "ada@corrected.example");
        assert_eq!(
            person.email_verified,
            Some(false),
            "a corrected address stayed proven"
        );
    }

    // The named client's consent goes; asked again, nothing stands.
    let object = opened("objection").await;
    let (status, done) = written(
        &plane,
        Method::POST,
        &format!("{base}/{object}/fulfil"),
        &bearer,
        serde_json::json!({ "client_id": support::CONFIDENTIAL }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(
        done["outcome"]
            .as_str()
            .unwrap_or_default()
            .contains("was withdrawn"),
        "{done}"
    );
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let standing = store::providers::consents::of_user(&transaction, support::SUBJECT)
            .await
            .unwrap();
        assert!(standing.is_empty(), "the consent survived the objection");
    }
    let again = opened("objection").await;
    let (status, done) = written(
        &plane,
        Method::POST,
        &format!("{base}/{again}/fulfil"),
        &bearer,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(
        done["outcome"]
            .as_str()
            .unwrap_or_default()
            .contains("nothing to stop"),
        "{done}"
    );
}

/// The breach register keeps what a regulator asks for: the clock hangs on
/// discovery and only where a law actually fixes one, a filing is recorded
/// with who filed and with whom or not at all, deciding not to notify is
/// itself a recorded decision, and the draft a portal is filled from is
/// never ready as drawn: it says what a person still owes it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_breach_runs_its_clock_and_its_paper_trail() {
    let plane = Plane::with_actions(&[AdminAction::BreachRead, AdminAction::BreachWrite]).await;
    let bearer = plane.token(&claims());
    let base = format!("/admin/realms/{REALM}/breaches");

    // A breach discovered before it happened is refused.
    let (status, told) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "description": "a laptop went missing",
            "severity": "high",
            "jurisdiction": "eu",
            "occurred_at": 9_999_999_999i64,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .unwrap_or_default()
            .contains("before it happened"),
        "{told}"
    );

    // The EU clock: seventy-two hours from discovery, settled at discovery.
    let (status, found) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "description": "a laptop went missing",
            "data_categories": ["emails"],
            "severity": "high",
            "jurisdiction": "eu",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{found}");
    assert_eq!(found["status"], "discovered", "{found}");
    assert_eq!(
        found["notify_by"].as_i64(),
        found["discovered_at"].as_i64().map(|at| at + 72 * 3_600),
        "{found}"
    );
    let eu_breach = found["breach_id"].as_str().expect("an id").to_owned();

    // A jurisdiction whose law fixes no window gets no invented one, and its
    // draft says to confirm the deadline rather than omitting the question.
    let (status, found) = written(
        &plane,
        Method::POST,
        &base,
        &bearer,
        serde_json::json!({
            "description": "a misdirected export",
            "severity": "medium",
            "jurisdiction": "ke",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{found}");
    assert!(found["notify_by"].is_null(), "{found}");
    let ke_breach = found["breach_id"].as_str().expect("an id").to_owned();

    // Closing straight from discovery is not a path.
    let (status, told) = written(
        &plane,
        Method::POST,
        &format!("{base}/{eu_breach}/close"),
        &bearer,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // Assessed, then a filing that names nobody is refused whole.
    let (status, told) = written(
        &plane,
        Method::POST,
        &format!("{base}/{eu_breach}/assess"),
        &bearer,
        serde_json::json!({ "severity": "critical", "subjects_affected": 1200 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "assessed", "{told}");
    let (status, told) = written(
        &plane,
        Method::POST,
        &format!("{base}/{eu_breach}/filing"),
        &bearer,
        serde_json::json!({ "notified_to": "CNIL" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .unwrap_or_default()
            .contains("who filed it and with whom"),
        "{told}"
    );

    // The draft before filing: the narrative fields are a person's account,
    // so they start empty and are named as outstanding.
    let (status, draft) = fetched(
        &plane,
        Method::GET,
        &format!("{base}/{eu_breach}/notification-draft"),
        &bearer,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{draft}");
    assert_eq!(draft["approximate_subjects_affected"], 1200, "{draft}");
    assert_eq!(draft["subject_notice_likely_required"], true, "{draft}");
    let outstanding = draft["outstanding"].to_string();
    assert!(
        outstanding.contains("likely_consequences") && outstanding.contains("measures_taken"),
        "{draft}"
    );

    let (status, told) = written(
        &plane,
        Method::POST,
        &format!("{base}/{eu_breach}/filing"),
        &bearer,
        serde_json::json!({ "notified_to": "CNIL", "filed_by": "ada" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "notified", "{told}");
    assert_eq!(told["filed_by"], "ada", "{told}");
    let (status, told) = written(
        &plane,
        Method::POST,
        &format!("{base}/{eu_breach}/close"),
        &bearer,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "closed", "{told}");

    // The other lawful exit: assessed as under the threshold, recorded as a
    // decision rather than left to stop moving, and its draft still warns
    // that no window was read for this law.
    let (_, _) = written(
        &plane,
        Method::POST,
        &format!("{base}/{ke_breach}/assess"),
        &bearer,
        serde_json::json!({ "severity": "low" }),
    )
    .await;
    let (status, told) = written(
        &plane,
        Method::POST,
        &format!("{base}/{ke_breach}/not-notifiable"),
        &bearer,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "not-notifiable", "{told}");
    let (_, draft) = fetched(
        &plane,
        Method::GET,
        &format!("{base}/{ke_breach}/notification-draft"),
        &bearer,
    )
    .await;
    assert!(
        draft["outstanding"]
            .to_string()
            .contains("no window was read"),
        "{draft}"
    );
}

/// The evidence pack accounts for a period with the chain leading, because
/// the chain is the reason to believe the sections under it. Its verdict is
/// read before its contents, what falls outside the period stays out, an
/// empty register reads as a clean period and not as a failure, and the
/// retention in force rides along in the controller's own words.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_evidence_pack_accounts_for_its_period_with_the_chain_leading() {
    let plane = Plane::with_actions(&[
        AdminAction::EvidenceRead,
        AdminAction::DsarRead,
        AdminAction::DsarWrite,
        AdminAction::BreachRead,
        AdminAction::BreachWrite,
    ])
    .await;
    let bearer = plane.token(&claims());
    let now = chrono::Utc::now().timestamp();

    // One of each register inside the period, and a consent stamped before
    // it, which must stay out.
    let (_, lodged) = written(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/subject-requests"),
        &bearer,
        serde_json::json!({
            "subject_identifier": "ada",
            "kind": "access",
            "jurisdiction": "eu",
        }),
    )
    .await;
    assert_eq!(lodged["stage"], "received", "{lodged}");
    let (_, found) = written(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/breaches"),
        &bearer,
        serde_json::json!({
            "description": "a misdirected export",
            "severity": "low",
            "jurisdiction": "eu",
        }),
    )
    .await;
    assert_eq!(found["status"], "discovered", "{found}");
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::consents::keep(
            &transaction,
            support::SUBJECT,
            support::CONFIDENTIAL,
            &["openid".to_owned()],
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        transaction
            .execute(
                "UPDATE user_consents SET granted_at = to_timestamp($1::bigint) WHERE user_id = $2",
                &[&(now - 10_000), &support::SUBJECT],
            )
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }

    let (status, pack) = fetched(
        &plane,
        Method::GET,
        &format!(
            "/admin/realms/{REALM}/evidence-pack?from={}&to={}",
            now - 300,
            now + 300
        ),
        &bearer,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pack}");
    assert_eq!(pack["chain"]["result"], "verified", "{pack}");
    assert_eq!(pack["verdict"], "sound", "{pack}");
    assert_eq!(pack["gaps"], serde_json::json!([]), "{pack}");
    assert_eq!(
        pack["dsar_requests"]["items"].as_array().map(Vec::len),
        Some(1),
        "{pack}"
    );
    assert_eq!(
        pack["breaches"]["items"].as_array().map(Vec::len),
        Some(1),
        "{pack}"
    );
    // The consent granted before the period stays out, and the section still
    // reads as a complete account of the period.
    assert_eq!(
        pack["consent_receipts"]["items"].as_array().map(Vec::len),
        Some(0),
        "{pack}"
    );
    assert_eq!(
        pack["consent_receipts"]["completeness"], "complete",
        "{pack}"
    );
    assert!(
        pack["registrations"]["items"]
            .as_array()
            .map(Vec::len)
            .unwrap_or_default()
            >= 1,
        "the accounts the plant registered are in the period: {pack}"
    );
    let retention = pack["retention"].to_string();
    assert!(retention.contains("sign_in_log"), "{pack}");

    // A period that runs backwards is refused before anything is drawn.
    let (status, told) = fetched(
        &plane,
        Method::GET,
        &format!(
            "/admin/realms/{REALM}/evidence-pack?from={}&to={}",
            now + 300,
            now - 300
        ),
        &bearer,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // A chain with a tampered entry settles the verdict, whatever else
    // holds. The app role cannot write history, which is its own guarantee,
    // so the tampering has to be done as the table's owner.
    {
        let (owner, connection) = support::owner()
            .connect(tokio_postgres::NoTls)
            .await
            .expect("the owner");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        owner
            .execute(
                "UPDATE audit_events SET envelope = envelope || '{\"tampered\": true}'::jsonb \
                 WHERE seq = (SELECT min(seq) FROM audit_events)",
                &[],
            )
            .await
            .unwrap();
    }
    let (status, pack) = fetched(
        &plane,
        Method::GET,
        &format!(
            "/admin/realms/{REALM}/evidence-pack?from={}&to={}",
            now - 300,
            now + 300
        ),
        &bearer,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pack}");
    assert_eq!(pack["chain"]["result"], "broken", "{pack}");
    assert_eq!(pack["verdict"], "chain-unverified", "{pack}");
    assert!(pack["chain"]["at"].is_i64(), "{pack}");
}
