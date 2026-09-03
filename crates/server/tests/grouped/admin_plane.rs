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
