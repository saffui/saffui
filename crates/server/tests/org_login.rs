mod support;

use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use data_encoding::BASE64;
use models::entities::authz::AdminAction;
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;
use support::{Plane, cookie_value, urlencode};

const REDIRECT: &str = "https://app.example/callback";
const REALM: &str = support::REALM;

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
        egress: config::serving::Egress::Outward,
    }
}

async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asking = test::TestRequest::default()
        .method(method)
        .uri(path)
        .insert_header(("authorization", format!("Bearer {bearer}")));
    if let Some(body) = body {
        asking = asking.set_json(body);
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// Create an organization over the plane and say its id.
async fn born_org(plane: &Plane, bearer: &str, name: &str, display_name: &str) -> String {
    let (status, born) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/organizations"),
        bearer,
        Some(serde_json::json!({
            "name": name,
            "display_name": display_name,
            "description": "",
            "enabled": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    born["org_id"].as_str().expect("an identity").to_owned()
}

/// Open a login at `/auth`, with the organization the query names, and hand
/// back the login cookie.
async fn opened(plane: &Plane, organization: Option<&str>) -> String {
    let pinned = organization
        .map(|slug| format!("&organization={}", urlencode(slug)))
        .unwrap_or_default();
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope=openid+profile&state=s{pinned}",
                support::CONFIDENTIAL,
                urlencode(REDIRECT),
            ))
            .to_request(),
    )
    .await;
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login")
}

/// Answer the login round, and hand back what was told plus the cookies set.
async fn answered(plane: &Plane, binding: &str) -> (Value, Vec<String>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/login"))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .set_json(
                serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
            )
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    (test::read_body_json(response).await, cookies)
}

/// Sign in with the organization the query names, and say where the browser
/// was sent.
async fn signed_in(plane: &Plane, organization: Option<&str>) -> String {
    let binding = opened(plane, organization).await;
    let (told, _) = answered(plane, &binding).await;
    told["redirect_to"]
        .as_str()
        .unwrap_or_else(|| panic!("nowhere to go: {told}"))
        .to_owned()
}

fn code_of(landing: &str) -> String {
    landing
        .split_once("code=")
        .expect("a code")
        .1
        .split('&')
        .next()
        .expect("a code")
        .to_owned()
}

async fn at_token(plane: &Plane, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let request = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
        .insert_header(("authorization", format!("Basic {encoded}")))
        .set_form(form)
        .to_request();
    let response = test::call_service(&app, request).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

async fn redeemed(plane: &Plane, landing: &str) -> Value {
    let code = code_of(landing);
    let (status, granted) = at_token(
        plane,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{granted}");
    granted
}

async fn renewed(plane: &Plane, refresh_token: &str) -> (StatusCode, Value) {
    at_token(
        plane,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ],
    )
    .await
}

/// The whole life of an organization-scoped login: the pin resolves against
/// the user, the claims ride every token and the userinfo answer, a renewal
/// re-verifies the membership and a rotation does not shed what the chain
/// attests, and a member who left is quietly realm-level again.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_organization_login_carries_its_claims_for_as_long_as_the_membership() {
    let plane = Plane::with_actions(&[AdminAction::OrgRead, AdminAction::OrgWrite]).await;
    let bearer = plane.token(&support::claims());
    let acme = born_org(&plane, &bearer, "acme", "Acme Corp").await;
    plane.add_org_member(&acme, support::SUBJECT).await;

    let granted = redeemed(&plane, &signed_in(&plane, Some("acme")).await).await;
    for named in ["access_token", "id_token", "refresh_token"] {
        let claims = plane.claims_of(granted[named].as_str().expect(named)).await;
        assert_eq!(claims["org_id"], acme.as_str(), "{named}: {claims}");
        assert_eq!(claims["org_name"], "Acme Corp", "{named}: {claims}");
    }

    // The userinfo answer describes the token's confinement.
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/userinfo"))
            .insert_header((
                "authorization",
                format!("Bearer {}", granted["access_token"].as_str().unwrap()),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let told: Value = test::read_body_json(response).await;
    assert_eq!(told["org_id"], acme.as_str(), "{told}");
    assert_eq!(told["org_name"], "Acme Corp", "{told}");

    // Renewed while a member: kept. Renewed again, on the rotated token: still
    // kept, which is the successor carrying what its predecessor did.
    let (status, first) = renewed(&plane, granted["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(
        plane
            .claims_of(first["access_token"].as_str().unwrap())
            .await["org_id"],
        acme.as_str()
    );
    let (status, second) = renewed(&plane, first["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let identity = plane
        .claims_of(second["id_token"].as_str().expect("an id token"))
        .await;
    assert_eq!(identity["org_id"], acme.as_str(), "{identity}");
    assert!(identity["auth_time"].is_i64(), "the carry lost auth_time");

    // A member who left renews into a realm-level token: the stale claim is
    // dropped, never carried, and the renewal itself still succeeds.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!(
            "/admin/realms/{REALM}/organizations/{acme}/members/{}",
            support::SUBJECT
        ),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, plain) = renewed(&plane, second["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{plain}");
    for named in ["access_token", "id_token", "refresh_token"] {
        let claims = plane.claims_of(plain[named].as_str().expect(named)).await;
        assert!(claims.get("org_id").is_none(), "{named}: {claims}");
        assert!(claims.get("org_name").is_none(), "{named}: {claims}");
    }
}

/// A pin the user does not hold, or that names nothing, is the client's
/// refusal: `access_denied` to the redirect, one answer for every reason, and
/// the same at the door a live session walks through.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_pin_the_user_does_not_hold_is_sent_back_refused() {
    let plane = Plane::with_actions(&[AdminAction::OrgRead, AdminAction::OrgWrite]).await;
    let bearer = plane.token(&support::claims());
    let acme = born_org(&plane, &bearer, "acme", "Acme Corp").await;
    born_org(&plane, &bearer, "closed", "Closed Doors").await;
    plane.add_org_member(&acme, support::SUBJECT).await;

    for pinned in ["closed", "nowhere"] {
        let binding = opened(&plane, Some(pinned)).await;
        let (told, _) = answered(&plane, &binding).await;
        assert_eq!(told["status"], "sent_back", "{pinned}: {told}");
        let landing = told["redirect_to"].as_str().expect("a landing");
        assert!(landing.contains("error=access_denied"), "{landing}");
        assert!(landing.contains("state=s"), "{landing}");
    }

    // The same request through a live session: the resolution guards the
    // single-sign-on door too.
    let binding = opened(&plane, Some("acme")).await;
    let (told, cookies) = answered(&plane, &binding).await;
    assert_eq!(told["status"], "admitted", "{told}");
    let sso = cookie_value(
        &cookies,
        server::api::rest::endpoints::protocol::binding::SSO_SESSION,
    )
    .expect("a session");
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope=openid&state=s2&organization=closed",
                support::CONFIDENTIAL,
                urlencode(REDIRECT),
            ))
            .insert_header((
                "cookie",
                format!(
                    "{}={sso}",
                    server::api::rest::endpoints::protocol::binding::SSO_SESSION
                ),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let landing = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .expect("a landing");
    assert!(landing.contains("error=access_denied"), "{landing}");
}

/// Nothing pinned: no membership is a realm login, one selects itself, and
/// several speak only through the user's verified mail domain.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn with_nothing_pinned_the_memberships_decide() {
    let plane = Plane::with_actions(&[AdminAction::OrgRead, AdminAction::OrgWrite]).await;
    let bearer = plane.token(&support::claims());

    // No membership: a realm-level login, no organization claims.
    let granted = redeemed(&plane, &signed_in(&plane, None).await).await;
    let claims = plane
        .claims_of(granted["access_token"].as_str().unwrap())
        .await;
    assert!(claims.get("org_id").is_none(), "{claims}");

    // One membership: it selects itself.
    let acme = born_org(&plane, &bearer, "acme", "Acme Corp").await;
    plane.add_org_member(&acme, support::SUBJECT).await;
    let granted = redeemed(&plane, &signed_in(&plane, None).await).await;
    let claims = plane
        .claims_of(granted["access_token"].as_str().unwrap())
        .await;
    assert_eq!(claims["org_id"], acme.as_str(), "{claims}");

    // Two memberships and no voice: refused, because guessing would hand the
    // client a confinement nobody chose.
    let beta = born_org(&plane, &bearer, "beta", "Beta LLC").await;
    plane.add_org_member(&beta, support::SUBJECT).await;
    let binding = opened(&plane, None).await;
    let (told, _) = answered(&plane, &binding).await;
    assert_eq!(told["status"], "sent_back", "{told}");
    assert!(
        told["redirect_to"]
            .as_str()
            .expect("a landing")
            .contains("error=access_denied"),
        "{told}"
    );

    // The user's verified mail domain is a voice, and it may only name an
    // organization they belong to.
    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::organizations::claim_domain(
            &transaction,
            &acme,
            "example.test",
            "a-challenge",
        )
        .await
        .expect("the domain claimed");
        store::providers::organizations::verify_domain(&transaction, "example.test")
            .await
            .expect("the domain proven");
        transaction.commit().await.expect("the domain kept");
    }
    let granted = redeemed(&plane, &signed_in(&plane, None).await).await;
    let claims = plane
        .claims_of(granted["access_token"].as_str().unwrap())
        .await;
    assert_eq!(claims["org_id"], acme.as_str(), "{claims}");
    assert_eq!(claims["org_name"], "Acme Corp", "{claims}");
}
