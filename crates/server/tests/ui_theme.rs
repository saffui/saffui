mod support;

use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;
use support::Plane;

const REALM: &str = support::REALM;

fn mounted(plane: &Plane) -> server::api::config::Plane {
    server::api::config::Plane {
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

async fn stylesheet(plane: &Plane) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/login.css"
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    String::from_utf8(test::read_body(response).await.to_vec()).expect("css")
}

/// The realm dresses its pages by tokens and nothing else: the sheet wears
/// the overrides after its defaults, an unsound value is refused at the
/// door before it can leave a declaration, and undressing restores the
/// default look.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_wears_its_own_tokens() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());

    // Bare: the default sheet, no override block.
    let bare = stylesheet(&plane).await;
    assert!(
        bare.contains("--brand-primary: #18181b"),
        "the default look"
    );
    assert!(!bare.contains("#12305e"));

    // Dressed: the overrides ride after the defaults, both halves.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/theme"),
        &bearer,
        Some(json!({
            "light": { "brand-primary": "#12305e", "radius": "0px" },
            "dark": { "brand-primary": "#9dbdf0" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let dressed = stylesheet(&plane).await;
    // The store hands the object back in its own key order, so each
    // declaration is asserted alone.
    assert!(dressed.contains("--brand-primary:#12305e;"), "{dressed}");
    assert!(dressed.contains("--radius:0px;"), "{dressed}");
    assert!(dressed.contains("--brand-primary:#9dbdf0;"), "{dressed}");
    let (_, held) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/theme"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(held["light"]["brand-primary"], "#12305e", "{held}");

    // The door is the boundary: a value that could leave its declaration,
    // and a token the pages do not read, are refused whole.
    for refused in [
        json!({ "light": { "brand-primary": "#111;}body{background:red" } }),
        json!({ "light": { "card-shadow": "url(https://evil.example/x)" } }),
        json!({ "light": { "made-up": "#fff" } }),
    ] {
        let (status, _) = asked(
            &plane,
            Method::PUT,
            &format!("/admin/realms/{REALM}/theme"),
            &bearer,
            Some(refused),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    // Refused means untouched: the realm still wears the last good theme.
    assert!(stylesheet(&plane).await.contains("#12305e"));

    // Undressed: back to the default.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/theme"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!stylesheet(&plane).await.contains("#12305e"));
}

async fn opened_login(plane: &Plane, organization: Option<&str>) -> String {
    let pinned = organization
        .map(|slug| format!("&organization={slug}"))
        .unwrap_or_default();
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/auth?client_id={}\
                 &redirect_uri=https%3A%2F%2Fapp.example%2Fcallback\
                 &response_type=code&scope=openid&state=s{pinned}",
                support::CONFIDENTIAL,
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
    support::cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login")
}

async fn stylesheet_holding(plane: &Plane, binding: &str) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/login.css"
            ))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    String::from_utf8(test::read_body(response).await.to_vec()).expect("css")
}

/// An organization dresses the pages its sign-ins land on, over the realm's
/// look: the sheet wears default, then realm, then organization, the request
/// that named no organization gets the realm's look, a name that resolves to
/// nothing falls back rather than breaking, and the admin door refuses the
/// unsound and the unknown apart.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_organization_dresses_over_the_realm() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmRead,
        AdminAction::RealmWrite,
        AdminAction::OrgRead,
        AdminAction::OrgWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    let (status, born) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/organizations"),
        &bearer,
        Some(json!({
            "name": "acme", "display_name": "Acme Corp",
            "description": "", "enabled": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let acme = born["org_id"].as_str().expect("an identity").to_owned();

    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/theme"),
        &bearer,
        Some(json!({ "light": { "brand-primary": "#12305e" } })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/organizations/{acme}/theme"),
        &bearer,
        Some(json!({ "light": { "brand-primary": "#a0325a", "radius": "3px" } })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    // The admin door: unknown organization and unsound value are told apart.
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/organizations/nowhere/theme"),
        &bearer,
        Some(json!({ "light": { "brand-primary": "#111111" } })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/organizations/{acme}/theme"),
        &bearer,
        Some(json!({ "light": { "card-shadow": "url(https://evil.example/x)" } })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // No organization named: the realm's look and nothing more.
    let plain = stylesheet_holding(&plane, &opened_login(&plane, None).await).await;
    assert!(plain.contains("#12305e"), "{plain}");
    assert!(!plain.contains("#a0325a"));

    // Named: the organization's overrides ride after the realm's, so they win.
    let dressed = stylesheet_holding(&plane, &opened_login(&plane, Some("acme")).await).await;
    let realm_at = dressed.find("#12305e").expect("the realm's look");
    let org_at = dressed.find("#a0325a").expect("the organization's look");
    assert!(realm_at < org_at, "the cascade is backwards");
    assert!(dressed.contains("--radius:3px;"), "{dressed}");

    // A name that resolves to nothing dresses nothing, and breaks nothing.
    let fallback = stylesheet_holding(&plane, &opened_login(&plane, Some("nowhere")).await).await;
    assert!(fallback.contains("#12305e"));
    assert!(!fallback.contains("#a0325a"));

    // Undressed: back to the realm's look.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/organizations/{acme}/theme"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let bare = stylesheet_holding(&plane, &opened_login(&plane, Some("acme")).await).await;
    assert!(!bare.contains("#a0325a"));
}
