#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;

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
        ceiling: support::ceiling(),
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

async fn opened_login(plane: &Plane, extra_query: &str) -> String {
    let pinned = extra_query;
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
    let plain = stylesheet_holding(&plane, &opened_login(&plane, "").await).await;
    assert!(plain.contains("#12305e"), "{plain}");
    assert!(!plain.contains("#a0325a"));

    // Named: the organization's overrides ride after the realm's, so they win.
    let dressed =
        stylesheet_holding(&plane, &opened_login(&plane, "&organization=acme").await).await;
    let realm_at = dressed.find("#12305e").expect("the realm's look");
    let org_at = dressed.find("#a0325a").expect("the organization's look");
    assert!(realm_at < org_at, "the cascade is backwards");
    assert!(dressed.contains("--radius:3px;"), "{dressed}");

    // A name that resolves to nothing dresses nothing, and breaks nothing.
    let fallback =
        stylesheet_holding(&plane, &opened_login(&plane, "&organization=nowhere").await).await;
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
    let bare = stylesheet_holding(&plane, &opened_login(&plane, "&organization=acme").await).await;
    assert!(!bare.contains("#a0325a"));
}

/// `ui_locales` rides the login and outranks the browser's list on the page
/// this login shows; a list naming no spoken tongue leaves the browser's
/// list to answer, and a page fetched outside any login follows the browser.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_client_may_ask_the_page_tongue_for_its_login() {
    let plane = Plane::with_actions(&[]).await;

    let binding = opened_login(&plane, "&ui_locales=fr-CA%20fr").await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let asked = |cookie: Option<String>, accept: &'static str| {
        let mut request = test::TestRequest::get()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/login"))
            .insert_header(("accept-language", accept));
        if let Some(cookie) = cookie {
            request = request.insert_header(("cookie", cookie));
        }
        request.to_request()
    };

    let response = test::call_service(
        &app,
        asked(
            Some(format!("{}={binding}", support::AUTH_SESSION_COOKIE)),
            "en-US",
        ),
    )
    .await;
    let page = String::from_utf8(test::read_body(response).await.to_vec()).expect("a page");
    assert!(page.contains("<html lang=\"fr\">"), "the client's say lost");

    // The same login, no cookie on the fetch: the browser's list answers.
    let response = test::call_service(&app, asked(None, "en-US")).await;
    let page = String::from_utf8(test::read_body(response).await.to_vec()).expect("a page");
    assert!(page.contains("<html lang=\"en\">"), "{page:.100}");

    // A list naming nothing spoken: the browser's list answers too.
    let binding = opened_login(&plane, "&ui_locales=de%20ja").await;
    let response = test::call_service(
        &app,
        asked(
            Some(format!("{}={binding}", support::AUTH_SESSION_COOKIE)),
            "fr-FR",
        ),
    )
    .await;
    let page = String::from_utf8(test::read_body(response).await.to_vec()).expect("a page");
    assert!(page.contains("<html lang=\"fr\">"), "the fallback lost");
}

/// Point the planted client's home page somewhere, under a display name.
async fn reshape_home(plane: &Plane, home: Option<&str>, named: &str) {
    let mut connection = plane.connection().await;
    let within = store::tenancy::TenantContext::new(support::TENANT, support::REALM);
    let transaction = plane.scoped(&mut connection, &within).await;
    let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
        .await
        .expect("the clients table")
        .expect("a planted client");
    client.client_uri = home.map(str::to_owned);
    client.display_name = named.to_owned();
    store::providers::clients::update(&transaction, &client)
        .await
        .expect("the clients table");
    transaction.commit().await.expect("the client kept");
}

/// The page, as fetched for the login this binding names, or for none.
async fn page_for(plane: &Plane, binding: Option<&str>) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut request =
        test::TestRequest::get().uri(&format!("/realms/{REALM}/protocol/openid-connect/login"));
    if let Some(binding) = binding {
        request = request.insert_header((
            "cookie",
            format!("{}={binding}", support::AUTH_SESSION_COOKIE),
        ));
    }
    let response = test::call_service(&app, request.to_request()).await;
    String::from_utf8(test::read_body(response).await.to_vec()).expect("a page")
}

fn doors_on(page: &str) -> Vec<String> {
    let (_, after) = page
        .split_once("data-doors=\"")
        .expect("a body that says its doors");
    let (doors, _) = after.split_once('"').expect("a closed attribute");
    doors.split_whitespace().map(str::to_owned).collect()
}

/// The page served for a live login carries the way back to the application
/// that started it, because once the login dies its row is swept and the
/// refusal can no longer name one. Written escaped, and only to an address
/// that can be nothing but a page.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_page_carries_the_way_back_to_the_application_its_login_came_from() {
    let plane = Plane::with_actions(&[]).await;
    reshape_home(&plane, Some("https://app.example/home"), "Billing <Ops>").await;

    let binding = opened_login(&plane, "").await;
    let page = page_for(&plane, Some(&binding)).await;
    assert!(
        doors_on(&page).contains(&"back".to_owned()),
        "the script is never told there is a way back: {:?}",
        doors_on(&page)
    );
    assert!(
        page.contains(r#"<a id="back" href="https://app.example/home">"#),
        "the page does not link to the application's home"
    );
    assert!(
        page.contains(r#"<span id="back-name">Billing &lt;Ops&gt;</span>"#),
        "the application's name reached the page unescaped"
    );

    // Outside any login there is no application to go back to.
    let page = page_for(&plane, None).await;
    assert!(!doors_on(&page).contains(&"back".to_owned()));
    assert!(
        page.contains(r#"<a id="back" href="">"#),
        "an anchor was aimed"
    );

    // A home page that would run as script in this origin is not written.
    reshape_home(&plane, Some("javascript:alert(document.cookie)"), "Billing").await;
    let binding = opened_login(&plane, "").await;
    let page = page_for(&plane, Some(&binding)).await;
    assert!(!doors_on(&page).contains(&"back".to_owned()));
    assert!(
        !page.contains("javascript:"),
        "an address that runs as script reached the sign-in page"
    );
}
