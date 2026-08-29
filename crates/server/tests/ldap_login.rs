mod support;

use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};
use support::Plane;

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
    let told = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, told)
}

async fn opened_login(plane: &Plane) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope=openid&state=s&nonce=n-local",
                support::CONFIDENTIAL,
                support::urlencode(support::REDIRECT),
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
    support::cookie_value(&cookies, support::AUTH_SESSION_COOKIE)
        .expect("a login")
        .to_owned()
}

/// Answer the open login with a name and a password, as JSON.
async fn answered(plane: &Plane, cookie: &str, username: &str, password: &str) -> StatusCode {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/login"))
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .set_json(json!({ "username": username, "password": password }))
            .to_request(),
    )
    .await;
    response.status()
}

/// The address of the test directory, when one is up. Absent, the whole
/// journey is skipped rather than failed: the directory is infrastructure,
/// not an assertion.
fn directory_url() -> Option<String> {
    std::env::var("SAFFUI_TEST_LDAP")
        .ok()
        .filter(|url| !url.is_empty())
}

/// A person the directory owns signs in here: found over LDAP on first
/// mention, mirrored as a shadow row the flow runs against, verified by the
/// directory's own bind, and refused when the directory refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG) and a directory (SAFFUI_TEST_LDAP)"]
async fn a_directory_person_signs_in_and_leaves_a_shadow() {
    let Some(url) = directory_url() else {
        eprintln!("SAFFUI_TEST_LDAP unset; the journey has no directory to cross");
        return;
    };
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/federation"),
        &bearer,
        Some(json!({
            "configs": {
                "url": { "Str": url },
                "bind_dn": { "Str": "cn=admin,dc=example,dc=org" },
                "bind_password": { "Str": "adminpw" },
                "users_dn": { "Str": "ou=users,dc=example,dc=org" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert!(
        told["configs"].get("bind_password").is_none()
            && told["configs"].get("bind_password_sealed").is_none(),
        "a secret rode the answer: {told}"
    );

    // Nobody local answers to the name yet.
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        assert!(
            store::providers::users::load_by_name(&transaction, "fedora")
                .await
                .unwrap()
                .is_none()
        );
    }

    // The wrong password is the directory's refusal, spoken here.
    let cookie = opened_login(&plane).await;
    assert_eq!(
        answered(&plane, &cookie, "fedora", "not-wilderness").await,
        StatusCode::UNAUTHORIZED
    );

    // The right one signs in, and the flow ran against a freshly mirrored
    // shadow row the directory's answer shaped.
    let cookie = opened_login(&plane).await;
    assert_eq!(
        answered(&plane, &cookie, "fedora", "wilderness").await,
        StatusCode::OK,
        "the directory's person was not admitted"
    );
    let shadowed = {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::users::load_by_name(&transaction, "fedora")
            .await
            .unwrap()
            .expect("a shadow row")
    };
    assert_eq!(
        shadowed.user_storage,
        Some(models::entities::user::UserStorage::Ldap)
    );
    assert_eq!(
        shadowed
            .attributes
            .as_ref()
            .and_then(|held| held.get(models::entities::user::profile::LAST_NAME))
            .and_then(models::entities::attributes::AttributeValue::as_str),
        Some("Bar1"),
        "the directory's surname did not reach the shadow: {:?}",
        shadowed.attributes
    );
    assert_eq!(
        shadowed.email_verified,
        Some(false),
        "an asserted address was taken as verified"
    );

    // A second sign-in finds the mirror rather than making another.
    let cookie = opened_login(&plane).await;
    assert_eq!(
        answered(&plane, &cookie, "fedora", "wilderness").await,
        StatusCode::OK
    );

    // The directory gone, the shadow cannot vouch for a password: nothing
    // local ever held one.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/federation"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let cookie = opened_login(&plane).await;
    assert_eq!(
        answered(&plane, &cookie, "fedora", "wilderness").await,
        StatusCode::UNAUTHORIZED,
        "a shadow row vouched for a password after the realm stopped federating"
    );
}

/// The directory row is read at the door, and secrets never ride answers.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_directory_row_is_read_at_the_door() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/federation");

    for (body, holds) in [
        (
            json!({ "configs": { "bind_dn": { "Str": "cn=admin" } } }),
            "url",
        ),
        (
            json!({ "configs": { "url": { "Str": "http://not-ldap" },
                                 "bind_dn": { "Str": "cn=admin" },
                                 "users_dn": { "Str": "ou=users" } } }),
            "ldap://",
        ),
        (
            json!({ "configs": { "url": { "Str": "ldap://x" },
                                 "bind_dn": { "Str": "cn=admin" },
                                 "users_dn": { "Str": "ou=users" },
                                 "user_filter": { "Str": "(uid=bob)" } } }),
            "{username}",
        ),
        (
            json!({ "configs": { "url": { "Str": "ldap://x" },
                                 "bind_dn": { "Str": "cn=admin" },
                                 "users_dn": { "Str": "ou=users" },
                                 "search_base": { "Str": "typo" } } }),
            "no directory reads",
        ),
    ] {
        let (status, told) = asked(&plane, Method::PUT, &base, &bearer, Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert!(
            told["message"]
                .as_str()
                .is_some_and(|why| why.contains(holds)),
            "the refusal does not say {holds}: {told}"
        );
    }

    let (status, _) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a refused write left a row");

    let (status, kept) = asked(
        &plane,
        Method::PUT,
        &base,
        &bearer,
        Some(json!({ "configs": {
            "url": { "Str": "ldap://directory.example:1389" },
            "bind_dn": { "Str": "cn=admin,dc=example,dc=org" },
            "bind_password": { "Str": "adminpw" },
            "users_dn": { "Str": "ou=users,dc=example,dc=org" },
        } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{kept}");
    assert!(kept["configs"].get("bind_password").is_none());
    assert!(kept["configs"].get("bind_password_sealed").is_none());

    // Rewriting bumps the one row rather than adding a second.
    let (status, kept) = asked(
        &plane,
        Method::PUT,
        &base,
        &bearer,
        Some(json!({ "enabled": false, "configs": {
            "url": { "Str": "ldap://directory.example:1389" },
            "bind_dn": { "Str": "cn=admin,dc=example,dc=org" },
            "users_dn": { "Str": "ou=users,dc=example,dc=org" },
        } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{kept}");
    assert!(kept["metadata"]["version"].as_i64().unwrap_or(1) > 1);
    assert_eq!(kept["enabled"], false);

    let (status, _) = asked(&plane, Method::DELETE, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(&plane, Method::DELETE, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
