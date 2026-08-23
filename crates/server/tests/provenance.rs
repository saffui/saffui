//! What a login records about where it came from.

mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use config::proxying::{ProxyHeader, Proxying};
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;
use support::{Plane, claims, cookie_value, urlencode};

const CHROME: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                      (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const REDIRECT: &str = "https://app.example/callback";

fn mounted(plane: &Plane, proxying: Proxying) -> Mounted {
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
        hops: proxying,
        sealing: support::sealing(),
    }
}

/// Open a login and answer it, from `peer`, carrying `headers`.
async fn log_in(plane: &Plane, proxying: Proxying, peer: &str, headers: &[(&str, &str)]) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane, proxying)))).await;

    let mut opening = test::TestRequest::get()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/auth\
             ?client_id={}&response_type=code&redirect_uri={}&scope=openid&state=s",
            support::REALM,
            support::CONFIDENTIAL,
            urlencode(REDIRECT),
        ))
        .peer_addr(peer.parse().expect("a peer"));
    for (named, value) in headers {
        opening = opening.insert_header((*named, *value));
    }
    let opened = test::call_service(&app, opening.to_request()).await;
    assert_eq!(opened.status(), StatusCode::FOUND);
    let cookies: Vec<String> = opened
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let binding = cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login");

    let mut answering = test::TestRequest::post()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/login",
            support::REALM
        ))
        .set_json(serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD
        }))
        .peer_addr(peer.parse().expect("a peer"))
        .insert_header((
            "cookie",
            format!("{}={binding}", support::AUTH_SESSION_COOKIE),
        ));
    for (named, value) in headers {
        answering = answering.insert_header((*named, *value));
    }
    let answered = test::call_service(&app, answering.to_request()).await;
    assert_eq!(answered.status(), StatusCode::OK);
    binding
}

/// What the row holds for the login the fixture's user just opened.
async fn recorded(plane: &Plane) -> (Option<String>, Option<String>) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    let held = store::providers::sessions::load_for_user(&transaction, support::SUBJECT)
        .await
        .expect("the logins")
        .into_iter()
        .next()
        .expect("a login");
    (held.ip_address, held.user_agent)
}

/// With no proxy declared, the address is the one that dialled and the header
/// is not read. A deployment that reads it anyway records whatever the caller
/// wrote, which is the header's whole purpose to whoever forges it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_forged_header_is_not_believed_by_a_server_with_no_proxy() {
    let plane = Plane::with_actions(&[]).await;
    log_in(
        &plane,
        Proxying::none(),
        "10.0.0.9:5000",
        &[
            ("x-forwarded-for", "203.0.113.7"),
            ("forwarded", "for=203.0.113.7"),
            ("user-agent", CHROME),
        ],
    )
    .await;

    let (address, agent) = recorded(&plane).await;
    assert_eq!(
        address.as_deref(),
        Some("10.0.0.9"),
        "a header was believed by a server that has no proxy"
    );
    assert_eq!(agent.as_deref(), Some(CHROME));
}

/// Behind one proxy, the entry that proxy wrote is the last one. What the
/// caller put in front of it is not the caller's address, it is a claim.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn behind_a_proxy_the_claim_in_front_is_not_believed() {
    let plane = Plane::with_actions(&[]).await;
    log_in(
        &plane,
        Proxying::behind(1, ProxyHeader::XForwardedFor),
        "10.0.0.9:5000",
        &[
            ("x-forwarded-for", "198.51.100.1, 203.0.113.7"),
            ("user-agent", CHROME),
        ],
    )
    .await;

    assert_eq!(
        recorded(&plane).await.0.as_deref(),
        Some("203.0.113.7"),
        "the claim the caller put in front was believed"
    );
}

/// The same, through the header RFC 7239 defines.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_forwarded_header_names_the_caller_too() {
    let plane = Plane::with_actions(&[]).await;
    log_in(
        &plane,
        Proxying::behind(1, ProxyHeader::Forwarded),
        "10.0.0.9:5000",
        &[
            (
                "forwarded",
                r#"for=198.51.100.1, for="203.0.113.7:4711";proto=https"#,
            ),
            // The header this deployment did not name, carrying something else
            // entirely. Reading both is how a caller picks which one is read.
            ("x-forwarded-for", "192.0.2.4"),
            ("user-agent", CHROME),
        ],
    )
    .await;

    assert_eq!(
        recorded(&plane).await.0.as_deref(),
        Some("203.0.113.7"),
        "the wrong header was read, or the claim in front was believed"
    );
}

/// The admin plane shows what was recorded, and reads a browser out of it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_admin_plane_shows_a_login_and_reads_its_browser() {
    let plane = Plane::with_actions(&[models::entities::authz::AdminAction::UserRead]).await;
    let bearer = plane.token(&claims());
    log_in(
        &plane,
        Proxying::none(),
        "10.0.0.9:5000",
        &[("user-agent", CHROME)],
    )
    .await;

    let app =
        test::init_service(App::new().configure(register(&mounted(&plane, Proxying::none()))))
            .await;
    let request = test::TestRequest::get()
        .uri(&format!(
            "/admin/realms/{}/users/{}/sessions",
            support::REALM,
            support::SUBJECT
        ))
        .insert_header(("authorization", format!("Bearer {bearer}")))
        .to_request();
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let shown: serde_json::Value = test::read_body_json(response).await;
    let first = &shown[0];
    assert_eq!(first["ip_address"], "10.0.0.9");
    assert_eq!(first["browser"], "Chrome");
    assert_eq!(first["system"], "macOS");
    assert_eq!(first["mobile"], false);
    assert_eq!(
        first["user_agent"], CHROME,
        "the string it was read from was not given back"
    );
}
