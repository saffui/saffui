mod support;

use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::Value;
use support::Plane;

/// Ask the plane, with a body or without one.
async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    use actix_web::{App, test};
    use server::api::config::register;
    use server::middleware::admin_policy::AdminPolicy;
    let app = test::init_service(App::new().configure(register(&server::api::config::Plane {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    })))
    .await;
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

/// A realm is born ready or not at all: the row, the standard scopes, this
/// deployment's console and a signing key arrive together, a second create
/// is a conflict, and the switches are rewritten in place afterwards.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_is_created_ready_and_reshaped_in_place() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmCreate,
        AdminAction::RealmWrite,
        AdminAction::RealmDelete,
        AdminAction::RealmRead,
        AdminAction::ClientRead,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    // A name that will not survive a URL is refused before anything is made.
    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(serde_json::json!({ "name": "no spaces", "display_name": "x", "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, born) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(serde_json::json!({ "name": "staging", "display_name": "Staging", "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    assert_eq!(born["name"], "staging", "{born}");

    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(serde_json::json!({ "name": "staging", "display_name": "Again", "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    // Born ready: the standard scopes and the admin scope are in place, and
    // the deployment's console is registered and pointed at this server.
    let (status, scopes) = asked(
        &plane,
        Method::GET,
        "/admin/realms/staging/client-scopes",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{scopes}");
    let names: Vec<&str> = scopes
        .as_array()
        .expect("a scope catalogue")
        .iter()
        .filter_map(|held| held["name"].as_str())
        .collect();
    for wanted in ["profile", "email", "offline_access", support::SCOPE] {
        assert!(names.contains(&wanted), "{wanted} missing from {names:?}");
    }

    let (status, console) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/staging/clients/{}", support::PARTY),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{console}");

    // Reshaped: the mentioned switches move, the name does not.
    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({
            "display_name": "Staging ground",
            "access_token_lifespan": 600,
            "refresh_token_lifespan": 900,
            "session_max_lifespan": 28800,
            "require_pushed_authorization_requests": true,
            "registration_bounds": {
                "max_clients": 5,
                "requires_consent": true,
                "trusted_hosts": ["apps.test"]
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["name"], "staging", "{shaped}");
    assert_eq!(shaped["display_name"], "Staging ground", "{shaped}");
    assert_eq!(shaped["access_token_lifespan"], 600, "{shaped}");
    assert_eq!(shaped["refresh_token_lifespan"], 900, "{shaped}");
    assert_eq!(shaped["session_max_lifespan"], 28800, "{shaped}");
    assert_eq!(shaped["require_pushed_authorization_requests"], true);
    assert_eq!(shaped["registration_bounds"]["max_clients"], 5, "{shaped}");

    let (status, read) = asked(
        &plane,
        Method::GET,
        "/admin/realms/staging?briefRepresentation=false",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(read["access_token_lifespan"], 600, "{read}");
    assert_eq!(read["display_name"], "Staging ground", "{read}");

    // The OTP policy is bounded by what an authenticator app will honour.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({ "otp_policy": { "digits": 9, "period": 30 } })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({
            "otp_policy": { "digits": 8, "period": 60, "algorithm": "SHA256", "window": 2 }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["otp_policy"]["digits"], 8, "{shaped}");
    assert_eq!(shaped["otp_policy"]["algorithm"], "SHA256", "{shaped}");

    // A reworded mail keeps its link or is refused; sound words round-trip.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({
            "mail_templates": { "magic_link": { "fr": { "subject": "Lien", "body": "sans lien" } } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({
            "mail_templates": {
                "magic_link": { "fr": { "subject": "Votre lien", "body": "Suivez : {{link}}" } }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(
        shaped["mail_templates"]["magic_link"]["fr"]["subject"], "Votre lien",
        "{shaped}"
    );

    // Device pacing is bounded to what a waiting screen can live with.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({ "device_code_lifespan": 10 })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({ "device_code_lifespan": 300, "device_poll_interval": 10 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["device_code_lifespan"], 300, "{shaped}");
    assert_eq!(shaped["device_poll_interval"], 10, "{shaped}");

    // Backchannel pacing stands on the same footing.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({ "ciba_expiry": 10 })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({ "ciba_expiry": 120, "ciba_interval": 9 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["ciba_expiry"], 120, "{shaped}");
    assert_eq!(shaped["ciba_interval"], 9, "{shaped}");

    // The key ceremony's shown name is bounded; the subdomain switch rides.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({ "webauthn_policy": { "rp_name": "x".repeat(65) } })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({
            "webauthn_policy": { "rp_name": "Acme Staging", "allow_subdomains": true }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(
        shaped["webauthn_policy"]["rp_name"], "Acme Staging",
        "{shaped}"
    );
    assert_eq!(shaped["webauthn_policy"]["allow_subdomains"], true);

    // The realm's browser binding: a named flow must exist and stand top
    // level; the seeded flow does, a ghost does not, and empty clears.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({ "browser_flow": "ghost" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({ "browser_flow": "browser" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["browser_flow"], "browser", "{shaped}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/staging",
        &bearer,
        Some(serde_json::json!({ "browser_flow": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(shaped["browser_flow"].is_null(), "{shaped}");

    // The relay test refuses in words when no settings stand, and wants an
    // address that is one.
    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms/staging/mail/test",
        &bearer,
        Some(serde_json::json!({ "to": "nobody" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms/staging/mail/test",
        &bearer,
        Some(serde_json::json!({ "to": "someone@acme.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");

    // Reshaping what does not exist is not creating it.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/nowhere",
        &bearer,
        Some(serde_json::json!({ "display_name": "ghost" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");

    // The registration secret is drawn, answered once, and never read back.
    let (status, drawn) = asked(
        &plane,
        Method::POST,
        "/admin/realms/staging/registration-secret",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{drawn}");
    let first = drawn["registration_secret"]
        .as_str()
        .expect("a secret answered once")
        .to_owned();

    let (status, drawn) = asked(
        &plane,
        Method::POST,
        "/admin/realms/staging/registration-secret",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        drawn["registration_secret"].as_str().unwrap(),
        first,
        "a rotation answered the same secret twice"
    );

    let (status, read) = asked(
        &plane,
        Method::GET,
        "/admin/realms/staging?briefRepresentation=false",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        read.get("registration_secret").is_none(),
        "the stored secret is serialised: {read}"
    );

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        "/admin/realms/staging/registration-secret",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A realm is deleted from somewhere else, never out from under its own
    // console, and the schema takes everything keyed under it along.
    let (status, told) = asked(&plane, Method::DELETE, "/admin/realms/main", &bearer, None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        "/admin/realms/staging",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::GET,
        "/admin/realms/staging?briefRepresentation=false",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        "/admin/realms/staging",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A realm speaks over the pages: the accepted words reach the render, and
/// words nothing reads are refused at the door.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_speaks_over_its_pages() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());

    // The catalogue lists what may be spoken over.
    let (status, keys) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{}/page-keys", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{keys}");
    assert!(
        keys["keys"]
            .as_array()
            .expect("a listing")
            .iter()
            .any(|row| row["name"] == "login-title"),
        "{keys}"
    );

    // A key nobody reads, a tongue nobody renders: both refused in words.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "page_overrides": { "en": { "no-such-key": "x" } } })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "page_overrides": { "eo": { "login-title": "x" } } })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // Spoken, and the page wears it.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({
            "page_overrides": { "en": { "login-title": "The Acme door" } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    use actix_web::{App, test};
    use server::api::config::register;
    use server::middleware::admin_policy::AdminPolicy;
    let app = test::init_service(App::new().configure(register(&server::api::config::Plane {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    })))
    .await;
    let request = test::TestRequest::get()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/login",
            support::REALM
        ))
        .to_request();
    let response = test::call_service(&app, request).await;
    let body = String::from_utf8(test::read_body(response).await.to_vec()).expect("a page");
    assert!(
        body.contains("The Acme door"),
        "the override missed the render"
    );
    assert!(
        !body.contains("{{"),
        "the rest of the page lost its words: {body}"
    );
}
