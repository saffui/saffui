#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use data_encoding::BASE64URL_NOPAD;
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;

const REALM: &str = support::REALM;

const SESSION_REVOKED: &str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
const CREDENTIAL_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/credential-change";
const ACCOUNT_DISABLED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
const ACCOUNT_PURGED: &str = "https://schemas.openid.net/secevent/risc/event-type/account-purged";

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
        egress: config::serving::Egress::Anywhere,
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

async fn walked(plane: &Plane) {
    server::jobs::deliver_every_realm(
        &plane.pool(),
        &plane.tenancy(),
        &support::sealing(),
        &support::origin(),
        1,
    )
    .await;
}

/// The header of a compact JWS, read without trusting it: what the test wants
/// from it is only that the transmitter said what this is.
fn header_of(token: &str) -> Value {
    let first = token.split('.').next().expect("a compact token");
    serde_json::from_slice(&BASE64URL_NOPAD.decode(first.as_bytes()).expect("base64"))
        .expect("a json header")
}

/// The whole journey of the realm's security signals: a receiver subscribes,
/// and revoking a session, changing a credential, disabling and purging the
/// account each land as one verified Security Event Token, while ordinary
/// provisioning stays silent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_happens_here_is_signalled_there() {
    let plane = Plane::with_actions(&[
        AdminAction::IdpRead,
        AdminAction::IdpWrite,
        AdminAction::UserRead,
        AdminAction::UserWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    // Whatever provisioning wrote is drained before anybody listens: those
    // happenings predate the subscription.
    walked(&plane).await;

    // The ear: every push lands here, bearer and body kept for the test.
    let (heard_tx, mut heard) = tokio::sync::mpsc::unbounded_channel::<(String, String, String)>();
    let ear = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let ear_port = ear.local_addr().unwrap().port();
    let listening = actix_web::HttpServer::new(move || {
        let heard_tx = heard_tx.clone();
        actix_web::App::new().route(
            "/events",
            actix_web::web::post().to(
                move |request: actix_web::HttpRequest, body: actix_web::web::Bytes| {
                    let told = (
                        request
                            .headers()
                            .get("authorization")
                            .and_then(|held| held.to_str().ok())
                            .unwrap_or_default()
                            .to_owned(),
                        request
                            .headers()
                            .get("content-type")
                            .and_then(|held| held.to_str().ok())
                            .unwrap_or_default()
                            .to_owned(),
                        String::from_utf8_lossy(&body).into_owned(),
                    );
                    let _ = heard_tx.send(told);
                    async { actix_web::HttpResponse::Accepted().finish() }
                },
            ),
        )
    })
    .listen(ear)
    .expect("a listener")
    .workers(1)
    .disable_signals()
    .run();
    tokio::spawn(listening);

    // The receiver, wearing the bag a provider row wears; the bearer is
    // sealed on write and never rides back out.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        Some(json!({
            "provider_id": "the-watcher",
            "name": "the-watcher",
            "display_name": "", "description": "", "trust_email": false,
            "configs": {
                "kind": { "Str": "caep-push" },
                "endpoint": { "Str": format!("http://127.0.0.1:{ear_port}/events") },
                "audience": { "Str": "https://watcher.example" },
                "bearer": { "Str": "watcher-secret" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let (_, kept) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/identity-providers/the-watcher"),
        &bearer,
        None,
    )
    .await;
    assert!(
        kept["configs"].get("bearer").is_none(),
        "the bearer rode back out: {kept}"
    );

    // A second login for ada, so the one revoked is not the one the admin
    // bearer itself rides on.
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::sessions::open(
            &transaction,
            &models::sessions::records::UserSessionModel {
                browser_state: None,
                tenant: support::TENANT.into(),
                session_id: "session-2".into(),
                realm_id: REALM.into(),
                user_id: support::SUBJECT.into(),
                login_username: support::SUBJECT.into(),
                broker_session_id: None,
                broker_user_id: None,
                auth_method: None,
                ip_address: None,
                user_agent: None,
                started_at: chrono::Utc::now().timestamp(),
                auth_time: None,
                loa: None,
                expiration: None,
                state: models::sessions::records::UserSessionState::LoggedIn,
                remember_me: None,
                last_session_refresh: None,
                is_offline: None,
                notes: None,
            },
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }

    // A session ends by the admin's hand: the receiver is told, in a token
    // the realm's published keys verify.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!(
            "/admin/realms/{REALM}/users/{}/sessions/session-2",
            support::SUBJECT,
        ),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    walked(&plane).await;
    let (authorization, content_type, set) = heard.recv().await.expect("a push");
    assert_eq!(authorization, "Bearer watcher-secret");
    assert_eq!(content_type, "application/secevent+jwt");
    assert_eq!(header_of(&set)["typ"], "secevent+jwt", "{set}");
    let claims = plane.claims_of(&set).await;
    assert_eq!(claims["aud"], "https://watcher.example", "{claims}");
    assert_eq!(claims["sub_id"]["sub"], support::SUBJECT, "{claims}");
    assert!(
        claims["events"][SESSION_REVOKED].is_object(),
        "the event is missing or misnamed: {claims}"
    );
    assert!(
        claims["events"][SESSION_REVOKED]["event_timestamp"].is_i64(),
        "{claims}"
    );

    // A password change is a credential-change.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/users/{}/password", support::SUBJECT),
        &bearer,
        Some(json!({ "password": "a-brand-new-password-of-length" })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    walked(&plane).await;
    let (_, _, set) = heard.recv().await.expect("a push");
    let claims = plane.claims_of(&set).await;
    assert_eq!(
        claims["events"][CREDENTIAL_CHANGE]["credential_type"], "password",
        "{claims}"
    );

    // A new person is nothing at all: provisioning is the connectors'
    // traffic, not a security signal.
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/users"),
        &bearer,
        Some(json!({
            "user_name": "grace",
            "enabled": true,
            "email": "grace@example.test",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    walked(&plane).await;
    assert!(heard.try_recv().is_err(), "grace's arrival became a signal");

    // Disabling is an account-disabled; grace and not the admin's own
    // account, which would take the bearer down with it.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/users/grace"),
        &bearer,
        Some(json!({
            "user_name": "grace",
            "enabled": false,
            "email": "grace@example.test",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    walked(&plane).await;
    let (_, _, set) = heard.recv().await.expect("a push");
    let claims = plane.claims_of(&set).await;
    assert!(
        claims["events"][ACCOUNT_DISABLED].is_object(),
        "disabling said something else: {claims}"
    );
    assert_eq!(claims["sub_id"]["sub"], "grace", "{claims}");

    // Deletion is an account-purged.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/users/grace"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    walked(&plane).await;
    let (_, _, set) = heard.recv().await.expect("a push");
    let claims = plane.claims_of(&set).await;
    assert!(
        claims["events"][ACCOUNT_PURGED].is_object(),
        "deletion said something else: {claims}"
    );

    // Everything due was delivered: another pass pushes nothing.
    walked(&plane).await;
    assert!(
        heard.try_recv().is_err(),
        "something was pushed that nothing should have said"
    );

    // A receiver learns how to verify all of this at the fixed name.
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/realms/{REALM}/.well-known/ssf-configuration"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let told: Value = test::read_body_json(response).await;
    assert_eq!(told["issuer"], support::origin().issuer(REALM), "{told}");
    assert_eq!(told["delivery_methods_supported"][0], "urn:ietf:rfc:8935");
    assert!(
        told["jwks_uri"]
            .as_str()
            .is_some_and(|held| held.ends_with("/protocol/openid-connect/certs")),
        "{told}"
    );
}
