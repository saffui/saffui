//! The desktop-ticket door, driven with a real ticket from a real KDC.
//!
//! Needs a database and a Kerberos world: `deploy/krb5/up.sh` brings the KDC
//! up, and the environment does the rest (`KRB5_CONFIG` naming the realm,
//! `KRB5_KTNAME` naming the exported service keytab, a `kinit` for ada, and
//! `SAFFUI_TEST_KRB5` naming the realm to say all of that stands).

#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;

const REALM: &str = support::REALM;
const SERVICE: &str = "HTTP/localhost";

fn kerberos_realm() -> Option<String> {
    std::env::var("SAFFUI_TEST_KRB5").ok()
}

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

/// A flow where a ticket is one way in and a password stays the other, bound
/// to the client the bench signs in with, plus the realm's door row.
async fn negotiating(plane: &Plane, realm: &str) {
    use models::entities::attributes::AttributeValue;
    use store::tenancy::TenantContext;

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let metadata =
        || models::auditable::AuditableModel::from_creator(support::TENANT.into(), "root".into());
    let flow = models::entities::auth::AuthenticationFlowMutationModel {
        alias: "desk".into(),
        provider_id: "basic-flow".into(),
        description: String::new(),
        top_level: Some(true),
        built_in: Some(false),
    }
    .into_model("desk".into(), REALM.into(), metadata());
    store::providers::auth_flows::create_flow(&transaction, &flow)
        .await
        .unwrap();
    for (id, authenticator, priority) in
        [("desk-ticket", "kerberos", 10), ("desk-pw", "password", 20)]
    {
        let step = models::entities::auth::AuthenticationExecutionMutationModel {
            alias: id.into(),
            flow_id: "desk".into(),
            priority,
            step: models::entities::auth::ExecutionStep::Authenticator {
                authenticator: authenticator.into(),
                config_id: None,
            },
            requirement: models::entities::auth::AuthenticatorRequirement::Alternative,
        }
        .into_model(id.into(), REALM.into(), metadata());
        store::providers::auth_flows::create_execution(&transaction, &step)
            .await
            .unwrap();
    }
    store::providers::brokering::keep_spnego(
        &transaction,
        &models::entities::brokering::RealmSpnegoModel {
            realm_id: REALM.into(),
            enabled: Some(true),
            configs: Some(std::collections::HashMap::from([(
                "service_principal".to_owned(),
                AttributeValue::Str(format!("{SERVICE}@{realm}")),
            )])),
            metadata: metadata(),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    plane.bind_browser_flow(support::CONFIDENTIAL, "desk").await;
}

async fn opened_login(plane: &Plane) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope=openid&state=s&nonce=n-desk",
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

/// One POST at the login, with or without a ticket attached.
async fn posted(
    plane: &Plane,
    cookie: &str,
    body: Value,
    ticket: Option<&[u8]>,
) -> (StatusCode, Option<String>, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asking = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect/login"))
        .insert_header((
            "cookie",
            format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
        ))
        .set_json(body);
    if let Some(blob) = ticket {
        asking = asking.insert_header((
            "authorization",
            format!("Negotiate {}", data_encoding::BASE64.encode(blob)),
        ));
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let negotiate = response
        .headers()
        .get("www-authenticate")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = test::read_body(response).await;
    let told = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, negotiate, told)
}

/// A real ticket for the bench's service, out of the caller's own cache.
fn minted_ticket(realm: &str) -> Vec<u8> {
    use cross_krb5::{ClientCtx, InitiateFlags};
    let (_pending, token) = ClientCtx::new(
        InitiateFlags::empty(),
        None,
        &format!("{SERVICE}@{realm}"),
        None,
    )
    .expect("a ticket from the kinited cache");
    token.to_vec()
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG) and a KDC (SAFFUI_TEST_KRB5)"]
async fn a_desktop_ticket_signs_ada_in() {
    let Some(realm) = kerberos_realm() else {
        eprintln!("no KDC named; skipping");
        return;
    };
    let plane = Plane::with_actions(&[]).await;
    negotiating(&plane, &realm).await;
    let cookie = opened_login(&plane).await;

    // An empty answer is challenged the protocol's way: a 401 naming the
    // scheme, with the flow's own challenge still in the body.
    let (status, negotiate, told) = posted(&plane, &cookie, json!({}), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(negotiate.as_deref(), Some("Negotiate"), "{told}");
    assert_eq!(told["asks"]["mechanism"], "negotiate", "{told}");

    // The retry carries the ticket, and the ticket is the whole answer.
    let ticket = minted_ticket(&realm);
    let (status, _, told) = posted(&plane, &cookie, json!({}), Some(&ticket)).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "admitted", "{told}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG) and a KDC (SAFFUI_TEST_KRB5)"]
async fn garbage_is_not_a_ticket_and_a_password_still_is() {
    let Some(realm) = kerberos_realm() else {
        eprintln!("no KDC named; skipping");
        return;
    };
    let plane = Plane::with_actions(&[]).await;
    negotiating(&plane, &realm).await;
    let cookie = opened_login(&plane).await;

    // A blob that is not a Kerberos exchange fails the step, and the flow
    // falls to its other way in rather than admitting, looping the 401, or
    // refusing the whole login while a password could still answer.
    let (status, negotiate, told) = posted(&plane, &cookie, json!({}), Some(b"not-spnego")).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "challenge", "garbage admitted: {told}");
    assert_eq!(told["execution"], "desk-pw", "{told}");
    assert_eq!(negotiate, None, "a failed step was re-challenged: {told}");

    // Off the domain, the password alternative still signs ada in.
    let fresh = opened_login(&plane).await;
    let (status, _, told) = posted(
        &plane,
        &fresh,
        json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "admitted", "{told}");
}

/// One admin call against the mounted plane.
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

/// The door's row is read at the plane, whole or not at all. No KDC in this
/// one: what it proves is the configuration surface.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_door_row_is_read_at_the_plane() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/spnego");

    // Nothing yet: asking reads as absence, not as an empty door.
    let (status, _) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A bag missing its principal, a principal missing its realm, and a key
    // no door reads: each refused at the write, spelled.
    for (body, named) in [
        (json!({ "configs": {} }), "service_principal"),
        (
            json!({ "configs": { "service_principal": { "Str": "HTTP/localhost" } } }),
            "whole",
        ),
        (
            json!({ "configs": { "service_principal": { "Str": "HTTP/localhost@SAFFUI.TEST" },
                                 "keytab": { "Str": "/etc/krb5.keytab" } } }),
            "no door reads",
        ),
    ] {
        let (status, told) = asked(&plane, Method::PUT, &base, &bearer, Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert!(
            told.to_string().contains(named),
            "the refusal did not name {named}: {told}"
        );
    }

    // A whole one is kept and read back as written.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &base,
        &bearer,
        Some(json!({ "configs": {
            "service_principal": { "Str": "HTTP/localhost@SAFFUI.TEST" }
        } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, told) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        told["configs"]["service_principal"]["Str"], "HTTP/localhost@SAFFUI.TEST",
        "{told}"
    );

    // Taken away, it is gone, and taking it away twice says so.
    let (status, _) = asked(&plane, Method::DELETE, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(&plane, Method::DELETE, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
