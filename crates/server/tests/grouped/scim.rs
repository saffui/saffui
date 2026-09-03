#[allow(unused_imports)]
use super::support;

use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;
use super::support::Plane;

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
        asking = asking
            .insert_header(("content-type", "application/scim+json"))
            .set_payload(body.to_string());
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
                 &response_type=code&scope=openid&state=s&nonce=n-scim",
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

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_provisioner_runs_a_whole_day() {
    let plane = Plane::with_actions(&[AdminAction::ScimRead, AdminAction::ScimWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/realms/{REALM}/scim/v2");

    // Discovery says honestly what this server does and refuses.
    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("{base}/ServiceProviderConfig"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["bulk"]["supported"], false);
    assert_eq!(told["patch"]["supported"], true);

    // The joiner: created with an externalId and a password.
    let (status, created) = asked(
        &plane,
        Method::POST,
        &format!("{base}/Users"),
        &bearer,
        Some(json!({
            "schemas": [services::scim::USER_SCHEMA],
            "userName": "grace",
            "externalId": "hr-1906",
            "name": { "givenName": "Grace", "familyName": "Hopper" },
            "emails": [{ "value": "grace@example.test", "primary": true }],
            "password": "a-password-of-decent-length",
            "active": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("an id").to_owned();
    assert_eq!(created["userName"], "grace");
    assert_eq!(created["externalId"], "hr-1906");
    assert!(
        created.get("password").is_none(),
        "the password rode back out: {created}"
    );

    // Reconciliation: the provisioner finds its own person by externalId.
    let (status, found) = asked(
        &plane,
        Method::GET,
        &format!("{base}/Users?filter=externalId%20eq%20%22hr-1906%22"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{found}");
    assert_eq!(found["totalResults"], 1, "{found}");
    assert_eq!(found["Resources"][0]["id"], id.as_str(), "{found}");

    // The pushed password opens a real login.
    let cookie = opened_login(&plane).await;
    assert_eq!(
        answered(&plane, &cookie, "grace", "a-password-of-decent-length").await,
        StatusCode::OK,
        "the provisioned password did not open the door"
    );

    // Uniqueness speaks the protocol's word.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("{base}/Users"),
        &bearer,
        Some(json!({
            "schemas": [services::scim::USER_SCHEMA],
            "userName": "grace",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["scimType"], "uniqueness", "{told}");

    // An exotic filter is refused, never approximated.
    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("{base}/Users?filter=userName%20co%20%22gr%22"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(told["scimType"], "invalidFilter", "{told}");

    // The leaver: Entra's own spelling of a deactivation.
    let (status, told) = asked(
        &plane,
        Method::PATCH,
        &format!("{base}/Users/{id}"),
        &bearer,
        Some(json!({
            "schemas": [services::scim::PATCH_SCHEMA],
            "Operations": [{ "op": "Replace", "path": "active", "value": "False" }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["active"], false, "{told}");
    let cookie = opened_login(&plane).await;
    assert_eq!(
        answered(&plane, &cookie, "grace", "a-password-of-decent-length").await,
        StatusCode::UNAUTHORIZED,
        "a deactivated person still signed in"
    );

    // The mover comes back, renamed on the way.
    let (status, told) = asked(
        &plane,
        Method::PATCH,
        &format!("{base}/Users/{id}"),
        &bearer,
        Some(json!({
            "schemas": [services::scim::PATCH_SCHEMA],
            "Operations": [
                { "op": "replace", "path": "active", "value": true },
                { "op": "replace", "value": { "name": { "familyName": "Hopper-Murray" } } },
            ],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["name"]["familyName"], "Hopper-Murray", "{told}");
    let cookie = opened_login(&plane).await;
    assert_eq!(
        answered(&plane, &cookie, "grace", "a-password-of-decent-length").await,
        StatusCode::OK
    );

    // The version tag moves when the person moves.
    let (_, read_back) = asked(
        &plane,
        Method::GET,
        &format!("{base}/Users/{id}"),
        &bearer,
        None,
    )
    .await;
    assert_ne!(
        read_back["meta"]["version"], created["meta"]["version"],
        "the tag did not move: {read_back}"
    );

    // Groups: created with a member, patched both ways, read from both sides.
    let (status, group) = asked(
        &plane,
        Method::POST,
        &format!("{base}/Groups"),
        &bearer,
        Some(json!({
            "schemas": [services::scim::GROUP_SCHEMA],
            "displayName": "crew",
            "members": [{ "value": id }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    let group_id = group["id"].as_str().expect("a group id").to_owned();
    assert_eq!(group["members"][0]["value"], id.as_str(), "{group}");

    let (_, person) = asked(
        &plane,
        Method::GET,
        &format!("{base}/Users/{id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(person["groups"][0]["value"], group_id.as_str(), "{person}");

    let (status, told) = asked(
        &plane,
        Method::PATCH,
        &format!("{base}/Groups/{group_id}"),
        &bearer,
        Some(json!({
            "schemas": [services::scim::PATCH_SCHEMA],
            "Operations": [
                { "op": "remove", "path": format!("members[value eq \"{id}\"]") },
            ],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["members"].as_array().map(Vec::len), Some(0), "{told}");

    // The day ends: the person is deleted, and asking again is a 404 in the
    // protocol's own error shape.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/Users/{id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("{base}/Users/{id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert!(
        told["schemas"][0]
            .as_str()
            .is_some_and(|held| held.ends_with(":Error")),
        "{told}"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_scim_door_needs_its_own_capability() {
    let plane = Plane::with_actions(&[AdminAction::UserRead, AdminAction::UserWrite]).await;
    let bearer = plane.token(&support::claims());
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("/realms/{REALM}/scim/v2/Users"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a general admin walked the provisioning door"
    );

    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("/realms/{REALM}/scim/v2/Users"),
        "not-a-token",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
