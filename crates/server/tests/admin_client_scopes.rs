mod support;

use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use support::Plane;

const REALM: &str = support::REALM;

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

/// A scope's whole life over the plane: born under a name its protocol owns,
/// renamed only onto free ground, held by a client in either manner, refused
/// deletion while held, and gone once released.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_scope_lives_and_dies_over_the_plane() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/client-scopes");
    let client = support::CONFIDENTIAL;

    // The provisioned world already owns this name: the pre-check answers for
    // rows the plane did not write.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "profile" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "client.scope.already_exists");

    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "employment", "description": "where a person works" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let scope_id = born["client_scope_id"]
        .as_str()
        .expect("an identity")
        .to_owned();
    assert_eq!(born["protocol"], "openid-connect", "the resting protocol");

    // The same word means something else to another protocol, and may exist.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "employment", "protocol": "docker" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let docker_id = told["client_scope_id"]
        .as_str()
        .expect("an identity")
        .to_owned();

    // A name that could never ride the scope parameter is refused.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "two words" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, told) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        told.as_array()
            .expect("a listing")
            .iter()
            .filter(|scope| scope["name"] == "employment")
            .count(),
        2,
        "both protocols' scopes are listed: {told}"
    );

    // A rename may not land on ground its protocol already holds.
    let (status, second) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "clearance" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    let second_id = second["client_scope_id"]
        .as_str()
        .expect("an identity")
        .to_owned();
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{second_id}"),
        &bearer,
        Some(json!({ "name": "employment" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    // Keeping its own name is not a collision with itself.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{second_id}"),
        &bearer,
        Some(json!({ "name": "clearance", "description": "renamed onto itself" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["description"], "renamed onto itself");
    assert!(
        told["metadata"]["version"].as_i64().unwrap_or(1) > 1,
        "the rewrite left no trace: {told}"
    );

    // Held as required first, then corrected to optional: one attachment,
    // whose manner the second call rewrites.
    let held = format!("/admin/realms/{REALM}/clients/{client}/scopes");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{held}/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (status, told) = asked(&plane, Method::GET, &held, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let mine = |told: &Value| {
        told.as_array()
            .expect("attachments")
            .iter()
            .find(|scope| scope["name"] == "employment")
            .cloned()
            .expect("the attached scope")
    };
    let count_before = told.as_array().expect("attachments").len();
    assert_eq!(mine(&told)["optional"], false);
    assert!(
        told.as_array()
            .expect("attachments")
            .iter()
            .any(|scope| scope["name"] == "profile"),
        "the provisioned attachment is listed beside the new one: {told}"
    );
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{held}/{scope_id}"),
        &bearer,
        Some(json!({ "optional": true })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (_, told) = asked(&plane, Method::GET, &held, &bearer, None).await;
    assert_eq!(
        told.as_array().expect("attachments").len(),
        count_before,
        "the second attachment corrected the first rather than adding: {told}"
    );
    assert_eq!(mine(&told)["optional"], true);

    // Each absent end is named as itself.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/clients/nobody/scopes/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "client.not_found");
    let (status, told) = asked(&plane, Method::PUT, &format!("{held}/none"), &bearer, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "client.scope.not_found");

    // Deletion is told no while a client holds the scope.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "directory.still_granted");

    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{held}/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    // An attachment that was never made is missing, not silently confirmed.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{held}/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");

    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("{base}/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    for leftover in [second_id, docker_id] {
        let (status, _) = asked(
            &plane,
            Method::DELETE,
            &format!("{base}/{leftover}"),
            &bearer,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
}

/// Reading the catalogue does not grant writing it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_scope_capabilities_split_where_they_should() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/client-scopes");

    let (status, told) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let (status, _) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "anything" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!(
            "/admin/realms/{REALM}/clients/{}/scopes/anything",
            support::CONFIDENTIAL
        ),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// What the catalogue calls a default reaches every client registered after
/// it, attached as required; the rest of the standard set stays optional, and
/// a custom scope nobody marked default reaches nobody by itself.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_new_client_carries_the_catalogue_defaults() {
    use actix_web::{App, test};
    use server::api::config::register;
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    plane
        .allow_registration(models::entities::realm::ClientRegistration::Open, None)
        .await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/client-scopes");

    for (name, default) in [("employment", true), ("clearance", false)] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &base,
            &bearer,
            Some(json!({ "name": name, "default_scope": default })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{told}");
    }

    let registered = |body: Value| {
        let plane = &plane;
        async move {
            let app =
                test::init_service(App::new().configure(register(&server::api::config::Plane {
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
                })))
                .await;
            let response = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri(&format!("/realms/{REALM}/protocol/openid-connect/register"))
                    .set_json(body)
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
            let told: Value = test::read_body_json(response).await;
            told["client_id"].as_str().expect("an identity").to_owned()
        }
    };

    let newcomer = registered(json!({
        "client_name": "a fresh application",
        "redirect_uris": ["https://fresh.example/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    }))
    .await;

    let (status, held) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/clients/{newcomer}/scopes"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{held}");
    let manner = |name: &str| {
        held.as_array()
            .expect("attachments")
            .iter()
            .find(|scope| scope["name"] == name)
            .map(|scope| scope["optional"].as_bool().expect("a manner"))
    };
    for offered in [
        "profile",
        "email",
        "employment",
        "phone",
        "address",
        "offline_access",
    ] {
        assert_eq!(manner(offered), Some(true), "{offered} waits to be asked");
    }
    assert_eq!(
        manner("clearance"),
        None,
        "an unmarked scope reached a client"
    );

    // Offered is not granted: a request naming less gets exactly what it
    // named, and one naming the admin's default gets it like any other.
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &store::tenancy::TenantContext::new(support::TENANT, REALM),
        )
        .await;
    assert_eq!(
        services::authorize::granted_scope(&transaction, &newcomer, "openid email")
            .await
            .unwrap(),
        "openid email",
        "a scope merely offered was granted unasked"
    );
    assert_eq!(
        services::authorize::granted_scope(&transaction, &newcomer, "openid employment")
            .await
            .unwrap(),
        "openid employment"
    );
    drop(transaction);
    drop(connection);

    // The flag is read live: unmade after, a default stops reaching the next
    // client, and the one already registered keeps what it was given.
    let employment_id = {
        let (_, listed) = asked(&plane, Method::GET, &base, &bearer, None).await;
        listed
            .as_array()
            .expect("a listing")
            .iter()
            .find(|scope| scope["name"] == "employment")
            .and_then(|scope| scope["client_scope_id"].as_str())
            .expect("the employment scope")
            .to_owned()
    };
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{employment_id}"),
        &bearer,
        Some(json!({ "name": "employment", "default_scope": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let second = registered(json!({
        "client_name": "a later application",
        "redirect_uris": ["https://later.example/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    }))
    .await;
    let (_, held) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/clients/{second}/scopes"),
        &bearer,
        None,
    )
    .await;
    assert!(
        held.as_array()
            .expect("attachments")
            .iter()
            .all(|scope| scope["name"] != "employment"),
        "an unmade default still reached the next client: {held}"
    );
}
