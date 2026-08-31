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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_change_here_lands_in_the_provisioned_app() {
    let plane = Plane::with_actions(&[
        AdminAction::IdpRead,
        AdminAction::IdpWrite,
        AdminAction::UserRead,
        AdminAction::UserWrite,
        AdminAction::ScimRead,
        AdminAction::ScimWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    // The provisioned app is this very server, at another realm, reached
    // over a real socket: its inbound SCIM door is the far side.
    let served = mounted(&plane);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().unwrap().port();
    let upstream = actix_web::HttpServer::new(move || App::new().configure(register(&served)))
        .listen(listener)
        .expect("a listener")
        .workers(1)
        .disable_signals()
        .run();
    tokio::spawn(upstream);
    plane.plant_realm("mirror").await;

    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        Some(json!({
            "provider_id": "the-mirror",
            "name": "the-mirror",
            "display_name": "", "description": "", "trust_email": false,
            "configs": {
                "kind": { "Str": "scim-outbound" },
                "base_url": { "Str": format!("http://127.0.0.1:{port}/realms/mirror/scim/v2") },
                "bearer": { "Str": bearer },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let (_, kept) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/identity-providers/the-mirror"),
        &bearer,
        None,
    )
    .await;
    assert!(
        kept["configs"].get("bearer").is_none(),
        "the bearer rode back out: {kept}"
    );

    // A person appears here, by any door; the admin one will do.
    let (status, told) = asked(
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
    assert_eq!(status, StatusCode::CREATED, "{told}");

    // One outbox pass, run the way the job runs it.
    server::jobs::deliver_every_realm(&plane.pool(), &plane.tenancy(), &support::sealing(), 1)
        .await;

    // The mirror holds her, tied by our identifier.
    let (status, found) = asked(
        &plane,
        Method::GET,
        "/realms/mirror/scim/v2/Users?filter=externalId%20eq%20%22grace%22",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{found}");
    assert_eq!(found["totalResults"], 1, "{found}");
    assert_eq!(found["Resources"][0]["userName"], "grace", "{found}");
    let mirrored = found["Resources"][0]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    // The leaver: disabled here, inactive there.
    let (status, _) = asked(
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
    assert_eq!(status, StatusCode::OK);
    server::jobs::deliver_every_realm(&plane.pool(), &plane.tenancy(), &support::sealing(), 1)
        .await;
    let (_, shown) = asked(
        &plane,
        Method::GET,
        &format!("/realms/mirror/scim/v2/Users/{mirrored}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(shown["active"], false, "{shown}");

    // Gone here, gone there.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/users/grace"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    server::jobs::deliver_every_realm(&plane.pool(), &plane.tenancy(), &support::sealing(), 1)
        .await;
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("/realms/mirror/scim/v2/Users/{mirrored}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Running the pass again moves nothing: everything due was delivered.
    server::jobs::deliver_every_realm(&plane.pool(), &plane.tenancy(), &support::sealing(), 1)
        .await;
}
