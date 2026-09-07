#[allow(unused_imports)]
use super::support;
use std::sync::{Arc, Mutex};

use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, HttpRequest, HttpResponse, test, web};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::register;

const REALM: &str = support::REALM;
const SECRET: &str = "a-webhook-secret-of-decent-length";

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

/// One delivery as the ear kept it: the two routing headers, the
/// signature, and the exact bytes it covered.
#[derive(Debug, Clone)]
struct Heard {
    signature: String,
    kind: String,
    event_id: String,
    body: Vec<u8>,
}

/// A listening ear on a real socket: every POST is kept whole, so the test
/// verifies the signature over the very bytes that travelled.
fn listening() -> (String, Arc<Mutex<Vec<Heard>>>) {
    let heard: Arc<Mutex<Vec<Heard>>> = Arc::new(Mutex::new(Vec::new()));
    let kept = heard.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().unwrap().port();
    let ear = actix_web::HttpServer::new(move || {
        let kept = kept.clone();
        App::new().route(
            "/hook",
            web::post().to(move |request: HttpRequest, body: web::Bytes| {
                let header = |name: &str| {
                    request
                        .headers()
                        .get(name)
                        .and_then(|held| held.to_str().ok())
                        .unwrap_or_default()
                        .to_owned()
                };
                kept.lock().unwrap().push(Heard {
                    signature: header("x-saffui-signature"),
                    kind: header("x-saffui-event"),
                    event_id: header("x-saffui-event-id"),
                    body: body.to_vec(),
                });
                async { HttpResponse::Ok().finish() }
            }),
        )
    })
    .listen(listener)
    .expect("a listener")
    .workers(1)
    .disable_signals()
    .run();
    tokio::spawn(ear);
    (format!("http://127.0.0.1:{port}/hook"), heard)
}

async fn one_pass(plane: &Plane) {
    server::jobs::deliver_every_realm(
        &plane.pool(),
        &plane.tenancy(),
        &support::sealing(),
        &support::origin(),
        // No backoff to wait out: a failed telling is due again at once.
        0,
    )
    .await;
}

/// The whole promise of the webhook sink in one walk: registered over the
/// plane with its secret sealed on write and masked on read, delivering
/// each admitted kind exactly as signed bytes the far side can verify,
/// filtering out what was not asked for, and redelivering under the same
/// event id while any listener still fails, which is the at-least-once
/// contract and the dedup key in one sight.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_happening_lands_signed_filtered_and_redeliverable() {
    let plane = Plane::with_actions(&[
        AdminAction::IdpRead,
        AdminAction::IdpWrite,
        AdminAction::UserRead,
        AdminAction::UserWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let (url, heard) = listening();

    // The planted world left its own tellings due; with nobody listening
    // yet, one pass puts them away, and the counts below start at zero.
    one_pass(&plane).await;

    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        Some(json!({
            "provider_id": "siem",
            "name": "siem",
            "display_name": "", "description": "", "trust_email": false,
            "configs": {
                "kind": { "Str": "webhook" },
                "url": { "Str": url },
                "filter": { "Str": "user.* session.revoked" },
                "secret": { "Str": SECRET },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");

    // The secret never rides back: masked in the clear key, and the sealed
    // bytes are nobody's to read over the plane.
    let (_, kept) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/identity-providers/siem"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(kept["configs"]["secret"]["Str"], "**********", "{kept}");
    assert!(
        kept["configs"].get("secret_sealed").is_none(),
        "the sealed secret rode back out: {kept}"
    );

    let (status, born) = asked(
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
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let grace = born["user_id"].as_str().expect("an identity").to_owned();

    one_pass(&plane).await;

    let first = {
        let held = heard.lock().unwrap();
        assert_eq!(held.len(), 1, "the ear heard {} tellings", held.len());
        held[0].clone()
    };
    assert_eq!(first.kind, "user.created");
    let expected =
        services::webhook::signature(support::sealing().provider.as_ref(), SECRET, &first.body)
            .expect("a signature");
    assert_eq!(
        first.signature, expected,
        "the signature does not cover the bytes that travelled"
    );
    assert_ne!(
        services::webhook::signature(
            support::sealing().provider.as_ref(),
            SECRET,
            format!("{}x", String::from_utf8_lossy(&first.body)).as_bytes(),
        )
        .unwrap(),
        first.signature,
        "a byte of tampering went unnoticed"
    );
    let envelope: Value = serde_json::from_slice(&first.body).expect("a JSON envelope");
    assert_eq!(envelope["kind"], "user.created", "{envelope}");
    assert_eq!(envelope["realm"], REALM, "{envelope}");
    assert_eq!(envelope["user_id"], grace.as_str(), "{envelope}");
    let occurred = envelope["occurred_at"].as_str().expect("an instant");
    assert!(
        chrono::DateTime::parse_from_rfc3339(occurred).is_ok(),
        "occurred_at does not parse: {occurred}"
    );
    assert_eq!(
        envelope["event_id"].to_string(),
        first.event_id,
        "the header id and the envelope id disagree"
    );

    // A kind the filter never asked for passes the webhook by, and with
    // nobody else listening the telling is put away, not retried.
    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(
                &mut connection,
                &store::tenancy::TenantContext::new(support::TENANT, REALM),
            )
            .await;
        store::providers::outbox::emit(
            &transaction,
            store::providers::outbox::CREDENTIAL_CHANGED,
            &grace,
            &json!({ "credential": "password" }),
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }
    one_pass(&plane).await;
    assert_eq!(
        heard.lock().unwrap().len(),
        1,
        "a filtered kind reached the ear anyway"
    );

    // A second listener that always fails holds the event due, and the
    // next pass tells the healthy ear again under the same id: this is
    // at-least-once, and the id is the dedup key.
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        Some(json!({
            "provider_id": "dead-ear",
            "name": "dead-ear",
            "display_name": "", "description": "", "trust_email": false,
            "configs": {
                "kind": { "Str": "webhook" },
                "url": { "Str": "http://127.0.0.1:9/hook" },
                "filter": { "Str": "user.*" },
                "secret": { "Str": SECRET },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/users/{grace}"),
        &bearer,
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    one_pass(&plane).await;
    one_pass(&plane).await;

    let held = heard.lock().unwrap();
    let updates: Vec<_> = held
        .iter()
        .filter(|heard| heard.kind == "user.updated")
        .collect();
    assert!(
        updates.len() >= 2,
        "the healthy ear was not told again while the dead one failed: {} tellings",
        updates.len()
    );
    assert_eq!(
        updates[0].event_id, updates[1].event_id,
        "a redelivery changed its id, which breaks every consumer's dedup"
    );
}
