#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;

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
        ceiling: support::ceiling(),
    }
}

async fn asked(plane: &Plane, method: Method, path: &str, bearer: &str) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let request = test::TestRequest::default()
        .method(method)
        .uri(path)
        .insert_header(("authorization", format!("Bearer {bearer}")))
        .to_request();
    let response = test::call_service(&app, request).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// The live feed hears what the store commits, and only that: an emission
/// inside a transaction says nothing until the commit speaks it, a rolled
/// back one never speaks, and what arrives is the summary, never the
/// payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_feed_speaks_at_commit_and_never_before() {
    let plane = Plane::with_actions(&[AdminAction::EventRead]).await;
    let feed = server::live::listen(support::owner());
    let mut watching = feed.subscribe();
    // The LISTEN has to stand before the emission, or the notify lands on
    // nobody; a moment is what the connection needs.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::outbox::emit(
            &transaction,
            store::providers::outbox::SESSION_REVOKED,
            "ada",
            &json!({ "session": "s-1", "held_back": "the payload stays home" }),
        )
        .await
        .unwrap();

        // Not yet: the transaction is open, so nothing happened.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(400), watching.recv())
                .await
                .is_err(),
            "the feed spoke before the commit"
        );
        transaction.commit().await.unwrap();
    }

    let told = tokio::time::timeout(std::time::Duration::from_secs(5), watching.recv())
        .await
        .expect("the feed said nothing after the commit")
        .expect("the feed closed");
    assert_eq!(told.kind, "session.revoked");
    assert_eq!(told.realm, REALM);
    assert_eq!(told.tenant, support::TENANT);
    assert_eq!(told.user_id, "ada");
    assert!(told.event_id > 0);
    assert!(
        chrono::DateTime::parse_from_rfc3339(&told.occurred_at).is_ok(),
        "occurred_at does not parse: {}",
        told.occurred_at
    );

    // Rolled back is never spoken.
    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::outbox::emit(
            &transaction,
            store::providers::outbox::USER_UPDATED,
            "ada",
            &json!({}),
        )
        .await
        .unwrap();
        drop(transaction);
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(600), watching.recv())
            .await
            .is_err(),
        "a rolled back emission was spoken"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_live_replay_answers_after_a_cursor_without_payloads() {
    let plane = Plane::with_actions(&[AdminAction::EventRead]).await;
    let bearer = plane.token(&support::claims());
    let baseline = {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let baseline = transaction
            .query_one("SELECT coalesce(max(event_id), 0) FROM event_outbox", &[])
            .await
            .unwrap()
            .get::<_, i64>(0);
        transaction.commit().await.unwrap();
        baseline
    };

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    store::providers::outbox::emit(
        &transaction,
        store::providers::outbox::USER_UPDATED,
        "ada",
        &json!({ "private": true }),
    )
    .await
    .unwrap();
    store::providers::outbox::emit(
        &transaction,
        store::providers::outbox::SESSION_REVOKED,
        "ada",
        &json!({ "private": true }),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();

    let (status, first_page) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/events/replay?after_event_id={baseline}&limit=1"),
        &bearer,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first_page}");
    assert_eq!(first_page["items"].as_array().unwrap().len(), 1);
    assert_eq!(first_page["more"], true);
    assert!(first_page["items"][0].get("payload").is_none());

    let cursor = first_page["next_event_id"].as_i64().unwrap();
    let (status, second_page) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/events/replay?after_event_id={cursor}"),
        &bearer,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second_page}");
    assert_eq!(
        second_page["items"][0]["kind"], "session.revoked",
        "{second_page}"
    );
}

/// A reconnect hears what it missed after its cursor, then the broadcast, and
/// an event both replayed from the store and still in the broadcast's buffer
/// is said once. The race is laid out by hand: the feed is the test's own, and
/// the committed event is pushed into it after the stream has read the store.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_reconnect_hears_each_missed_event_once() {
    use actix_web::body::MessageBody;

    let plane = Plane::with_actions(&[AdminAction::EventRead]).await;
    let bearer = plane.token(&support::claims());
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let baseline: i64 = transaction
        .query_one("SELECT coalesce(max(event_id), 0) FROM event_outbox", &[])
        .await
        .unwrap()
        .get(0);
    for kind in [
        store::providers::outbox::USER_UPDATED,
        store::providers::outbox::SESSION_REVOKED,
    ] {
        store::providers::outbox::emit(&transaction, kind, "ada", &json!({}))
            .await
            .unwrap();
    }
    let missed: Vec<i64> = transaction
        .query(
            "SELECT event_id FROM event_outbox WHERE event_id > $1 ORDER BY event_id",
            &[&baseline],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    transaction.commit().await.unwrap();
    assert_eq!(missed.len(), 2, "two events after the cursor");

    let (feed, _) = tokio::sync::broadcast::channel::<server::live::Told>(16);
    let app = test::init_service(
        App::new()
            .app_data(actix_web::web::Data::new(feed.clone()))
            .configure(register(&mounted(&plane))),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/admin/realms/{REALM}/events/stream"))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .insert_header(("last-event-id", baseline.to_string()))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let told = |event_id: i64| server::live::Told {
        tenant: support::TENANT.into(),
        realm: REALM.into(),
        event_id,
        kind: "session.revoked".into(),
        user_id: "ada".into(),
        occurred_at: chrono::Utc::now().to_rfc3339(),
    };
    let fresh = missed[1] + 1_000;
    feed.send(told(missed[1])).expect("the stream listens");
    feed.send(told(fresh)).expect("the stream listens");

    let mut body = std::pin::pin!(response.into_body());
    let mut heard = Vec::new();
    while !heard.contains(&fresh) {
        let chunk = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            std::future::poll_fn(|cx| body.as_mut().poll_next(cx)),
        )
        .await
        .expect("the stream fell silent")
        .expect("the stream ended")
        .expect("a frame");
        for line in std::str::from_utf8(&chunk).unwrap().lines() {
            if let Some(id) = line.strip_prefix("id: ") {
                heard.push(id.parse::<i64>().unwrap());
            }
        }
    }
    assert_eq!(
        heard,
        vec![missed[0], missed[1], fresh],
        "an event replayed from the store was said again from the broadcast"
    );
}
