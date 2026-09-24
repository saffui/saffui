use super::support;
use super::support::Plane;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use models::entities::realm::SourceThrottle;
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;

const HERE: &str = "203.0.113.7:40000";
const ELSEWHERE: &str = "198.51.100.2:40000";

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        sealing: support::sealing(),
        ceiling: support::ceiling(),
        egress: config::serving::Egress::Outward,
    }
}

fn policy(max_failures: i32, max_name_failures: i32) -> SourceThrottle {
    SourceThrottle {
        throttled: true,
        max_failures,
        max_name_failures,
        window_seconds: 900,
    }
}

/// Start a login and hand back the cookie that names it.
async fn opened(plane: &Plane) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope=openid&state=s",
                support::REALM,
                support::CONFIDENTIAL,
                support::urlencode("https://app.example/callback"),
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
    support::cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login")
}

/// One answer, from `peer` when there is one, as json or as the form a page
/// without scripts posts.
async fn posted(
    plane: &Plane,
    peer: Option<&str>,
    name: &str,
    password: &str,
    as_form: bool,
) -> actix_web::dev::ServiceResponse {
    let binding = opened(plane).await;
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut request = test::TestRequest::post()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/login",
            support::REALM
        ))
        .insert_header((
            "cookie",
            format!("{}={binding}", support::AUTH_SESSION_COOKIE),
        ));
    if let Some(peer) = peer {
        request = request.peer_addr(peer.parse().expect("an address"));
    }
    request = if as_form {
        let minted = support::page_token_for(plane, &binding).await;
        request.set_form([
            ("username", name),
            ("password", password),
            ("page_token", minted.as_str()),
        ])
    } else {
        request.set_json(serde_json::json!({ "username": name, "password": password }))
    };
    test::call_service(&app, request.to_request()).await
}

async fn answered_from(
    plane: &Plane,
    peer: Option<&str>,
    name: &str,
    password: &str,
) -> (StatusCode, Value) {
    let response = posted(plane, peer, name, password, false).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

/// What is counted against the address alone, and how many rows name it.
async fn counted_for_the_address(plane: &Plane) -> (i64, i64) {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    let row = transaction
        .query_one(
            "SELECT COALESCE(SUM(failures), 0)::bigint, COUNT(*) FROM source_failures \
             WHERE named = ''",
            &[],
        )
        .await
        .expect("the counts");
    (row.get(0), row.get(1))
}

/// What is counted against the person, however many addresses tried.
async fn counted_for_the_person(plane: &Plane) -> i64 {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    store::providers::login::failures(&transaction, support::SUBJECT)
        .await
        .expect("the failures table")
        .map_or(0, |record| record.num_failures)
}

/// A password tried once against many names is the shape a count per person
/// never sees. Past the threshold, the right password for somebody who exists
/// is not even looked at from that address, and is let in from any other.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_password_tried_against_many_names_turns_the_address_away() {
    let plane = Plane::with_actions(&[]).await;
    plane.throttle_sources(policy(3, 10)).await;

    for name in ["nobody-1", "nobody-2", support::SUBJECT] {
        let (status, body) = answered_from(&plane, Some(HERE), name, "Winter2026!").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}: {body}");
    }

    let response = posted(
        &plane,
        Some(HERE),
        support::SUBJECT,
        support::PASSWORD,
        false,
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let waited: i64 = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .expect("a Retry-After in seconds");
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["status"], "throttled", "{body}");
    let now = chrono::Utc::now().timestamp();
    let until = body["until"].as_i64().expect("an instant");
    assert!(
        until > now && until <= now + 900 + 60,
        "released at {until}, now {now}"
    );
    assert!(
        (1..=900 + 60).contains(&waited),
        "told to wait {waited} seconds"
    );

    // A page without scripts is sent back to be told the same.
    let response = posted(
        &plane,
        Some(HERE),
        support::SUBJECT,
        support::PASSWORD,
        true,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let went = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(went.ends_with("#throttled"), "sent to {went}");

    let (status, body) =
        answered_from(&plane, Some(ELSEWHERE), support::SUBJECT, support::PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "admitted", "{body}");
}

/// One account guessed at from one address fills the count with its name long
/// before the address's own. Every spelling of the name is the name, another
/// name from the same address is still answered, and the same name from
/// anywhere else gets in.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn one_name_guessed_from_one_address_is_held_before_the_address_is() {
    let plane = Plane::with_actions(&[]).await;
    plane.throttle_sources(policy(100, 2)).await;

    for typed in [
        support::SUBJECT.to_uppercase(),
        format!(" {} ", support::SUBJECT),
    ] {
        let (status, body) = answered_from(&plane, Some(HERE), &typed, "not-the-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{typed}: {body}");
    }
    let (status, body) =
        answered_from(&plane, Some(HERE), support::SUBJECT, support::PASSWORD).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["status"], "throttled", "{body}");

    let (status, body) = answered_from(&plane, Some(HERE), "somebody-else", "a-guess").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "another name from the same address was held: {body}"
    );

    let (status, body) =
        answered_from(&plane, Some(ELSEWHERE), support::SUBJECT, support::PASSWORD).await;
    assert_eq!(body["status"], "admitted", "{status}: {body}");
}

/// Turned away means not looked at: the password is not verified, so the
/// person's own count does not move, and the address's does not either, or an
/// address that kept knocking would never be let back.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_turned_away_attempt_verifies_nothing_and_counts_nothing() {
    let plane = Plane::with_actions(&[]).await;
    plane.count_logins(10).await;
    plane.throttle_sources(policy(2, 10)).await;

    for _ in 0..2 {
        let (status, body) =
            answered_from(&plane, Some(HERE), support::SUBJECT, "not-the-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
    assert_eq!(counted_for_the_person(&plane).await, 2);
    assert_eq!(counted_for_the_address(&plane).await.0, 2);

    for _ in 0..3 {
        let (status, body) =
            answered_from(&plane, Some(HERE), support::SUBJECT, "not-the-password").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    }
    assert_eq!(
        counted_for_the_person(&plane).await,
        2,
        "a turned away password was verified"
    );
    assert_eq!(
        counted_for_the_address(&plane).await.0,
        2,
        "a turned away attempt was counted"
    );
}

/// A lock the address's count skipped would say that somebody holds the name:
/// an attempt refused by the person's lock counts against the address like any
/// other refusal. The second failure locks the person, and the lock that
/// answers the third is the third count against the name.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_locked_person_still_counts_against_the_address() {
    let plane = Plane::with_actions(&[]).await;
    plane.count_logins(2).await;
    plane.throttle_sources(policy(100, 4)).await;

    let mut heard = Vec::new();
    for _ in 0..5 {
        let (_, body) =
            answered_from(&plane, Some(HERE), support::SUBJECT, "not-the-password").await;
        heard.push(body["status"].as_str().unwrap_or_default().to_owned());
    }
    assert_eq!(
        heard,
        [
            "refused",
            "refused",
            "locked-out",
            "locked-out",
            "throttled"
        ]
    );
}

/// A realm that switched the throttle off counts nothing and turns nobody away.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_that_does_not_throttle_counts_nothing() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .throttle_sources(SourceThrottle {
            throttled: false,
            ..policy(1, 1)
        })
        .await;

    for name in ["nobody-1", "nobody-2", "nobody-3"] {
        let (status, body) = answered_from(&plane, Some(HERE), name, "Winter2026!").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
    let (status, body) =
        answered_from(&plane, Some(HERE), support::SUBJECT, support::PASSWORD).await;
    assert_eq!(body["status"], "admitted", "{status}: {body}");
    assert_eq!(counted_for_the_address(&plane).await, (0, 0));
}

/// A stock realm throttles. What typed name came with a failure is kept only
/// as its digest, since a name box sometimes receives a password, and an
/// attempt nobody can say the address of is counted against no address.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_stock_realm_counts_by_address_and_keeps_no_name_as_typed() {
    let plane = Plane::with_actions(&[]).await;

    let (status, body) = answered_from(&plane, Some(HERE), "Winter2026!", "a-guess").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (status, body) = answered_from(&plane, None, "nobody", "a-guess").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    let rows = transaction
        .query(
            "SELECT source, named, failures FROM source_failures ORDER BY named",
            &[],
        )
        .await
        .expect("the counts");
    let held: Vec<(String, String, i32)> = rows
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    assert_eq!(held.len(), 2, "{held:?}");
    assert!(
        held.iter()
            .all(|(source, _, failures)| source == "203.0.113.7" && *failures == 1),
        "{held:?}"
    );
    assert_eq!(held[0].1, "", "{held:?}");
    let digest = &held[1].1;
    assert!(
        digest.len() == 64 && digest.chars().all(|held| held.is_ascii_hexdigit()),
        "a name was kept as something other than its digest: {digest}"
    );
    assert!(!digest.to_lowercase().contains("winter"), "{digest}");
}

/// Failures older than the window no longer count, whatever their number.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn failures_older_than_the_window_do_not_count() {
    let plane = Plane::with_actions(&[]).await;
    plane.throttle_sources(policy(3, 10)).await;
    let now = chrono::Utc::now().timestamp();
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    transaction
        .execute(
            "INSERT INTO source_failures (tenant, realm_id, source, named, minute, failures) \
             VALUES ($1, $2, '203.0.113.7', '', $3, 50)",
            &[
                &support::TENANT,
                &support::REALM,
                &(now - now % 60 - 900 - 120),
            ],
        )
        .await
        .expect("an old count");
    transaction.commit().await.expect("kept");

    let (status, body) =
        answered_from(&plane, Some(HERE), support::SUBJECT, support::PASSWORD).await;
    assert_eq!(body["status"], "admitted", "{status}: {body}");
}
