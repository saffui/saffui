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
    store::providers::protocol::login::failures(&transaction, support::SUBJECT)
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
    let response = posted(
        &plane,
        Some(HERE),
        support::SUBJECT,
        support::PASSWORD,
        false,
    )
    .await;
    assert_eq!(
        device_left_by(&response),
        None,
        "a realm that weighs no device minted a token"
    );
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["status"], "admitted", "{body}");
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

/// One answer, as the script sends it, to the login `binding` names, from
/// `peer`, carrying the device token when the browser kept one.
async fn answered_on(
    plane: &Plane,
    binding: &str,
    peer: &str,
    device: Option<&str>,
    body: Value,
) -> actix_web::dev::ServiceResponse {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut cookies = format!("{}={binding}", support::AUTH_SESSION_COOKIE);
    if let Some(device) = device {
        cookies.push_str(&format!("; {}={device}", support::DEVICE_COOKIE));
    }
    let request = test::TestRequest::post()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/login",
            support::REALM
        ))
        .insert_header(("cookie", cookies))
        .peer_addr(peer.parse().expect("an address"))
        .set_json(body);
    test::call_service(&app, request.to_request()).await
}

/// A name and a password against a fresh login, from `peer`.
async fn tried(
    plane: &Plane,
    peer: &str,
    device: Option<&str>,
    name: &str,
    password: &str,
) -> (StatusCode, Value) {
    let binding = opened(plane).await;
    let response = answered_on(
        plane,
        &binding,
        peer,
        device,
        serde_json::json!({ "username": name, "password": password }),
    )
    .await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

/// The device token a response left in the browser, if it left one.
fn device_left_by(response: &actix_web::dev::ServiceResponse) -> Option<String> {
    let set: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    support::cookie_value(&set, support::DEVICE_COOKIE)
}

/// Sign the subject in from `peer`, and keep what the browser was left.
async fn signed_in_from(plane: &Plane, peer: &str) -> String {
    let binding = opened(plane).await;
    let response = answered_on(
        plane,
        &binding,
        peer,
        None,
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    device_left_by(&response).expect("a device token")
}

/// A token for this name, sealed as the server seals one, at `at`.
async fn minted_at(plane: &Plane, typed: &str, at: chrono::DateTime<chrono::Utc>) -> String {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    let sealing = support::sealing();
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        support::TENANT,
        support::REALM,
    )
    .await
    .expect("the realm's keyring");
    let knock = auth::login::throttle::Knock::new(sealing.provider.as_ref(), None, Some(typed))
        .expect("a digest");
    auth::login::device::mint(
        sealing.provider.as_ref(),
        &ring,
        &sealing.envelope,
        knock.counted_name().expect("a name"),
        at,
    )
    .await
    .expect("a token")
}

/// What is counted against this source alone.
async fn counted_for(plane: &Plane, source: &str) -> i64 {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    transaction
        .query_one(
            "SELECT COALESCE(SUM(failures), 0)::bigint FROM source_failures \
             WHERE named = '' AND source = $1",
            &[&source],
        )
        .await
        .expect("the counts")
        .get(0)
}

/// The code the subject's authenticator app shows right now.
fn current_code() -> String {
    use crypto::provider::CryptoProvider as _;
    let provider = support::provider();
    let secret = data_encoding::BASE32_NOPAD
        .decode(support::TOTP_SECRET.as_bytes())
        .expect("a base32 secret");
    let code = crypto::otp::totp::totp_now(
        provider.hmac(),
        &secrecy::SecretBox::new(Box::new(secret)),
        crypto::otp::totp::TotpParams::new(crypto::provider::HashAlg::Sha1),
    )
    .expect("a code");
    crypto::otp::totp::format_code(code, 6)
}

/// People behind one address share its count, unless their browser signed in
/// before: past the threshold a stranger there is turned away, and the person
/// whose browser kept a token is answered.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_browser_that_signed_in_before_is_answered_where_its_address_is_turned_away() {
    let plane = Plane::with_actions(&[]).await;
    plane.throttle_sources(policy(2, 10)).await;
    let device = signed_in_from(&plane, HERE).await;

    for name in ["nobody-1", "nobody-2"] {
        let (status, body) = tried(&plane, HERE, None, name, "a-guess").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}: {body}");
    }
    let (status, body) = tried(&plane, HERE, None, support::SUBJECT, support::PASSWORD).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");

    let (status, body) = tried(
        &plane,
        HERE,
        Some(&device),
        support::SUBJECT,
        support::PASSWORD,
    )
    .await;
    assert_eq!(body["status"], "admitted", "{status}: {body}");
}

/// A device's failures are its own: past the threshold for one name it is
/// turned away the way an address is, while its address, which none of them
/// were counted against, still answers.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_device_is_counted_and_turned_away_on_its_own() {
    let plane = Plane::with_actions(&[]).await;
    plane.throttle_sources(policy(3, 2)).await;
    let device = signed_in_from(&plane, ELSEWHERE).await;

    for _ in 0..2 {
        let (status, body) = tried(
            &plane,
            HERE,
            Some(&device),
            support::SUBJECT,
            "not-the-password",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
    let binding = opened(&plane).await;
    let response = answered_on(
        &plane,
        &binding,
        HERE,
        Some(&device),
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().get("retry-after").is_some());
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["status"], "throttled", "{body}");

    assert_eq!(
        counted_for(&plane, "203.0.113.7").await,
        0,
        "a device's failures were counted against its address"
    );
    let (status, body) = tried(&plane, HERE, None, support::SUBJECT, support::PASSWORD).await;
    assert_eq!(body["status"], "admitted", "{status}: {body}");
}

/// A token is read under the name typed with it, every spelling of it alike,
/// and under no other: another name from the same browser is weighed on the
/// address, like any attempt without one.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_is_read_under_the_name_typed_and_no_other() {
    let plane = Plane::with_actions(&[]).await;
    plane.throttle_sources(policy(1, 10)).await;
    let device = signed_in_from(&plane, ELSEWHERE).await;
    let (status, body) = tried(&plane, HERE, None, "nobody", "a-guess").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let (status, body) = tried(&plane, HERE, Some(&device), "grace", "a-guess").await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "a token minted for one name answered for another: {body}"
    );

    let respelled = format!(" {} ", support::SUBJECT.to_uppercase());
    let (status, body) = tried(&plane, HERE, Some(&device), &respelled, "a-guess").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "another spelling of the name was not the name: {body}"
    );
}

/// The admission leaves the token on terms that keep it to the sign-in post of
/// this realm, for as long as it stands; a refusal leaves none.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_admission_leaves_a_device_token_on_strict_terms() {
    let plane = Plane::with_actions(&[]).await;

    let binding = opened(&plane).await;
    let response = answered_on(
        &plane,
        &binding,
        HERE,
        None,
        serde_json::json!({ "username": support::SUBJECT, "password": "not-the-password" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(device_left_by(&response), None, "a refusal left a token");

    let binding = opened(&plane).await;
    let response = answered_on(
        &plane,
        &binding,
        HERE,
        None,
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let set = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .find(|held| held.starts_with(&format!("{}=", support::DEVICE_COOKIE)))
        .expect("a device token")
        .to_owned();
    for term in [
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        &format!("Path=/realms/{}", support::REALM),
        &format!("Max-Age={}", auth::login::device::LIFETIME),
    ] {
        assert!(
            set.split("; ").any(|held| held == term),
            "{term} missing from {set}"
        );
    }
}

/// The lock is for strangers. Once they have filled it, the person still signs
/// in from the browser that signed in before, and getting in does not forget
/// what the strangers counted.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_locked_by_strangers_still_signs_in_from_their_browser() {
    let plane = Plane::with_actions(&[]).await;
    plane.count_logins(2).await;
    plane.throttle_sources(policy(100, 10)).await;
    let device = signed_in_from(&plane, HERE).await;

    for _ in 0..2 {
        let (status, body) = tried(
            &plane,
            ELSEWHERE,
            None,
            support::SUBJECT,
            "not-the-password",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
    let (_, body) = tried(&plane, ELSEWHERE, None, support::SUBJECT, support::PASSWORD).await;
    assert_eq!(body["status"], "locked-out", "{body}");

    let (status, body) = tried(
        &plane,
        HERE,
        Some(&device),
        support::SUBJECT,
        support::PASSWORD,
    )
    .await;
    assert_eq!(body["status"], "admitted", "{status}: {body}");

    assert_eq!(counted_for_the_person(&plane).await, 2);
    let (_, body) = tried(&plane, ELSEWHERE, None, support::SUBJECT, support::PASSWORD).await;
    assert_eq!(
        body["status"], "locked-out",
        "the person getting in forgot what strangers counted: {body}"
    );
}

/// What a device gets wrong is its own count's to answer: logged like any
/// failure, it locks nobody out.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_browsers_own_failures_are_logged_and_lock_nobody() {
    let plane = Plane::with_actions(&[]).await;
    plane.count_logins(2).await;
    plane.record_login_events().await;
    plane.throttle_sources(policy(100, 5)).await;
    let device = signed_in_from(&plane, HERE).await;

    for _ in 0..3 {
        let (status, body) = tried(
            &plane,
            HERE,
            Some(&device),
            support::SUBJECT,
            "not-the-password",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
    assert_eq!(counted_for_the_person(&plane).await, 0);
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, support::REALM))
        .await;
    let logged: i64 = transaction
        .query_one(
            "SELECT count(*) FROM login_events WHERE kind = 'sign_in_failed'",
            &[],
        )
        .await
        .expect("the sign-in log")
        .get(0);
    assert_eq!(logged, 3, "a device's failure went unlogged");

    let (status, body) = tried(&plane, ELSEWHERE, None, support::SUBJECT, support::PASSWORD).await;
    assert_eq!(body["status"], "admitted", "{status}: {body}");
}

/// A login is weighed under the name its first round typed. The second round
/// of a flow asking for a code types none, and is still the device's.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_later_round_is_weighed_under_the_name_the_first_one_typed() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .bind_browser_flow(support::CONFIDENTIAL, support::STRONG_FLOW)
        .await;
    plane.throttle_sources(policy(1, 10)).await;
    let named = serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD });
    let device = minted_at(&plane, support::SUBJECT, chrono::Utc::now()).await;

    let (status, body) = tried(&plane, HERE, None, "nobody", "a-guess").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let binding = opened(&plane).await;
    let response = answered_on(&plane, &binding, HERE, Some(&device), named).await;
    let status = response.status();
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["status"], "challenge", "{status}: {body}");
    let response = answered_on(
        &plane,
        &binding,
        HERE,
        Some(&device),
        serde_json::json!({ "password": support::PASSWORD, "totp": current_code() }),
    )
    .await;
    let status = response.status();
    let body: Value = test::read_body_json(response).await;
    assert_eq!(
        body["status"], "admitted",
        "a round that typed no name was weighed on the address: {status}: {body}"
    );
}

/// Where the realm counts nothing by where attempts come from, no device is
/// weighed either, so a token spares nobody the person's lock.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_device_is_not_weighed_where_the_realm_does_not_throttle() {
    let plane = Plane::with_actions(&[]).await;
    plane.count_logins(2).await;
    let device = signed_in_from(&plane, HERE).await;
    plane
        .throttle_sources(SourceThrottle {
            throttled: false,
            ..policy(100, 10)
        })
        .await;

    for _ in 0..2 {
        let (status, body) = tried(
            &plane,
            ELSEWHERE,
            None,
            support::SUBJECT,
            "not-the-password",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
    let (_, body) = tried(
        &plane,
        HERE,
        Some(&device),
        support::SUBJECT,
        support::PASSWORD,
    )
    .await;
    assert_eq!(body["status"], "locked-out", "{body}");
}

/// A token past its lifetime is no token, whatever the cookie's own expiry
/// said to the browser.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_past_its_lifetime_is_no_token() {
    let plane = Plane::with_actions(&[]).await;
    plane.throttle_sources(policy(1, 10)).await;
    let now = chrono::Utc::now();
    let aged = minted_at(
        &plane,
        support::SUBJECT,
        now - chrono::Duration::seconds(auth::login::device::LIFETIME + 1),
    )
    .await;
    let fresh = minted_at(&plane, support::SUBJECT, now).await;
    let (status, body) = tried(&plane, HERE, None, "nobody", "a-guess").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let (status, body) = tried(
        &plane,
        HERE,
        Some(&aged),
        support::SUBJECT,
        support::PASSWORD,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    let (status, body) = tried(
        &plane,
        HERE,
        Some(&fresh),
        support::SUBJECT,
        support::PASSWORD,
    )
    .await;
    assert_eq!(body["status"], "admitted", "{status}: {body}");
}
