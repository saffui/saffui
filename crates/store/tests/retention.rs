//! Retention on Postgres: what expired is removed in every realm, what is
//! still of use stays, and the work is done by one node, under one role.

use pgcore::pool::PoolSettings;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE};
use saffui_core::app::App;
use saffui_core::directory::Person;
use saffui_core::ids::mint_id;
use saffui_core::login::session::{Session, SessionState};
use saffui_core::oidc::code::{AuthorizationCode, PendingAuthorization};
use saffui_core::ports::storage::StorageError;
use saffui_core::retention::{PurgeReport, run_retention_pass};
use saffui_core::tenancy::RealmScope;
use saffui_core::testkit::fixtures::create_realm;
use saffui_core::tokens::store::RefreshToken;
use store::retention::{PgRetention, RETENTION_LOCK};
use time::{Duration, OffsetDateTime};
use tokio_postgres::Client;

mod support;

/// Writes, in one realm, a row past its keeping and a row still of use in
/// each of the five tables retention reads.
async fn fill_realm(app: &App, scope: RealmScope, now: OffsetDateTime) {
    let identify = || mint_id(app).expect("an identifier");
    let person = Person {
        id: identify(),
        username: "ada".to_owned(),
        email: None,
        email_verified: false,
        display_name: None,
        enabled: true,
        created_at: now,
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_person(&person).await.expect("a person");
    // Expired a minute ago, or still of use for five minutes. A code is kept
    // the length of a session past its expiry.
    let lifetimes = [
        (1_u8, Duration::minutes(-1), Duration::hours(-13)),
        (2, Duration::minutes(5), Duration::hours(-11)),
    ];
    for (digest, expires_in, code_expires_in) in lifetimes {
        let expires_at = now + expires_in;
        let session = Session {
            id: identify(),
            person: person.id,
            secret_digest: vec![digest; 32],
            state: SessionState::Active,
            authenticated_at: now - Duration::hours(12),
            expires_at,
        };
        work.insert_session(&session).await.expect("a session");
        work.insert_refresh_token(&RefreshToken {
            token_digest: vec![digest; 32],
            family: identify(),
            client_id: "portal".to_owned(),
            person: person.id,
            session: session.id,
            scopes: vec!["openid".to_owned()],
            issued_at: now - Duration::hours(1),
            expires_at,
        })
        .await
        .expect("a refresh token");
        work.insert_pending_authorization(&PendingAuthorization {
            id: identify(),
            browser_digest: vec![digest; 32],
            client_id: "portal".to_owned(),
            redirect_uri: "https://app.example.org/cb".to_owned(),
            scopes: vec!["openid".to_owned()],
            state: None,
            nonce: None,
            code_challenge: "c".repeat(43),
            expires_at,
            expected_person: None,
        })
        .await
        .expect("a pending request");
        work.insert_authorization_code(&AuthorizationCode {
            code_digest: vec![digest; 32],
            client_id: "portal".to_owned(),
            person: person.id,
            session: session.id,
            redirect_uri: "https://app.example.org/cb".to_owned(),
            scopes: vec!["openid".to_owned()],
            nonce: None,
            code_challenge: "c".repeat(43),
            authenticated_at: now,
            expires_at: now + code_expires_in,
        })
        .await
        .expect("a code");
    }
    // A counter of three days ago, and one of the window that is being read.
    work.record_login_failure(&[1; 32], now - Duration::days(3))
        .await
        .expect("an old counter");
    work.record_login_failure(&[2; 32], now - Duration::minutes(3))
        .await
        .expect("a recent counter");
    work.commit().await.expect("a commit");
}

const TABLES: [&str; 5] = [
    "authorization_requests",
    "authorization_codes",
    "refresh_tokens",
    "sessions",
    "login_failures",
];

async fn count_rows(client: &Client) -> [i64; 5] {
    let mut counted = [0; 5];
    for (slot, table) in TABLES.into_iter().enumerate() {
        counted[slot] = client
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .expect("a count")
            .get(0);
    }
    counted
}

#[tokio::test]
async fn a_pass_removes_what_expired_in_every_realm_and_leaves_what_is_still_of_use() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    for realm in ["retention-one", "retention-two"] {
        let scope = create_realm(&app, realm).await;
        fill_realm(&app, scope, now).await;
    }
    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    assert_eq!(count_rows(&maintenance).await, [4; 5]);
    let retention = PgRetention::new(database.plan(MAINTENANCE_ROLE));

    let first = run_retention_pass(&retention, now).await;

    let two_of_each = PurgeReport {
        pending_requests: 2,
        codes: 2,
        refresh_tokens: 2,
        sessions: 2,
        failure_counters: 2,
    };
    assert_eq!(first, Ok(Some(two_of_each)));
    assert_eq!(
        count_rows(&maintenance).await,
        [2; 5],
        "what is still of use stays, in both realms"
    );
    assert_eq!(
        run_retention_pass(&retention, now).await,
        Ok(Some(PurgeReport::default())),
        "a second pass finds nothing left to remove"
    );
}

#[tokio::test]
async fn a_pass_under_the_role_that_serves_is_refused_and_removes_nothing() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-refused").await;
    fill_realm(&app, scope, now).await;
    let under_the_serving_role = PgRetention::new(database.plan(APP_ROLE));

    let refused = run_retention_pass(&under_the_serving_role, now).await;

    assert_eq!(refused, Err(StorageError::Failed));
    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    assert_eq!(count_rows(&maintenance).await, [2; 5]);
}

#[tokio::test]
async fn a_node_that_finds_the_pass_taken_leaves_it_to_the_other() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-taken").await;
    fill_realm(&app, scope, now).await;
    let mut other_node = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    let holding = other_node.transaction().await.expect("a transaction");
    holding
        .execute("SELECT pg_advisory_xact_lock($1)", &[&RETENTION_LOCK])
        .await
        .expect("the lock");
    let retention = PgRetention::new(database.plan(MAINTENANCE_ROLE));

    let left_alone = run_retention_pass(&retention, now).await;

    assert_eq!(left_alone, Ok(None));
    holding.rollback().await.expect("the lock released");
    assert!(
        matches!(run_retention_pass(&retention, now).await, Ok(Some(report)) if report.codes == 1),
        "once the lock is free the pass runs"
    );
}

#[tokio::test]
async fn a_pass_removes_more_than_one_batch_and_still_leaves_what_is_of_use() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-batches").await;
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    // One more than a batch removes, and one that is still read.
    for digest in 0..1_001_u32 {
        work.record_login_failure(&digest.to_be_bytes(), now - Duration::days(3))
            .await
            .expect("an old counter");
    }
    work.record_login_failure(&[9; 32], now - Duration::minutes(3))
        .await
        .expect("a recent counter");
    work.commit().await.expect("a commit");
    let retention = PgRetention::new(database.plan(MAINTENANCE_ROLE));

    let report = run_retention_pass(&retention, now).await;

    assert_eq!(
        report.map(|report| report.map(|report| report.failure_counters)),
        Ok(Some(1_001))
    );
    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    assert_eq!(count_rows(&maintenance).await[4], 1);
}
