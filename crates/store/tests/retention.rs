//! Retention on Postgres: what expired is removed in every realm, what is
//! still of use stays, and the work is done by one node, under a role that
//! may do nothing else.

use pgcore::pool::PoolSettings;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE, RETENTION_ROLE};
use saffui_core::app::App;
use saffui_core::directory::Person;
use saffui_core::ids::mint_id;
use saffui_core::login::session::{Session, SessionState};
use saffui_core::login::store::KnownBrowser;
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

/// More than any of these passes needs.
const TIME_ENOUGH: std::time::Duration = std::time::Duration::from_mins(1);

/// Writes, in one realm, a row past its keeping and a row still of use in
/// each of the six tables retention reads.
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
        work.remember_browser(
            &KnownBrowser {
                device: identify(),
                person: person.id,
                expires_at,
            },
            10,
        )
        .await
        .expect("a known browser");
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

const TABLES: [&str; 6] = [
    "authorization_requests",
    "authorization_codes",
    "refresh_tokens",
    "sessions",
    "known_browsers",
    "login_failures",
];

async fn count_rows(client: &Client) -> [i64; 6] {
    let mut counted = [0; 6];
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
    assert_eq!(count_rows(&maintenance).await, [4; 6]);
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));

    let first = run_retention_pass(&retention, now, TIME_ENOUGH).await;

    let two_of_each = PurgeReport {
        pending_requests: 2,
        codes: 2,
        refresh_tokens: 2,
        sessions: 2,
        known_browsers: 2,
        failure_counters: 2,
    };
    assert_eq!(first, Ok(Some(two_of_each)));
    assert_eq!(
        count_rows(&maintenance).await,
        [2; 6],
        "what is still of use stays, in both realms"
    );
    assert_eq!(
        run_retention_pass(&retention, now, TIME_ENOUGH).await,
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

    let refused = run_retention_pass(&under_the_serving_role, now, TIME_ENOUGH).await;

    assert_eq!(refused, Err(StorageError::Failed));
    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    assert_eq!(count_rows(&maintenance).await, [2; 6]);
}

#[tokio::test]
async fn a_pass_under_a_role_that_may_do_more_than_purge_is_refused_and_removes_nothing() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-too-much").await;
    fill_realm(&app, scope, now).await;
    // It bypasses row security as retention does, and writes tenants.
    let under_maintenance = PgRetention::new(database.plan(MAINTENANCE_ROLE));

    assert_eq!(
        run_retention_pass(&under_maintenance, now, TIME_ENOUGH).await,
        Err(StorageError::Failed)
    );
    assert_eq!(
        under_maintenance.verify_role().await,
        Err(StorageError::Failed)
    );
    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    assert_eq!(count_rows(&maintenance).await, [2; 6]);
    let under_retention = PgRetention::new(database.plan(RETENTION_ROLE));
    assert_eq!(under_retention.verify_role().await, Ok(()));
}

#[tokio::test]
async fn a_retention_role_with_any_right_beyond_purging_is_refused() {
    let (_app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    let purged = "authorization_requests, authorization_codes, refresh_tokens, sessions, \
                  known_browsers, login_failures";
    // Each bypasses row security as retention does, and holds one thing more.
    for role in [
        "saffui_test_retention_reads_all",
        "saffui_test_retention_creates_roles",
        "saffui_test_retention_replicates",
        "saffui_test_retention_runs_programs",
        "saffui_test_retention_noinherit_owner",
        "saffui_test_retention_creates_databases",
    ] {
        owner
            .batch_execute(&format!("GRANT SELECT, DELETE ON {purged} TO {role}"))
            .await
            .expect("the rights of retention");
        assert_eq!(
            PgRetention::new(database.plan(role)).verify_role().await,
            Err(StorageError::Failed),
            "{role}"
        );
    }
    // The retention role itself, given one right more, then none.
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));
    owner
        .batch_execute("CREATE SEQUENCE saffui_test_counter")
        .await
        .expect("a sequence");
    let on_the_database = (
        format!(
            "GRANT CREATE ON DATABASE \"{}\" TO saffui_retention",
            database.name()
        ),
        format!(
            "REVOKE CREATE ON DATABASE \"{}\" FROM saffui_retention",
            database.name()
        ),
    );
    for (given, taken) in [
        (on_the_database.0.as_str(), on_the_database.1.as_str()),
        (
            "GRANT USAGE ON SEQUENCE saffui_test_counter TO saffui_retention",
            "REVOKE USAGE ON SEQUENCE saffui_test_counter FROM saffui_retention",
        ),
        (
            "GRANT SELECT ON persons TO saffui_retention",
            "REVOKE SELECT ON persons FROM saffui_retention",
        ),
        (
            "GRANT SELECT (username) ON persons TO saffui_retention",
            "REVOKE SELECT (username) ON persons FROM saffui_retention",
        ),
        (
            "GRANT UPDATE (used_at) ON refresh_tokens TO saffui_retention",
            "REVOKE UPDATE (used_at) ON refresh_tokens FROM saffui_retention",
        ),
        (
            "GRANT CREATE ON SCHEMA public TO saffui_retention",
            "REVOKE CREATE ON SCHEMA public FROM saffui_retention",
        ),
        (
            "GRANT EXECUTE ON FUNCTION saffui_locate_realm(text) TO saffui_retention",
            "REVOKE EXECUTE ON FUNCTION saffui_locate_realm(text) FROM saffui_retention",
        ),
    ] {
        owner.batch_execute(given).await.expect("a right more");
        assert_eq!(
            retention.verify_role().await,
            Err(StorageError::Failed),
            "{given}"
        );
        owner
            .batch_execute(taken)
            .await
            .expect("the right taken back");
        assert_eq!(retention.verify_role().await, Ok(()), "{taken}");
    }
}

#[tokio::test]
async fn a_retention_role_that_may_not_read_and_remove_every_purged_table_is_refused() {
    let (_app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    // It bypasses row security as retention does, and was given nothing.
    assert_eq!(
        PgRetention::new(database.plan("saffui_test_retention_holds_nothing"))
            .verify_role()
            .await,
        Err(StorageError::Failed)
    );
    // The retention role itself, one right short on one table, then whole.
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));
    for (taken, given) in [
        (
            "REVOKE DELETE ON known_browsers FROM saffui_retention",
            "GRANT DELETE ON known_browsers TO saffui_retention",
        ),
        (
            "REVOKE SELECT ON sessions FROM saffui_retention",
            "GRANT SELECT ON sessions TO saffui_retention",
        ),
    ] {
        owner.batch_execute(taken).await.expect("a right taken");
        assert_eq!(
            retention.verify_role().await,
            Err(StorageError::Failed),
            "{taken}"
        );
        owner
            .batch_execute(given)
            .await
            .expect("the right given back");
        assert_eq!(retention.verify_role().await, Ok(()), "{given}");
    }
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
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));

    let left_alone = run_retention_pass(&retention, now, TIME_ENOUGH).await;

    assert_eq!(left_alone, Ok(None));
    holding.rollback().await.expect("the lock released");
    assert!(
        matches!(run_retention_pass(&retention, now, TIME_ENOUGH).await, Ok(Some(report)) if report.codes == 1),
        "once the lock is free the pass runs"
    );
}

/// Writes, as the owner would, `count` counters of the brake whose bucket
/// started at `bucket_start`, in one statement.
async fn plant_counters(
    database: &pgcore::testkit::TestDatabase,
    scope: RealmScope,
    count: i32,
    bucket_start: OffsetDateTime,
) {
    let mut owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    let (tenant, realm) = (scope.tenant().as_uuid(), scope.realm().as_uuid());
    let planting = owner.transaction().await.expect("a transaction");
    planting
        .execute(
            "SELECT set_config('saffui.tenant', $1, true), set_config('saffui.realm', $2, true)",
            &[&tenant.to_string(), &realm.to_string()],
        )
        .await
        .expect("the scope");
    planting
        .execute(
            "INSERT INTO login_failures (tenant_id, realm_id, identifier_digest, bucket_start, failures)
             SELECT $1, $2, int4send(n), $3, 1 FROM generate_series(1, $4) AS n",
            &[&tenant, &realm, &bucket_start, &count],
        )
        .await
        .expect("the counters");
    planting.commit().await.expect("a commit");
}

#[tokio::test]
async fn a_pass_goes_on_while_its_batches_come_back_full_and_still_leaves_what_is_of_use() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-batches").await;
    // Fifty-one batches of old counters, and one counter that is still read.
    plant_counters(&database, scope, 50_001, now - Duration::days(3)).await;
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.record_login_failure(&[9; 32], now - Duration::minutes(3))
        .await
        .expect("a recent counter");
    work.commit().await.expect("a commit");
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));

    let report = run_retention_pass(&retention, now, TIME_ENOUGH).await;

    assert_eq!(
        report.map(|report| report.map(|report| report.failure_counters)),
        Ok(Some(50_001))
    );
    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    assert_eq!(count_rows(&maintenance).await[5], 1);
}

#[tokio::test]
async fn a_pass_that_spent_its_time_leaves_the_rest_to_the_next_one() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-out-of-time").await;
    plant_counters(&database, scope, 1_001, now - Duration::days(3)).await;
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));
    let removed = |report: Result<Option<PurgeReport>, StorageError>| {
        report.map(|report| report.map(|report| report.failure_counters))
    };

    // Out of time from the start: each table gets its one batch.
    let first = run_retention_pass(&retention, now, std::time::Duration::ZERO).await;
    assert_eq!(removed(first), Ok(Some(1_000)));
    let next = run_retention_pass(&retention, now, std::time::Duration::ZERO).await;
    assert_eq!(removed(next), Ok(Some(1)));
}

#[tokio::test]
async fn a_table_that_fails_is_said_and_the_pass_goes_on_with_the_others() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-one-fails").await;
    fill_realm(&app, scope, now).await;
    let owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    // Every removal of a code fails, as a statement that times out would.
    owner
        .batch_execute(
            "CREATE FUNCTION saffui_test_refuse() RETURNS trigger LANGUAGE plpgsql
                 AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$;
             CREATE TRIGGER saffui_test_refuse BEFORE DELETE ON authorization_codes
                 FOR EACH ROW EXECUTE FUNCTION saffui_test_refuse();",
        )
        .await
        .expect("a refusing trigger");
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));

    let report = run_retention_pass(&retention, now, TIME_ENOUGH).await;

    let all_but_codes = PurgeReport {
        pending_requests: 1,
        codes: 0,
        refresh_tokens: 1,
        sessions: 1,
        known_browsers: 1,
        failure_counters: 1,
    };
    assert_eq!(report, Ok(Some(all_but_codes)));
    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    assert_eq!(count_rows(&maintenance).await, [1, 2, 1, 1, 1, 1]);
}

#[tokio::test]
async fn sessions_wait_until_their_refresh_tokens_are_gone() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-sessions-wait").await;
    let identify = || mint_id(&app).expect("an identifier");
    let person = Person {
        id: identify(),
        username: "ada".to_owned(),
        email: None,
        email_verified: false,
        display_name: None,
        enabled: true,
        created_at: now,
    };
    let session = Session {
        id: identify(),
        person: person.id,
        secret_digest: vec![1; 32],
        state: SessionState::Active,
        authenticated_at: now - Duration::hours(13),
        expires_at: now - Duration::hours(1),
    };
    // A session refreshed a thousand times and once more: its tokens fill
    // more than a batch.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_person(&person).await.expect("a person");
    work.insert_session(&session).await.expect("a session");
    let family = identify();
    for digest in 0..1_001_u32 {
        work.insert_refresh_token(&RefreshToken {
            token_digest: digest.to_be_bytes().to_vec(),
            family,
            client_id: "portal".to_owned(),
            person: person.id,
            session: session.id,
            scopes: vec!["openid".to_owned()],
            issued_at: now - Duration::hours(2),
            expires_at: session.expires_at,
        })
        .await
        .expect("a refresh token");
    }
    work.commit().await.expect("a commit");
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));
    let removed = |report: Result<Option<PurgeReport>, StorageError>| {
        report.map(|report| report.map(|report| (report.refresh_tokens, report.sessions)))
    };

    let first = run_retention_pass(&retention, now, std::time::Duration::ZERO).await;
    assert_eq!(
        removed(first),
        Ok(Some((1_000, 0))),
        "a token is left: the session waits"
    );
    let next = run_retention_pass(&retention, now, std::time::Duration::ZERO).await;
    assert_eq!(removed(next), Ok(Some((1, 1))));
}
