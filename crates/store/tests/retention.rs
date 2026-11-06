//! Retention on Postgres: what expired is removed in every realm, what is
//! still of use stays, and the work is done by one node, under a role that
//! may do nothing else.

use pgcore::pool::PoolSettings;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE, RETENTION_ROLE};
use saffui_core::app::App;
use saffui_core::directory::Person;
use saffui_core::ids::mint_id;
use saffui_core::login::session::{AuthenticationMethod, Session, SessionState};
use saffui_core::login::store::KnownBrowser;
use saffui_core::oidc::code::{AuthorizationCode, PendingAuthorization};
use saffui_core::ports::storage::{StorageError, StorageUnavailable};
use saffui_core::retention::{PurgeOutcome, PurgeReport, run_retention_pass};
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
/// each of the seven tables retention reads.
#[expect(clippy::too_many_lines, reason = "one realm, filled table by table")]
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
    // An enrollment is kept per person: the second one is of another person.
    let other = Person {
        id: identify(),
        username: "bob".to_owned(),
        ..person.clone()
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_person(&person).await.expect("a person");
    work.insert_person(&other).await.expect("a person");
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
            methods: vec![AuthenticationMethod::Password],
            authenticated_at: now - Duration::hours(12),
            expires_at,
        };
        work.insert_session(&session).await.expect("a session");
        let enrolling = if digest == 1 { person.id } else { other.id };
        work.write_key_enrollment(enrolling, &[digest; 8], expires_at)
            .await
            .expect("an enrollment");
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
            first_factor: None,
            key_proof: None,
            consent_prompted: false,
            consent_session: None,
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

const TABLES: [&str; 7] = [
    "authorization_requests",
    "authorization_codes",
    "refresh_tokens",
    "sessions",
    "known_browsers",
    "login_failures",
    "security_key_enrollments",
];

/// What a pass removed from each table and how each came out, in the order
/// of `TABLES`.
fn summarize(
    report: Result<Option<PurgeReport>, StorageError>,
) -> Result<Option<[(u64, PurgeOutcome); 7]>, StorageError> {
    report.map(|report| {
        report.map(|report| {
            report
                .list_tables()
                .map(|(_, table)| (table.removed, table.outcome))
        })
    })
}

const DONE: PurgeOutcome = PurgeOutcome::Done;

async fn count_rows(client: &Client) -> [i64; 7] {
    let mut counted = [0; 7];
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
    assert_eq!(count_rows(&maintenance).await, [4; 7]);
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));

    let first = run_retention_pass(&retention, now, TIME_ENOUGH).await;

    assert_eq!(
        summarize(first),
        Ok(Some([(2, DONE); 7])),
        "two of each, one in each realm"
    );
    assert_eq!(
        count_rows(&maintenance).await,
        [2; 7],
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
    assert_eq!(count_rows(&maintenance).await, [2; 7]);
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
    assert_eq!(count_rows(&maintenance).await, [2; 7]);
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
                  known_browsers, login_failures, security_key_enrollments";
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
        // A right it may hand on, on a table it purges.
        (
            "GRANT SELECT ON sessions TO saffui_retention WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR SELECT ON sessions FROM saffui_retention",
        ),
        (
            "GRANT DELETE ON login_failures TO saffui_retention WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR DELETE ON login_failures FROM saffui_retention",
        ),
        // A right given to everyone is held by the role too.
        (
            "GRANT SELECT ON persons TO PUBLIC",
            "REVOKE SELECT ON persons FROM PUBLIC",
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
        // The tables are named in their schema: without it, none is reached.
        (
            "REVOKE USAGE ON SCHEMA public FROM PUBLIC",
            "GRANT USAGE ON SCHEMA public TO PUBLIC",
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

/// A schema named after the role comes first in the search path it would
/// have. A table there stands in for no purged table: the pass names them.
#[tokio::test]
async fn a_table_of_a_schema_named_after_the_role_stands_in_for_no_purged_table() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-shadowed").await;
    fill_realm(&app, scope, now).await;
    database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection")
        .batch_execute(
            "CREATE SCHEMA saffui_retention;
             CREATE TABLE saffui_retention.login_failures (bucket_start timestamptz);
             GRANT USAGE ON SCHEMA saffui_retention TO saffui_retention;",
        )
        .await
        .expect("a schema in the way");
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));

    let report = run_retention_pass(&retention, now, TIME_ENOUGH).await;

    assert_eq!(
        summarize(report).map(|report| report.map(|tables| tables[5])),
        Ok(Some((1, DONE))),
        "the counters of the product are purged"
    );
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
        matches!(run_retention_pass(&retention, now, TIME_ENOUGH).await, Ok(Some(report)) if report.codes.removed == 1),
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
        summarize(report).map(|report| report.map(|tables| tables[5])),
        Ok(Some((50_001, DONE))),
        "every full batch is followed by another"
    );
    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    assert_eq!(
        count_rows(&maintenance).await[5],
        1,
        "the counter still read stays"
    );
}

#[tokio::test]
async fn a_pass_that_spent_its_time_leaves_the_rest_to_the_next_one() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-out-of-time").await;
    plant_counters(&database, scope, 1_001, now - Duration::days(3)).await;
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));
    let counters = |report| summarize(report).map(|report| report.map(|tables| tables[5]));

    // Out of time from the start: each table gets its one batch.
    let first = run_retention_pass(&retention, now, std::time::Duration::ZERO).await;
    assert_eq!(
        counters(first),
        Ok(Some((1_000, PurgeOutcome::RowsLeft))),
        "one batch, and the rows left are said"
    );
    let next = run_retention_pass(&retention, now, std::time::Duration::ZERO).await;
    assert_eq!(
        counters(next),
        Ok(Some((1, DONE))),
        "the next pass goes on from there"
    );
}

#[tokio::test]
async fn a_table_that_fails_is_reported_and_the_pass_goes_on_with_the_others() {
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

    let mut all_but_codes = [(1, DONE); 7];
    all_but_codes[1] = (0, PurgeOutcome::Failed);
    assert_eq!(
        summarize(report),
        Ok(Some(all_but_codes)),
        "the codes are said failed, the others are purged"
    );
    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    assert_eq!(
        count_rows(&maintenance).await,
        [1, 2, 1, 1, 1, 1, 1],
        "both codes stay"
    );
}

/// Writes, in one realm, a person and two sessions that expired an hour
/// ago: one that was refreshed `refreshed` times and has its tokens still,
/// and one that never had any. Returns the first.
async fn plant_expired_sessions(
    app: &App,
    scope: RealmScope,
    now: OffsetDateTime,
    refreshed: u32,
) -> Session {
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
    let expired = |digest| Session {
        id: identify(),
        person: person.id,
        secret_digest: vec![digest; 32],
        state: SessionState::Active,
        methods: vec![AuthenticationMethod::Password],
        authenticated_at: now - Duration::hours(13),
        expires_at: now - Duration::hours(1),
    };
    let (refreshed_session, bare) = (expired(1), expired(2));
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_person(&person).await.expect("a person");
    work.insert_session(&refreshed_session)
        .await
        .expect("a session");
    work.insert_session(&bare).await.expect("a session");
    let family = identify();
    for digest in 0..=refreshed {
        work.insert_refresh_token(&RefreshToken {
            token_digest: digest.to_be_bytes().to_vec(),
            family,
            client_id: "portal".to_owned(),
            person: person.id,
            session: refreshed_session.id,
            scopes: vec!["openid".to_owned()],
            issued_at: now - Duration::hours(2),
            expires_at: refreshed_session.expires_at,
        })
        .await
        .expect("a refresh token");
    }
    work.commit().await.expect("a commit");
    refreshed_session
}

async fn count_session_and_tokens(client: &Client, session: &Session) -> (i64, i64) {
    let row = client
        .query_one(
            "SELECT (SELECT count(*) FROM sessions WHERE session_id = $1),
                    (SELECT count(*) FROM refresh_tokens WHERE session_id = $1)",
            &[&session.id],
        )
        .await
        .expect("a count");
    (row.get(0), row.get(1))
}

#[tokio::test]
async fn only_the_sessions_that_still_have_refresh_tokens_wait_for_them() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-sessions-wait").await;
    // Refreshed a thousand times: its tokens fill more than a batch.
    plant_expired_sessions(&app, scope, now, 1_000).await;
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));
    let tokens_and_sessions =
        |report| summarize(report).map(|report| report.map(|tables| (tables[2], tables[3])));

    let first = run_retention_pass(&retention, now, std::time::Duration::ZERO).await;
    assert_eq!(
        tokens_and_sessions(first),
        Ok(Some(((1_000, PurgeOutcome::RowsLeft), (1, DONE)))),
        "a token is left: its session waits, and the one without any goes"
    );
    let next = run_retention_pass(&retention, now, std::time::Duration::ZERO).await;
    assert_eq!(
        tokens_and_sessions(next),
        Ok(Some(((1, DONE), (1, DONE)))),
        "its last token gone, the session goes"
    );
}

#[tokio::test]
async fn while_refresh_tokens_fail_no_session_that_has_some_is_purged() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-tokens-fail").await;
    let refreshed = plant_expired_sessions(&app, scope, now, 3).await;
    // A batch of refresh tokens fails, as a statement that times out would.
    // A token a session would take along is let through: what holds the
    // session back is the pass, not this trigger.
    let owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    owner
        .batch_execute(
            "CREATE FUNCTION saffui_test_refuse() RETURNS trigger LANGUAGE plpgsql
                 AS $$ BEGIN
                     IF pg_trigger_depth() = 1 THEN RAISE EXCEPTION 'refused'; END IF;
                     RETURN OLD;
                 END $$;
             CREATE TRIGGER saffui_test_refuse BEFORE DELETE ON refresh_tokens
                 FOR EACH ROW EXECUTE FUNCTION saffui_test_refuse();",
        )
        .await
        .expect("a refusing trigger");
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));

    let report = run_retention_pass(&retention, now, TIME_ENOUGH).await;

    assert_eq!(
        summarize(report).map(|report| report.map(|tables| (tables[2], tables[3]))),
        Ok(Some(((0, PurgeOutcome::Failed), (1, DONE)))),
        "the session without tokens goes, the other waits"
    );
    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    assert_eq!(
        count_session_and_tokens(&maintenance, &refreshed).await,
        (1, 4),
        "the session that has tokens stays, and its tokens with it"
    );
}

/// Makes every statement that removes from `table` wait `seconds` first.
async fn slow_down_removals(database: &pgcore::testkit::TestDatabase, table: &str, seconds: f64) {
    database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection")
        .batch_execute(&format!(
            "CREATE FUNCTION saffui_test_slow() RETURNS trigger LANGUAGE plpgsql
                 AS $$ BEGIN PERFORM pg_sleep({seconds}); RETURN NULL; END $$;
             CREATE TRIGGER saffui_test_slow BEFORE DELETE ON {table}
                 FOR EACH STATEMENT EXECUTE FUNCTION saffui_test_slow();"
        ))
        .await
        .expect("a slow trigger");
}

/// Writes, as the owner would, `count` pending requests that expired.
async fn plant_expired_requests(
    database: &pgcore::testkit::TestDatabase,
    scope: RealmScope,
    count: i32,
    now: OffsetDateTime,
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
            "INSERT INTO authorization_requests (tenant_id, realm_id, request_id, browser_digest,
                 client_id, redirect_uri, scopes, code_challenge, consent_prompted, expires_at)
             SELECT $1, $2, gen_random_uuid(), int4send(n), 'portal', 'https://app.example.org/cb',
                    '{}', 'c', false, $3
             FROM generate_series(1, $4) AS n",
            &[&tenant, &realm, &(now - Duration::minutes(1)), &count],
        )
        .await
        .expect("the requests");
    planting.commit().await.expect("a commit");
}

/// Pending requests are written without signing in: anybody can flood them.
/// The pass gives them their part and goes on, so that the tables after them
/// still empty.
#[tokio::test]
async fn a_table_anybody_can_fill_spends_its_own_part_of_the_pass_and_no_more() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-flooded").await;
    // More requests than the whole pass could remove, at half a second a batch.
    plant_expired_requests(&database, scope, 7_001, now).await;
    slow_down_removals(&database, "authorization_requests", 0.5).await;
    plant_counters(&database, scope, 2_001, now - Duration::days(3)).await;
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));

    let report = run_retention_pass(&retention, now, std::time::Duration::from_secs(3)).await;

    let report = summarize(report)
        .expect("a pass")
        .expect("the lock was free");
    assert_eq!(
        report[0].1,
        PurgeOutcome::RowsLeft,
        "the requests spend their part"
    );
    assert!(report[0].0 < 6_000, "and not the whole pass: {report:?}");
    assert_eq!(
        report[5],
        (2_001, DONE),
        "the counters, after the requests, still get their part of what is left: {report:?}"
    );
}

#[tokio::test]
async fn a_pass_whose_every_table_fails_is_a_failure() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-all-fail").await;
    fill_realm(&app, scope, now).await;
    // Each statement fails, whether it finds rows or not.
    let triggers = TABLES
        .map(|table| {
            format!(
                "CREATE TRIGGER saffui_test_refuse BEFORE DELETE ON {table}
                     FOR EACH STATEMENT EXECUTE FUNCTION saffui_test_refuse();"
            )
        })
        .concat();
    database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection")
        .batch_execute(&format!(
            "CREATE FUNCTION saffui_test_refuse() RETURNS trigger LANGUAGE plpgsql
                 AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$;
             {triggers}"
        ))
        .await
        .expect("refusing triggers");
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));

    assert_eq!(
        run_retention_pass(&retention, now, TIME_ENOUGH).await,
        Err(StorageError::Failed),
        "a pass that removed nothing anywhere failed"
    );
}

#[tokio::test]
async fn a_pass_whose_link_closes_is_a_failure_and_stops_there() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let now = app.now();
    let scope = create_realm(&app, "retention-link-closes").await;
    fill_realm(&app, scope, now).await;
    // The first removal ends the session that runs it.
    database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection")
        .batch_execute(
            "CREATE FUNCTION saffui_test_hang_up() RETURNS trigger LANGUAGE plpgsql
                 AS $$ BEGIN PERFORM pg_terminate_backend(pg_backend_pid()); RETURN OLD; END $$;
             CREATE TRIGGER saffui_test_hang_up BEFORE DELETE ON authorization_requests
                 FOR EACH ROW EXECUTE FUNCTION saffui_test_hang_up();",
        )
        .await
        .expect("a trigger that hangs up");
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));

    assert_eq!(
        run_retention_pass(&retention, now, TIME_ENOUGH).await,
        Err(StorageError::Unavailable(StorageUnavailable::Unreachable)),
        "a pass that lost its link failed"
    );
    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    assert_eq!(
        count_rows(&maintenance).await,
        [2; 7],
        "nothing was removed after the link closed"
    );
}

/// A browser kept again while a batch waits on it lives longer: the batch
/// that found it expired asks again, and leaves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_made_to_live_longer_while_its_batch_waits_stays() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    keep_a_browser_again_while_its_batch_waits(&app, &database).await;
}

/// Asking again is what read committed does: the pass says its level.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_made_to_live_longer_while_its_batch_waits_stays_under_a_repeatable_read_default() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    database.default_transactions_to_repeatable_read().await;
    keep_a_browser_again_while_its_batch_waits(&app, &database).await;
}

/// Keeps the browser that expired again while the batch of browsers waits
/// on it, and checks that the pass leaves it.
async fn keep_a_browser_again_while_its_batch_waits(
    app: &App,
    database: &pgcore::testkit::TestDatabase,
) {
    use std::time::{Duration as Wait, Instant};

    let now = app.now();
    let scope = create_realm(app, "retention-kept-again").await;
    fill_realm(app, scope, now).await;
    // The browser that expired is kept again, in a transaction still open.
    let mut owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    let keeping = owner.transaction().await.expect("a transaction");
    keeping
        .execute(
            "SELECT set_config('saffui.tenant', $1, true), set_config('saffui.realm', $2, true)",
            &[
                &scope.tenant().as_uuid().to_string(),
                &scope.realm().as_uuid().to_string(),
            ],
        )
        .await
        .expect("the scope");
    let kept_again = keeping
        .execute(
            "UPDATE known_browsers SET expires_at = $1 WHERE expires_at < $2",
            &[&(now + Duration::days(30)), &now],
        )
        .await
        .expect("a browser kept again");
    assert_eq!(kept_again, 1, "the browser that expired");
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));
    let pass = tokio::spawn(async move { run_retention_pass(&retention, now, TIME_ENOUGH).await });
    // Seen by the sessions of retention, which wait on the row held here.
    let observer = database
        .plan(RETENTION_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    let deadline = Instant::now() + Wait::from_secs(10);
    loop {
        let waiting: i64 = observer
            .query_one(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname = current_database() AND wait_event_type = 'Lock'",
                &[],
            )
            .await
            .expect("a count")
            .get(0);
        if waiting > 0 || pass.is_finished() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the batch never waited on the row"
        );
        tokio::time::sleep(Wait::from_millis(10)).await;
    }
    assert!(
        !pass.is_finished(),
        "the batch of browsers waits on the row"
    );
    keeping.commit().await.expect("a commit");

    let report = pass.await.expect("the pass");

    assert_eq!(
        summarize(report).map(|report| report.map(|tables| tables[4])),
        Ok(Some((0, DONE))),
        "the browser kept again is not removed"
    );
    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    assert_eq!(count_rows(&maintenance).await[4], 2, "both browsers stay");
}
