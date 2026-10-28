//! The runner against a real Postgres: what only a server can prove.

use std::time::Duration;

use pgcore::connect::ConnectionPlan;
use pgcore::lock::{MIGRATION_LOCK, SessionLock};
use pgcore::migrate::plan::PlanError;
use pgcore::migrate::window::SchemaWindow;
use pgcore::migrate::{MigrateError, Migration, apply_pending};
use pgcore::pool::{PoolSettings, build_pool};
use pgcore::probe::{ProbeFailure, probe_database};
use pgcore::role::{read_role_facts, refuse_privileged_role};
use pgcore::testkit::TestDatabase;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE};

const OWNER: &str = "saffui_owner";
const NOTES: Migration = Migration {
    version: 1,
    name: "0001_notes",
    sql: "CREATE TABLE notes (id integer PRIMARY KEY, body text NOT NULL); GRANT SELECT ON notes TO saffui_app",
};
const NOTES_AUTHOR: Migration = Migration {
    version: 2,
    name: "0002_notes_author",
    sql: "ALTER TABLE notes ADD COLUMN author text;",
};
const BROKEN: Migration = Migration {
    version: 2,
    name: "0002_broken",
    sql: "ALTER TABLE notes ADD COLUMN author text; SELECT * FROM np_such_table;",
};

async fn count_columns(plan: &ConnectionPlan, table: &str) -> i64 {
    let client = plan.connect_directly().await.expect("a connection");
    client
        .query_one(
            "SELECT count(*) FROM information_schema.columns WHERE table_name = $1",
            &[&table],
        )
        .await
        .expect("the column count")
        .get(0)
}

#[tokio::test]
async fn migrations_apply_from_nothing_and_a_second_run_applies_nothing() {
    let database = TestDatabase::create(&[]).await;
    let owner = database.plan(OWNER);
    let first = apply_pending(&owner, &[NOTES, NOTES_AUTHOR])
        .await
        .expect("a first run");
    assert_eq!(first.applied, vec![1, 2]);
    assert_eq!(first.schema_version, 2);
    let second = apply_pending(&owner, &[NOTES, NOTES_AUTHOR])
        .await
        .expect("a second run");
    assert_eq!(second.applied, Vec::<i32>::new(), "nothing was pending");
    assert_eq!(second.schema_version, 2);
}

#[tokio::test]
async fn a_failed_migration_leaves_nothing_of_itself() {
    let database = TestDatabase::create(&[NOTES]).await;
    let owner = database.plan(OWNER);
    let failed = apply_pending(&owner, &[NOTES, BROKEN]).await;
    assert!(
        matches!(failed, Err(MigrateError::Failed { version: 2, .. })),
        "{failed:?}"
    );
    assert_eq!(
        count_columns(&owner, "notes").await,
        2,
        "the column the failed migration added is gone with it"
    );
}

#[tokio::test]
async fn a_migration_edited_after_it_was_applied_is_refused() {
    let database = TestDatabase::create(&[NOTES]).await;
    let edited = Migration {
        sql: "CREATE TABLE notes (id integer PRIMARY KEY);",
        ..NOTES
    };
    let refused = apply_pending(&database.plan(OWNER), &[edited]).await;
    assert!(
        matches!(
            refused,
            Err(MigrateError::Plan(PlanError::Drift { version: 1 })),
        ),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_binary_older_than_the_schema_refuses_to_migrate() {
    let database = TestDatabase::create(&[NOTES, NOTES_AUTHOR]).await;

    let refused = apply_pending(&database.plan(OWNER), &[NOTES]).await;

    assert!(
        matches!(
            refused,
            Err(MigrateError::Plan(PlanError::Ahead { version: 2 }))
        ),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_second_runner_is_refused_while_the_first_holds_the_lock() {
    let database = TestDatabase::create(&[]).await;
    let owner = database.plan(OWNER);
    let holder = owner.connect_directly().await.expect("a connection");
    let held = SessionLock::try_acquire(holder, MIGRATION_LOCK)
        .await
        .expect("the lock, free at first");

    let refused = apply_pending(&owner, &[NOTES]).await;
    assert!(
        matches!(refused, Err(MigrateError::AlreadyRunning)),
        "{refused:?}"
    );

    held.release().await.expect("the lock released");
    let applied = apply_pending(&owner, &[NOTES]).await.expect("a run alone");
    assert_eq!(applied.applied, vec![1]);
}

#[tokio::test]
async fn the_probe_tells_a_schema_behind_from_a_schema_ahead() {
    let database = TestDatabase::create(&[NOTES]).await;
    let pool = build_pool(&database.plan(APP_ROLE), PoolSettings::default()).expect("a pool");
    let patience = Duration::from_secs(2);
    let probe = |oldest, newest| probe_database(&pool, SchemaWindow { oldest, newest }, patience);

    assert_eq!(probe(1, 1).await, Ok(()));
    assert_eq!(
        probe(2, 2).await,
        Err(ProbeFailure::SchemaBehind {
            found: 1,
            oldest: 2
        })
    );
    assert_eq!(
        probe(0, 0).await,
        Err(ProbeFailure::SchemaAhead {
            found: 1,
            newest: 0
        })
    );
}

#[tokio::test]
async fn a_database_that_was_never_migrated_is_at_version_zero() {
    let database = TestDatabase::create(&[]).await;
    let pool = build_pool(&database.plan(APP_ROLE), PoolSettings::default()).expect("a pool");

    let behind = probe_database(
        &pool,
        SchemaWindow {
            oldest: 1,
            newest: 1,
        },
        Duration::from_secs(2),
    )
    .await;

    assert_eq!(
        behind,
        Err(ProbeFailure::SchemaBehind {
            found: 0,
            oldest: 1
        })
    );
}

#[tokio::test]
async fn the_probe_says_when_nothing_answers() {
    let nowhere = pgcore::connect::plan_connection(
        "host=127.0.0.1 port=1 user=saffui_app dbname=saffui",
        None,
        None,
    )
    .expect("a loopback plan");
    let pool = build_pool(&nowhere, PoolSettings::default()).expect("a pool");

    let failure = probe_database(
        &pool,
        SchemaWindow {
            oldest: 0,
            newest: 0,
        },
        Duration::from_secs(2),
    )
    .await;

    assert_eq!(failure, Err(ProbeFailure::Unreachable));
}

#[tokio::test]
async fn the_probe_says_when_the_database_refuses() {
    let database = TestDatabase::create(&[]).await;
    let unknown_database = pgcore::connect::plan_connection(
        &database
            .connection_string(APP_ROLE)
            .replace(database.name(), "saffui_no_such_database"),
        None,
        None,
    )
    .expect("a loopback plan");
    let pool = build_pool(&unknown_database, PoolSettings::default()).expect("a pool");

    let failure = probe_database(
        &pool,
        SchemaWindow {
            oldest: 0,
            newest: 0,
        },
        Duration::from_secs(2),
    )
    .await;

    assert_eq!(failure, Err(ProbeFailure::Refused));
}

#[tokio::test]
async fn the_probe_says_when_every_connection_is_taken() {
    let database = TestDatabase::create(&[]).await;
    let one_connection = PoolSettings {
        max_size: 1,
        ..PoolSettings::default()
    };
    let pool = build_pool(&database.plan(APP_ROLE), one_connection).expect("a pool");
    let _taken = pool.get().await.expect("the only connection");

    let failure = probe_database(
        &pool,
        SchemaWindow {
            oldest: 0,
            newest: 0,
        },
        Duration::from_millis(200),
    )
    .await;

    assert_eq!(failure, Err(ProbeFailure::PoolExhausted));
}

#[tokio::test]
async fn the_serving_role_passes_the_role_check_and_the_maintenance_role_does_not() {
    let database = TestDatabase::create(&[]).await;

    let app = database
        .plan(APP_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    let app_facts = read_role_facts(&app).await.expect("the facts of the role");
    assert_eq!(app_facts.name, APP_ROLE);
    assert!(refuse_privileged_role(&app_facts).is_ok());

    let maintenance = database
        .plan(MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    let maintenance_facts = read_role_facts(&maintenance)
        .await
        .expect("the facts of the role");
    assert!(
        refuse_privileged_role(&maintenance_facts).is_err(),
        "a role that bypasses row security must not serve"
    );
}

#[tokio::test]
async fn a_pooled_session_comes_back_without_the_transaction_or_the_settings_of_its_last_borrower()
{
    let database = TestDatabase::create(&[]).await;
    let one_connection = PoolSettings {
        max_size: 1,
        ..PoolSettings::default()
    };
    let pool = build_pool(&database.plan(APP_ROLE), one_connection).expect("a pool");

    {
        let first = pool.get().await.expect("the connection");
        first
            .batch_execute(
                "SET saffui.tenant = 'left-behind'; BEGIN; CREATE TEMP TABLE left_behind (id integer)",
            )
            .await
            .expect("a setting and an open transaction left behind");
    }
    let second = pool.get().await.expect("the same connection again");
    let row = second
        .query_one(
            "SELECT current_setting('saffui.tenant', true), to_regclass('pg_temp.left_behind') IS NULL",
            &[],
        )
        .await
        .expect("the session state");

    let setting: Option<String> = row.get(0);
    assert!(
        setting.is_none_or(|value| value.is_empty()),
        "the setting of the previous borrower is gone"
    );
    let rolled_back: bool = row.get(1);
    assert!(
        rolled_back,
        "the transaction of the previous borrower was rolled back"
    );
}
