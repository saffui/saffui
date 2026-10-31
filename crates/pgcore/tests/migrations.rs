//! The runner against a real Postgres: what only a server can prove.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use pgcore::connect::{ConnectionPlan, TlsMode, plan_connection};
use pgcore::lock::{MIGRATION_LOCK, SessionLock};
use pgcore::migrate::plan::PlanError;
use pgcore::migrate::window::SchemaWindow;
use pgcore::migrate::{MigrateError, Migration, apply_pending};
use pgcore::pool::{PoolSettings, build_pool};
use pgcore::probe::{ProbeFailure, probe_database};
use pgcore::role::{Privilege, read_role_facts, refuse_privileged_role};
use pgcore::testkit::TestDatabase;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_postgres::error::SqlState;

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
    sql: "ALTER TABLE notes ADD COLUMN author text; SELECT * FROM no_such_table;",
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
async fn a_role_that_bypasses_row_security_does_not_run_the_migrations() {
    let database = TestDatabase::create(&[]).await;

    for role in ["postgres", "saffui_test_superuser_only", MAINTENANCE_ROLE] {
        let refused = apply_pending(&database.plan(role), &[NOTES]).await;
        assert!(
            matches!(&refused, Err(MigrateError::RunnerBypassesRowSecurity(name)) if name == role),
            "{role}: {refused:?}"
        );
    }
    let applied = apply_pending(&database.plan(OWNER), &[NOTES])
        .await
        .expect("a run under the owner");
    assert_eq!(applied.applied, vec![1], "the refused runs applied nothing");
    wait_for_superuser_sessions_to_end(&database).await;
}

#[tokio::test]
async fn a_member_of_a_role_that_bypasses_row_security_runs_the_migrations_as_itself() {
    let database = TestDatabase::create(&[]).await;
    let superuser = database
        .plan("postgres")
        .connect_directly()
        .await
        .expect("a connection");
    superuser
        .batch_execute(
            "GRANT CREATE ON SCHEMA public TO saffui_test_member_of_maintenance;
             GRANT INSERT ON schema_migrations TO saffui_test_member_of_maintenance;",
        )
        .await
        .expect("the rights of a runner");
    drop(superuser);

    // Its functions would run with its own attributes, which bypass nothing.
    let applied = apply_pending(
        &database.plan("saffui_test_member_of_maintenance"),
        &[NOTES],
    )
    .await
    .expect("a run under a mere member");
    assert_eq!(applied.applied, vec![1]);
    wait_for_superuser_sessions_to_end(&database).await;
}

#[tokio::test]
async fn a_database_without_public_refuses_the_migrations_instead_of_keeping_them_for_a_session() {
    let database = TestDatabase::create(&[]).await;
    let owner = database.plan(OWNER);
    owner
        .connect_directly()
        .await
        .expect("a connection")
        .batch_execute("DROP SCHEMA public CASCADE")
        .await
        .expect("public gone");

    let refused = apply_pending(&owner, &[NOTES]).await;

    assert!(
        matches!(&refused, Err(MigrateError::Database(error))
            if error.code() == Some(&SqlState::INVALID_SCHEMA_NAME)),
        "{refused:?}"
    );
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
async fn the_probe_says_a_lock_waited_for_past_its_bound_is_a_time_out() {
    let database = TestDatabase::create(&[]).await;
    let owner = database
        .plan(OWNER)
        .connect_directly()
        .await
        .expect("a connection");
    owner
        .batch_execute("BEGIN; LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE")
        .await
        .expect("the history locked");
    let settings = PoolSettings {
        max_size: 1,
        wait_timeout: Duration::from_millis(300),
        ..PoolSettings::default()
    };
    let pool = build_pool(&database.plan(APP_ROLE), settings).expect("a pool");

    let failure = probe_database(
        &pool,
        SchemaWindow {
            oldest: 0,
            newest: 0,
        },
        Duration::from_secs(5),
    )
    .await;
    owner
        .batch_execute("ROLLBACK")
        .await
        .expect("the lock let go");

    assert_eq!(failure, Err(ProbeFailure::TimedOut), "busy, not refused");
}

#[tokio::test]
async fn a_probe_that_gave_up_leaves_no_statement_waiting_behind_it() {
    let database = TestDatabase::create(&[]).await;
    let owner = database
        .plan(OWNER)
        .connect_directly()
        .await
        .expect("a connection");
    owner
        .batch_execute("BEGIN; LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE")
        .await
        .expect("the history locked");
    // The pool bounds a lock at 5 s, past the patience of the probe.
    let one_connection = PoolSettings {
        max_size: 1,
        ..PoolSettings::default()
    };
    let pool = build_pool(&database.plan(APP_ROLE), one_connection).expect("a pool");

    let failure = probe_database(
        &pool,
        SchemaWindow {
            oldest: 0,
            newest: 0,
        },
        Duration::from_millis(300),
    )
    .await;
    let started = Instant::now();
    pool.get()
        .await
        .expect("a connection")
        .query_one("SELECT 1", &[])
        .await
        .expect("an answer");
    let waited = started.elapsed();
    // Only a superuser sees what the sessions of another role wait on.
    let sessions: (i64, i64) = {
        let row = database
            .plan("postgres")
            .connect_directly()
            .await
            .expect("a connection")
            .query_one(
                &format!(
                    "SELECT count(*), count(*) FILTER (WHERE wait_event_type = 'Lock') \
                     FROM pg_stat_activity \
                     WHERE datname = current_database() AND usename = '{APP_ROLE}'"
                ),
                &[],
            )
            .await
            .expect("the sessions of the serving role");
        (row.get(0), row.get(1))
    };
    owner
        .batch_execute("ROLLBACK")
        .await
        .expect("the lock let go");

    assert_eq!(failure, Err(ProbeFailure::TimedOut));
    assert!(
        waited < Duration::from_secs(1),
        "the next borrower waited {waited:?} behind the probe"
    );
    assert_eq!(
        sessions,
        (1, 0),
        "one session for a pool of one, and none waiting on the lock"
    );
    wait_for_superuser_sessions_to_end(&database).await;
}

/// A relay to the cluster that stops passing the answers of the server on a
/// connection once its client sets `statement_timeout`: a link gone silent.
struct SilencingRelay {
    port: u16,
    /// How many connections it has silenced.
    silenced: Arc<AtomicUsize>,
}

async fn start_silencing_relay(cluster: (String, u16)) -> SilencingRelay {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let silenced = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&silenced);
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(relay_one_connection(
                client,
                cluster.clone(),
                Arc::clone(&counted),
            ));
        }
    });
    SilencingRelay { port, silenced }
}

async fn relay_one_connection(
    client: TcpStream,
    cluster: (String, u16),
    counted: Arc<AtomicUsize>,
) {
    let Ok(server) = TcpStream::connect((cluster.0.as_str(), cluster.1)).await else {
        return;
    };
    let (mut from_client, mut to_client) = client.into_split();
    let (mut from_server, mut to_server) = server.into_split();
    let silenced = Arc::new(AtomicBool::new(false));
    let heard = Arc::clone(&silenced);
    let upstream = async move {
        let mut buffer = [0_u8; 8192];
        while let Ok(read) = from_client.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            if !heard.load(Ordering::SeqCst)
                && buffer[..read]
                    .windows(b"statement_timeout".len())
                    .any(|window| window == b"statement_timeout")
            {
                heard.store(true, Ordering::SeqCst);
                counted.fetch_add(1, Ordering::SeqCst);
            }
            if to_server.write_all(&buffer[..read]).await.is_err() {
                break;
            }
        }
    };
    let downstream = async move {
        let mut buffer = [0_u8; 8192];
        while let Ok(read) = from_server.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            if !silenced.load(Ordering::SeqCst)
                && to_client.write_all(&buffer[..read]).await.is_err()
            {
                break;
            }
        }
    };
    tokio::join!(upstream, downstream);
}

#[tokio::test]
async fn a_probe_that_hears_nothing_back_does_not_give_its_connection_back() {
    let database = TestDatabase::create(&[]).await;
    let direct = database.connection_string(APP_ROLE);
    let field = |key: &str| {
        direct
            .split_whitespace()
            .find_map(|field| field.strip_prefix(key))
            .expect("a field of the connection string")
            .to_owned()
    };
    let (host, port) = (field("host="), field("port="));
    let relay = start_silencing_relay((host.clone(), port.parse().expect("a port"))).await;
    let through_relay = direct.replace(
        &format!("host={host} port={port}"),
        &format!("host=127.0.0.1 port={}", relay.port),
    );
    let plan = plan_connection(&through_relay, Some(TlsMode::Disable), None).expect("a plan");
    // Patient: a silent connection given back would hold its next borrower
    // longer than this test waits for it.
    let patient_pool = PoolSettings {
        max_size: 1,
        wait_timeout: Duration::from_mins(1),
        ..PoolSettings::default()
    };
    let pool = build_pool(&plan, patient_pool).expect("a pool");

    let failure = probe_database(
        &pool,
        SchemaWindow {
            oldest: 0,
            newest: 0,
        },
        Duration::from_millis(300),
    )
    .await;
    let next = tokio::time::timeout(Duration::from_secs(2), async {
        pool.get()
            .await
            .expect("a connection")
            .query_one("SELECT 1", &[])
            .await
            .map(|_| ())
    })
    .await;

    assert_eq!(failure, Err(ProbeFailure::TimedOut));
    assert_eq!(
        relay.silenced.load(Ordering::SeqCst),
        1,
        "the probe gave up on a link gone silent, not on a slow connection"
    );
    assert!(
        matches!(next, Ok(Ok(()))),
        "the next borrower got a fresh connection, not the silent one: {next:?}"
    );
}

#[tokio::test]
async fn a_pooled_session_finds_the_objects_of_the_product_in_public_first() {
    let database = TestDatabase::create(&[]).await;
    let superuser = database
        .plan("postgres")
        .connect_directly()
        .await
        .expect("a connection");
    // A schema that bears the name of the serving role comes first by default.
    superuser
        .batch_execute(&format!(
            "CREATE FUNCTION public.which() RETURNS text LANGUAGE sql AS 'SELECT ''public''';
             CREATE SCHEMA {APP_ROLE};
             GRANT USAGE ON SCHEMA {APP_ROLE} TO {APP_ROLE};
             CREATE FUNCTION {APP_ROLE}.which() RETURNS text LANGUAGE sql AS 'SELECT ''shadow''';"
        ))
        .await
        .expect("two functions of one name");
    let pool = build_pool(&database.plan(APP_ROLE), PoolSettings::default()).expect("a pool");

    let answer: String = pool
        .get()
        .await
        .expect("a connection")
        .query_one("SELECT which()", &[])
        .await
        .expect("an answer")
        .get(0);

    assert_eq!(answer, "public");
    drop(superuser);
    wait_for_superuser_sessions_to_end(&database).await;
}

#[tokio::test]
async fn the_migrations_go_to_public_whatever_schema_bears_the_name_of_the_runner() {
    let database = TestDatabase::create(&[]).await;
    let owner = database.plan(OWNER);
    owner
        .connect_directly()
        .await
        .expect("a connection")
        .batch_execute(&format!("CREATE SCHEMA {OWNER}"))
        .await
        .expect("a schema named after the runner");

    apply_pending(&owner, &[NOTES])
        .await
        .expect("the migrations applied");

    let placed: String = owner
        .connect_directly()
        .await
        .expect("a connection")
        .query_one(
            "SELECT n.nspname::text FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relname = 'notes'",
            &[],
        )
        .await
        .expect("the table of the migration, once")
        .get(0);
    assert_eq!(placed, "public");
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

/// Waits for the superuser sessions of a test to end: the owner of the test
/// database, which drops it, may not end them.
async fn wait_for_superuser_sessions_to_end(database: &TestDatabase) {
    let observer = database
        .plan(OWNER)
        .connect_directly()
        .await
        .expect("a connection");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let open: i64 = observer
            .query_one(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE datname = current_database() AND usename = 'postgres'",
                &[],
            )
            .await
            .expect("a count")
            .get(0);
        if open == 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{open} superuser sessions still open"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn read_privilege(database: &TestDatabase, role: &str) -> Option<Privilege> {
    let client = database
        .plan(role)
        .connect_directly()
        .await
        .expect("a connection");
    read_role_facts(&client)
        .await
        .expect("the facts of the role")
        .privilege
}

#[tokio::test]
async fn a_role_that_is_or_may_become_a_privileged_one_does_not_pass_the_role_check() {
    let database = TestDatabase::create(&[]).await;

    // The `saffui_test_*` roles exist for this test alone: `scripts/dev-postgres.sh`
    // creates them.
    for (role, expected) in [
        ("postgres", Privilege::BypassesRowSecurity),
        (
            "saffui_test_member_of_maintenance",
            Privilege::BypassesRowSecurity,
        ),
        ("saffui_test_lowered_to_app", Privilege::BypassesRowSecurity),
        ("saffui_test_superuser_only", Privilege::BypassesRowSecurity),
        ("saffui_test_reads_all", Privilege::ReachesEverything),
        ("saffui_test_writes_all", Privilege::ReachesEverything),
        (
            "saffui_test_reads_server_files",
            Privilege::ReachesEverything,
        ),
        (
            "saffui_test_writes_server_files",
            Privilege::ReachesEverything,
        ),
        (
            "saffui_test_runs_server_programs",
            Privilege::ReachesEverything,
        ),
        (OWNER, Privilege::ActsAsOwner),
        ("saffui_test_noinherit_owner", Privilege::ActsAsOwner),
        ("saffui_test_heir_of_owner", Privilege::ActsAsOwner),
        ("saffui_test_creates_roles", Privilege::ManagesRoles),
        ("saffui_test_replicates", Privilege::Replicates),
    ] {
        assert_eq!(
            read_privilege(&database, role).await,
            Some(expected),
            "{role}"
        );
    }

    // A superuser lowered by a setting of its connection is still one.
    let lowered = plan_connection(
        &format!(
            "{} options='-c role={APP_ROLE}'",
            database.connection_string("postgres")
        ),
        Some(TlsMode::Disable),
        None,
    )
    .expect("a plan")
    .connect_directly()
    .await
    .expect("a connection");
    let facts = read_role_facts(&lowered)
        .await
        .expect("the facts of the role");
    assert_eq!(
        (facts.name.as_str(), facts.privilege),
        ("postgres", Some(Privilege::BypassesRowSecurity))
    );
    drop(lowered);
    wait_for_superuser_sessions_to_end(&database).await;
}

#[tokio::test]
async fn a_role_that_owns_a_schema_or_a_table_in_any_schema_does_not_pass_the_role_check() {
    let database = TestDatabase::create(&[]).await;
    let owner = database
        .plan(OWNER)
        .connect_directly()
        .await
        .expect("a connection");
    owner
        .batch_execute(&format!(
            "CREATE SCHEMA elsewhere; GRANT USAGE, CREATE ON SCHEMA elsewhere TO {APP_ROLE}"
        ))
        .await
        .expect("a schema the serving role may create in");
    assert_eq!(read_privilege(&database, APP_ROLE).await, None);

    let superuser = database
        .plan("postgres")
        .connect_directly()
        .await
        .expect("a connection");
    superuser
        .batch_execute(&format!("CREATE SCHEMA given AUTHORIZATION {APP_ROLE}"))
        .await
        .expect("a schema of its own");
    assert_eq!(
        read_privilege(&database, APP_ROLE).await,
        Some(Privilege::ActsAsOwner),
        "the owner of a schema may drop any table in it"
    );
    superuser
        .batch_execute(&format!(
            "DROP SCHEMA given; CREATE SCHEMA pgstage AUTHORIZATION {APP_ROLE};
             CREATE FUNCTION public.left(name, integer) RETURNS text LANGUAGE sql
                 AS 'SELECT ''pg_''::text'"
        ))
        .await
        .expect("a schema whose name starts like a system one");
    // Neither a setting of the connection nor a function earlier in the search
    // path, with closer argument types, changes which schemas are the system's.
    let old_strings = plan_connection(
        &format!(
            "{} options='-c standard_conforming_strings=off'",
            database.connection_string(APP_ROLE)
        ),
        Some(TlsMode::Disable),
        None,
    )
    .expect("a plan")
    .connect_directly()
    .await
    .expect("a connection");
    assert_eq!(
        read_role_facts(&old_strings)
            .await
            .expect("the facts of the role")
            .privilege,
        Some(Privilege::ActsAsOwner),
        "pgstage is not a system schema"
    );
    superuser
        .batch_execute("DROP SCHEMA pgstage; DROP FUNCTION public.left(name, integer)")
        .await
        .expect("the schema and the function gone");

    let app = database
        .plan(APP_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    app.batch_execute("CREATE TABLE elsewhere.mine (id integer)")
        .await
        .expect("a table of its own");
    assert_eq!(
        read_privilege(&database, APP_ROLE).await,
        Some(Privilege::ActsAsOwner),
        "the owner of a table outside public, of a database it does not own"
    );
    drop(superuser);
    wait_for_superuser_sessions_to_end(&database).await;
}

#[tokio::test]
async fn an_object_privilege_that_steps_past_row_security_does_not_pass_the_role_check() {
    let database = TestDatabase::create(&[]).await;
    let owner = database
        .plan(OWNER)
        .connect_directly()
        .await
        .expect("a connection");
    owner
        .batch_execute(&format!(
            "CREATE TABLE guarded (id integer PRIMARY KEY);
             ALTER TABLE guarded ENABLE ROW LEVEL SECURITY;
             CREATE TABLE parted (id integer) PARTITION BY RANGE (id);
             ALTER TABLE parted ENABLE ROW LEVEL SECURITY;
             CREATE TABLE parted_low PARTITION OF parted FOR VALUES FROM (0) TO (100);
             CREATE TABLE parted_open (id integer) PARTITION BY RANGE (id);
             CREATE VIEW history_window AS SELECT version FROM schema_migrations;
             CREATE TABLE unguarded (id integer, label text);
             CREATE VIEW window_on_guarded AS SELECT id FROM guarded;
             CREATE VIEW window_on_window AS SELECT id FROM window_on_guarded;
             CREATE MATERIALIZED VIEW copy_of_guarded AS SELECT id FROM guarded;
             CREATE VIEW invoker_window WITH (security_invoker = true) AS SELECT id FROM guarded;
             CREATE VIEW checked_window WITH (check_option = local) AS
                 SELECT id FROM guarded WHERE id > 0;
             CREATE VIEW window_on_unguarded AS SELECT id FROM unguarded;
             GRANT SELECT, INSERT, UPDATE, DELETE ON guarded, parted TO {APP_ROLE};
             GRANT SELECT ON invoker_window, history_window TO {APP_ROLE};"
        ))
        .await
        .expect("tables with and without row security");
    assert_eq!(
        read_privilege(&database, APP_ROLE).await,
        None,
        "reading and writing a guarded table, reading it through a view that runs as \
         the reader, and reading the history are what a node does"
    );

    // Granted by a superuser: only one may create a foreign table.
    let superuser = database
        .plan("postgres")
        .connect_directly()
        .await
        .expect("a connection");
    superuser
        .batch_execute(
            "CREATE FOREIGN DATA WRAPPER elsewhere_wrapper;
             CREATE SERVER elsewhere FOREIGN DATA WRAPPER elsewhere_wrapper;
             CREATE FOREIGN TABLE far (id integer) SERVER elsewhere;",
        )
        .await
        .expect("a foreign table");
    for (privilege, expected) in [
        ("INSERT ON unguarded", Privilege::WritesUnguardedTable),
        (
            "UPDATE (label) ON unguarded",
            Privilege::WritesUnguardedTable,
        ),
        ("DELETE ON unguarded", Privilege::WritesUnguardedTable),
        (
            "INSERT ON window_on_guarded",
            Privilege::WritesUnguardedTable,
        ),
        ("INSERT ON far", Privilege::WritesUnguardedTable),
        ("TRUNCATE ON guarded", Privilege::HoldsWholeTablePrivilege),
        ("TRUNCATE ON parted", Privilege::HoldsWholeTablePrivilege),
        (
            "REFERENCES (id) ON guarded",
            Privilege::HoldsWholeTablePrivilege,
        ),
        ("TRIGGER ON guarded", Privilege::HoldsWholeTablePrivilege),
        ("SELECT ON window_on_guarded", Privilege::ReadsThroughView),
        (
            "SELECT (id) ON window_on_guarded",
            Privilege::ReadsThroughView,
        ),
        ("SELECT ON window_on_window", Privilege::ReadsThroughView),
        ("SELECT ON copy_of_guarded", Privilege::ReadsThroughView),
        ("SELECT ON checked_window", Privilege::ReadsThroughView),
        ("SELECT ON window_on_unguarded", Privilege::ReadsThroughView),
        ("SELECT ON unguarded", Privilege::ReadsUnguardedTable),
        (
            "SELECT (label) ON unguarded",
            Privilege::ReadsUnguardedTable,
        ),
        ("SELECT ON parted_low", Privilege::ReadsUnguardedTable),
        ("SELECT ON parted_open", Privilege::ReadsUnguardedTable),
        ("SELECT ON far", Privilege::ReadsUnguardedTable),
    ] {
        superuser
            .batch_execute(&format!("GRANT {privilege} TO {APP_ROLE}"))
            .await
            .expect("a grant");
        assert_eq!(
            read_privilege(&database, APP_ROLE).await,
            Some(expected),
            "{privilege}"
        );
        superuser
            .batch_execute(&format!("REVOKE {privilege} FROM {APP_ROLE}"))
            .await
            .expect("a revoke");
    }
    drop(superuser);
    wait_for_superuser_sessions_to_end(&database).await;
}

#[tokio::test]
async fn an_operator_elsewhere_does_not_answer_for_the_catalog_in_the_role_check() {
    let database = TestDatabase::create(&[]).await;
    database
        .plan(OWNER)
        .connect_directly()
        .await
        .expect("a connection")
        .batch_execute(&format!(
            "CREATE TABLE unguarded (id integer); GRANT SELECT ON unguarded TO {APP_ROLE}"
        ))
        .await
        .expect("a table the serving role may read");
    // It would answer before the catalog's once a setting of the connection
    // puts its schema first in the search path.
    database
        .plan("postgres")
        .connect_directly()
        .await
        .expect("a connection")
        .batch_execute(
            "CREATE FUNCTION public.always_same(oid, oid) RETURNS boolean LANGUAGE sql
                 AS 'SELECT true';
             CREATE OPERATOR public.= (LEFTARG = oid, RIGHTARG = oid,
                 FUNCTION = public.always_same);",
        )
        .await
        .expect("an operator of the same name and types");
    let public_first = plan_connection(
        &format!(
            "{} options='-c search_path=public,pg_catalog'",
            database.connection_string(APP_ROLE)
        ),
        Some(TlsMode::Disable),
        None,
    )
    .expect("a plan")
    .connect_directly()
    .await
    .expect("a connection");
    assert_eq!(
        read_role_facts(&public_first)
            .await
            .expect("the facts of the role")
            .privilege,
        Some(Privilege::ReadsUnguardedTable)
    );
    wait_for_superuser_sessions_to_end(&database).await;
}

#[tokio::test]
async fn a_function_that_runs_as_an_owner_past_row_security_does_not_pass_the_role_check() {
    let database = TestDatabase::create(&[]).await;
    let owner = database
        .plan(OWNER)
        .connect_directly()
        .await
        .expect("a connection");
    owner
        .batch_execute(&format!(
            "CREATE TABLE guarded (id integer);
             ALTER TABLE guarded ENABLE ROW LEVEL SECURITY;
             ALTER TABLE guarded FORCE ROW LEVEL SECURITY;
             GRANT SELECT ON guarded TO {APP_ROLE};
             CREATE FUNCTION count_guarded() RETURNS bigint LANGUAGE sql SECURITY DEFINER
                 AS 'SELECT count(*) FROM guarded';"
        ))
        .await
        .expect("a function of the owner, whom row security binds");
    let superuser = database
        .plan("postgres")
        .connect_directly()
        .await
        .expect("a connection");
    // Only a superuser creates an event trigger, and its function cannot be called.
    superuser
        .batch_execute(
            "CREATE FUNCTION answer() RETURNS integer LANGUAGE sql AS 'SELECT 42';
             CREATE FUNCTION on_ddl() RETURNS event_trigger LANGUAGE plpgsql SECURITY DEFINER
                 AS 'BEGIN END';",
        )
        .await
        .expect("functions the node cannot run past row security");
    assert_eq!(read_privilege(&database, APP_ROLE).await, None);

    // EXECUTE is granted to PUBLIC unless revoked, and a view reaches a
    // function in a schema the role cannot name.
    for (create, function) in [
        (
            "CREATE FUNCTION every_guarded() RETURNS SETOF guarded LANGUAGE sql SECURITY DEFINER
                 AS 'SELECT * FROM guarded'",
            "every_guarded()",
        ),
        (
            "CREATE SCHEMA vault;
             CREATE FUNCTION vault.dump_guarded() RETURNS TABLE (id integer) LANGUAGE sql
                 SECURITY DEFINER AS 'SELECT id FROM public.guarded'",
            "vault.dump_guarded()",
        ),
        (
            "CREATE FUNCTION by_maintenance() RETURNS bigint LANGUAGE sql SECURITY DEFINER
                 AS 'SELECT count(*) FROM guarded';
             ALTER FUNCTION by_maintenance() OWNER TO saffui_maintenance",
            "by_maintenance()",
        ),
        (
            "CREATE FUNCTION by_superuser_only() RETURNS bigint LANGUAGE sql SECURITY DEFINER
                 AS 'SELECT count(*) FROM guarded';
             ALTER FUNCTION by_superuser_only() OWNER TO saffui_test_superuser_only",
            "by_superuser_only()",
        ),
        // The node may attach a trigger function to a temporary table of its own.
        (
            "CREATE FUNCTION on_row() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
                 AS 'BEGIN RETURN NEW; END'",
            "on_row()",
        ),
    ] {
        superuser.batch_execute(create).await.expect("a function");
        assert_eq!(
            read_privilege(&database, APP_ROLE).await,
            Some(Privilege::ExecutesDefinerFunction),
            "{function}"
        );
        superuser
            .batch_execute(&format!(
                "REVOKE EXECUTE ON FUNCTION {function} FROM PUBLIC"
            ))
            .await
            .expect("a revoke");
        assert_eq!(
            read_privilege(&database, APP_ROLE).await,
            None,
            "{function}"
        );
    }
    drop(superuser);
    wait_for_superuser_sessions_to_end(&database).await;
}

#[tokio::test]
async fn a_trigger_function_of_the_owner_the_node_may_attach_does_not_pass_the_role_check() {
    let database = TestDatabase::create(&[]).await;
    let owner = database
        .plan(OWNER)
        .connect_directly()
        .await
        .expect("a connection");
    // Attached to a temporary table of the node, it runs with the rights of the
    // owner, who may write what the node may not.
    owner
        .batch_execute(
            "CREATE FUNCTION mirror_row() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
                 AS 'BEGIN RETURN NEW; END'",
        )
        .await
        .expect("a trigger function of the owner");
    assert_eq!(
        read_privilege(&database, APP_ROLE).await,
        Some(Privilege::ExecutesDefinerFunction)
    );
    owner
        .batch_execute("REVOKE EXECUTE ON FUNCTION mirror_row() FROM PUBLIC")
        .await
        .expect("a revoke");
    assert_eq!(read_privilege(&database, APP_ROLE).await, None);
}

#[tokio::test]
async fn a_function_of_the_owner_of_a_table_without_force_does_not_pass_the_role_check() {
    let database = TestDatabase::create(&[]).await;
    let owner = database
        .plan(OWNER)
        .connect_directly()
        .await
        .expect("a connection");
    // The owner of a table that row security binds without force reads all of it.
    owner
        .batch_execute(
            "CREATE TABLE loose (id integer);
             ALTER TABLE loose ENABLE ROW LEVEL SECURITY;
             CREATE FUNCTION every_loose() RETURNS SETOF loose LANGUAGE sql SECURITY DEFINER
                 AS 'SELECT * FROM loose'",
        )
        .await
        .expect("a function of the owner of a table without force");
    assert_eq!(
        read_privilege(&database, APP_ROLE).await,
        Some(Privilege::ExecutesDefinerFunction)
    );
    owner
        .batch_execute("ALTER TABLE loose FORCE ROW LEVEL SECURITY")
        .await
        .expect("row security forced");
    assert_eq!(read_privilege(&database, APP_ROLE).await, None);

    // Owning is inherited: a function of an heir of the owner reads as the owner.
    owner
        .batch_execute(
            "DROP FUNCTION every_loose();
             ALTER TABLE loose NO FORCE ROW LEVEL SECURITY",
        )
        .await
        .expect("the function of the owner gone");
    assert_eq!(read_privilege(&database, APP_ROLE).await, None);
    database
        .plan("postgres")
        .connect_directly()
        .await
        .expect("a connection")
        .batch_execute(
            "CREATE FUNCTION by_heir() RETURNS bigint LANGUAGE sql SECURITY DEFINER
                 AS 'SELECT count(*) FROM loose';
             ALTER FUNCTION by_heir() OWNER TO saffui_test_heir_of_owner",
        )
        .await
        .expect("a function of an heir of the owner");
    assert_eq!(
        read_privilege(&database, APP_ROLE).await,
        Some(Privilege::ExecutesDefinerFunction)
    );
    wait_for_superuser_sessions_to_end(&database).await;
}

#[tokio::test]
async fn a_pooled_session_waits_for_a_lock_no_longer_than_the_pool_waits_for_a_connection() {
    let database = TestDatabase::create(&[]).await;
    let owner = database
        .plan(OWNER)
        .connect_directly()
        .await
        .expect("a connection");
    owner
        .batch_execute(&format!(
            "CREATE TABLE contended (id integer); GRANT SELECT ON contended TO {APP_ROLE}"
        ))
        .await
        .expect("a table");
    let settings = PoolSettings {
        max_size: 1,
        wait_timeout: Duration::from_millis(300),
        ..PoolSettings::default()
    };
    let pool = build_pool(&database.plan(APP_ROLE), settings).expect("a pool");

    // A borrower that lifts the bound does not lift it for the next one.
    pool.get()
        .await
        .expect("the connection")
        .batch_execute("SET lock_timeout = 0")
        .await
        .expect("a borrower that lifts the bound");
    owner
        .batch_execute("BEGIN; LOCK TABLE contended IN ACCESS EXCLUSIVE MODE")
        .await
        .expect("a lock held");
    let session = pool.get().await.expect("the same connection again");
    let started = Instant::now();
    // Bounded here too: without the setting, the statement would wait forever.
    let refused = tokio::time::timeout(
        Duration::from_secs(4),
        session.query("SELECT id FROM contended", &[]),
    )
    .await
    .expect("the session gave up the lock before 4 s")
    .expect_err("a lock that is never given");
    let waited = started.elapsed();
    owner
        .batch_execute("ROLLBACK")
        .await
        .expect("the lock let go");

    assert_eq!(refused.code(), Some(&SqlState::LOCK_NOT_AVAILABLE));
    assert!(
        waited >= Duration::from_millis(280) && waited < Duration::from_millis(900),
        "the session waited {waited:?}, where the pool waits 300 ms"
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
