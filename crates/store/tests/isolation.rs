//! What only SQL can prove: a session sees nothing outside the scope its
//! transaction set, whatever statement it sends.

use std::time::{Duration, Instant};

use pgcore::pool::PoolSettings;
use pgcore::testkit::TestDatabase;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE};
use saffui_core::app::App;
use saffui_core::error::ErrorCode;
use saffui_core::ports::storage::{StorageError, StorageUnavailable};
use saffui_core::tenancy::RealmName;
use saffui_core::tenancy::realm::{NewRealm, Provisioned, provision_first_realm};
use tokio_postgres::Client;
use tokio_postgres::error::SqlState;

mod support;

const OWNER: &str = "saffui_owner";

async fn provision(app: &App, tenant_name: &str, realm_name: &str) -> Provisioned {
    provision_first_realm(
        app,
        NewRealm {
            tenant_name,
            realm_name,
        },
    )
    .await
    .expect("a provisioned realm")
}

async fn connect(database: &TestDatabase, role: &str) -> Client {
    database
        .plan(role)
        .connect_directly()
        .await
        .expect("a connection")
}

async fn count_rows(client: &Client, table: &str) -> i64 {
    client
        .query_one(&format!("SELECT count(*) FROM {table}"), &[])
        .await
        .expect("a count")
        .get(0)
}

async fn open_scope(client: &Client, provisioned: &Provisioned) {
    client
        .batch_execute(&format!(
            "BEGIN; SELECT set_config('saffui.tenant', '{}', true), set_config('saffui.realm', '{}', true)",
            provisioned.tenant.id.as_uuid(),
            provisioned.realm.id.as_uuid()
        ))
        .await
        .expect("a scoped transaction");
}

#[tokio::test]
async fn a_session_without_a_scope_reads_no_row() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    provision(&app, "Acme", "acme").await;
    let session = connect(&database, APP_ROLE).await;

    assert_eq!(count_rows(&session, "tenants").await, 0);
    assert_eq!(count_rows(&session, "realms").await, 0);
}

#[tokio::test]
async fn a_session_whose_last_transaction_had_a_scope_reads_no_row_after_it() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let acme = provision(&app, "Acme", "acme").await;
    let session = connect(&database, APP_ROLE).await;

    open_scope(&session, &acme).await;
    assert_eq!(count_rows(&session, "realms").await, 1, "inside its scope");
    session.batch_execute("COMMIT").await.expect("a commit");

    // The setting now reads back as an empty string, not as NULL.
    assert_eq!(count_rows(&session, "realms").await, 0);
    assert_eq!(count_rows(&session, "tenants").await, 0);
}

#[tokio::test]
async fn statements_written_by_hand_under_one_scope_reach_no_other_tenant() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let acme = provision(&app, "Acme", "acme").await;
    let globex = provision(&app, "Globex", "globex").await;
    let session = connect(&database, APP_ROLE).await;
    open_scope(&session, &acme).await;

    assert_eq!(count_rows(&session, "tenants").await, 1);
    assert_eq!(count_rows(&session, "realms").await, 1);
    let disabled = session
        .execute("UPDATE realms SET enabled = false", &[])
        .await
        .expect("an update with no predicate at all");
    assert_eq!(disabled, 1, "only the realm of the scope was reached");

    let planted = session
        .execute(
            "INSERT INTO realms (tenant_id, realm_id, name, enabled, created_at)
             VALUES ($1, $2, 'planted', true, now())",
            &[&globex.tenant.id.as_uuid(), &uuid::Uuid::from_u128(7)],
        )
        .await
        .expect_err("a row for another tenant");
    assert_eq!(
        planted.code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE),
        "row security refuses the write"
    );
    session.batch_execute("ROLLBACK").await.expect("a rollback");

    let maintenance = connect(&database, MAINTENANCE_ROLE).await;
    let still_enabled: bool = maintenance
        .query_one(
            "SELECT enabled FROM realms WHERE realm_id = $1",
            &[&globex.realm.id.as_uuid()],
        )
        .await
        .expect("the other realm")
        .get(0);
    assert!(
        still_enabled,
        "the realm of the other tenant was not touched"
    );
}

#[tokio::test]
async fn a_session_writes_only_the_realm_of_its_scope_in_a_tenant_that_has_two() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let acme = provision(&app, "Acme", "acme").await;
    let maintenance = connect(&database, MAINTENANCE_ROLE).await;
    let sibling = uuid::Uuid::from_u128(11);
    maintenance
        .execute(
            "INSERT INTO realms (tenant_id, realm_id, name, enabled, created_at)
             VALUES ($1, $2, 'acme-two', true, now())",
            &[&acme.tenant.id.as_uuid(), &sibling],
        )
        .await
        .expect("a second realm of the same tenant");
    let session = connect(&database, APP_ROLE).await;
    open_scope(&session, &acme).await;

    assert_eq!(
        count_rows(&session, "realms").await,
        2,
        "a tenant lists its realms: reading stops at the tenant"
    );
    let disabled = session
        .execute("UPDATE realms SET enabled = false", &[])
        .await
        .expect("an update with no predicate at all");
    assert_eq!(disabled, 1, "only the realm of the scope was written");
    let planted = session
        .execute(
            "INSERT INTO realms (tenant_id, realm_id, name, enabled, created_at)
             VALUES ($1, $2, 'acme-three', true, now())",
            &[&acme.tenant.id.as_uuid(), &uuid::Uuid::from_u128(12)],
        )
        .await
        .expect_err("a row for another realm of the same tenant");
    assert_eq!(
        planted.code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE),
        "row security refuses the write"
    );
    session.batch_execute("ROLLBACK").await.expect("a rollback");
}

#[tokio::test]
async fn the_directory_follows_a_realm_that_is_disabled_renamed_or_deleted() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let acme = provision(&app, "Acme", "acme").await;
    let maintenance = connect(&database, MAINTENANCE_ROLE).await;
    let realm = acme.realm.id.as_uuid();
    let locate = |name: &'static str| {
        let name = RealmName::parse(name).expect("a realm name");
        let storage = &app.storage;
        async move {
            storage
                .locate_realm(&name)
                .await
                .expect("the directory answers")
                .map(|location| location.enabled)
        }
    };

    maintenance
        .execute(
            "UPDATE realms SET enabled = false WHERE realm_id = $1",
            &[&realm],
        )
        .await
        .expect("a disabled realm");
    assert_eq!(
        locate("acme").await,
        Some(false),
        "disabled in the directory"
    );

    maintenance
        .execute(
            "UPDATE realms SET name = 'acme-renamed' WHERE realm_id = $1",
            &[&realm],
        )
        .await
        .expect("a renamed realm");
    assert_eq!(locate("acme").await, None, "the old name leads nowhere");
    assert_eq!(locate("acme-renamed").await, Some(false));

    maintenance
        .execute("DELETE FROM realms WHERE realm_id = $1", &[&realm])
        .await
        .expect("a deleted realm");
    assert_eq!(
        locate("acme-renamed").await,
        None,
        "a deleted realm is gone"
    );
}

#[tokio::test]
async fn the_owner_of_the_tables_is_bound_by_row_security_too() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    provision(&app, "Acme", "acme").await;

    let owner = connect(&database, OWNER).await;

    assert_eq!(count_rows(&owner, "realms").await, 0);
}

#[tokio::test]
async fn the_maintenance_role_reads_across_tenants() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    provision(&app, "Acme", "acme").await;
    provision(&app, "Globex", "globex").await;

    let maintenance = connect(&database, MAINTENANCE_ROLE).await;

    assert_eq!(count_rows(&maintenance, "realms").await, 2);
}

#[tokio::test]
async fn the_serving_role_cannot_list_the_realm_directory() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    provision(&app, "Acme", "acme").await;
    let session = connect(&database, APP_ROLE).await;

    let refused = session
        .query("SELECT name FROM realm_directory", &[])
        .await
        .expect_err("a table no role is granted");

    assert_eq!(refused.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
}

#[tokio::test]
async fn of_two_units_of_work_that_take_one_realm_name_exactly_one_commits() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    let (first, second) = tokio::join!(
        provision_first_realm(
            &app,
            NewRealm {
                tenant_name: "Acme",
                realm_name: "contested"
            }
        ),
        provision_first_realm(
            &app,
            NewRealm {
                tenant_name: "Globex",
                realm_name: "contested"
            }
        ),
    );

    let refused: Vec<ErrorCode> = [&first, &second]
        .into_iter()
        .filter_map(|outcome| outcome.as_ref().err().map(|failure| failure.code))
        .collect();
    assert_eq!(
        refused,
        [ErrorCode::RealmNameTaken],
        "one provisioning wins the name and the other is told it is taken: {first:?} / {second:?}"
    );
}

#[tokio::test]
async fn an_abandoned_unit_of_work_gives_its_connection_back() {
    let one_connection = PoolSettings {
        max_size: 1,
        ..PoolSettings::default()
    };
    let (app, _database) = support::wire_on_postgres(one_connection).await;
    let acme = provision(&app, "Acme", "acme").await;
    let (_name, scope) = saffui_core::tenancy::resolve::resolve_realm(&app, "acme")
        .await
        .expect("the realm resolves");

    for _ in 0..3 {
        let abandoned = app.storage.begin(scope).await.expect("the only connection");
        drop(abandoned);
    }
    let mut work = app
        .storage
        .begin(scope)
        .await
        .expect("the connection came back");

    assert_eq!(
        work.read_realm()
            .await
            .map(|realm| realm.map(|realm| realm.id)),
        Ok(Some(acme.realm.id))
    );
}

#[tokio::test]
async fn a_statement_that_waits_for_a_lock_past_its_bound_is_told_busy() {
    // The pool bounds a lock at a minute here: only the bound of the unit of
    // work gives up before the test does.
    let patient_pool = PoolSettings {
        wait_timeout: Duration::from_mins(1),
        ..PoolSettings::default()
    };
    let (app, database) = support::wire_on_postgres(patient_pool).await;
    provision(&app, "Acme", "acme").await;
    let (_name, scope) = saffui_core::tenancy::resolve::resolve_realm(&app, "acme")
        .await
        .expect("the realm resolves");
    let owner = connect(&database, OWNER).await;
    owner
        .batch_execute("BEGIN; LOCK TABLE realms IN ACCESS EXCLUSIVE MODE")
        .await
        .expect("a lock held");

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    // Bounded here too: without a bound, the read would wait forever.
    let read = tokio::time::timeout(Duration::from_secs(20), work.read_realm())
        .await
        .expect("the read gave up the lock before 20 s");
    drop(work);
    owner
        .batch_execute("ROLLBACK")
        .await
        .expect("the lock let go");

    assert_eq!(
        read,
        Err(StorageError::Unavailable(StorageUnavailable::TimedOut)),
        "busy, not failed"
    );
}

async fn count_open_transactions(observer: &Client) -> i64 {
    observer
        .query_one(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND pid <> pg_backend_pid() \
               AND state LIKE 'idle in transaction%'",
            &[],
        )
        .await
        .expect("a count")
        .get(0)
}

#[tokio::test]
async fn an_abandoned_unit_of_work_is_rolled_back_before_its_connection_is_borrowed_again() {
    // The server ends an idle transaction itself long after the bound below:
    // only the unit of work can end it in time.
    let one_connection = PoolSettings {
        max_size: 1,
        idle_in_transaction_timeout: Duration::from_mins(1),
        ..PoolSettings::default()
    };
    let (app, database) = support::wire_on_postgres(one_connection).await;
    provision(&app, "Acme", "acme").await;
    let (_name, scope) = saffui_core::tenancy::resolve::resolve_realm(&app, "acme")
        .await
        .expect("the realm resolves");
    let observer = connect(&database, APP_ROLE).await;

    let abandoned = app.storage.begin(scope).await.expect("the only connection");
    assert_eq!(
        count_open_transactions(&observer).await,
        1,
        "a unit of work holds a transaction"
    );
    drop(abandoned);

    // Nothing borrows the connection again: only the unit of work can end it.
    let deadline = Instant::now() + Duration::from_secs(2);
    while count_open_transactions(&observer).await > 0 {
        assert!(
            Instant::now() < deadline,
            "an abandoned unit of work left its transaction open in the pool"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn every_table_that_carries_the_scope_keys_has_row_security_forced_on_it() {
    let (_app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let owner = connect(&database, OWNER).await;

    let scoped = owner
        .query(
            "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                    (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)
             FROM pg_class c
             JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
             WHERE c.relkind = 'r'
               -- The directory of realm names is read before any scope exists,
               -- through one function: the serving role is granted nothing on it.
               AND c.relname <> 'realm_directory'
               AND EXISTS (SELECT 1 FROM pg_attribute a
                           WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
             ORDER BY c.relname",
            &[],
        )
        .await
        .expect("the catalog");

    assert!(
        scoped.len() >= 2,
        "the scan found {} scoped tables: it reads nothing",
        scoped.len()
    );
    for table in &scoped {
        let name: String = table.get(0);
        let (enabled, forced, policies): (bool, bool, i64) =
            (table.get(1), table.get(2), table.get(3));
        assert!(enabled && forced, "{name}: row security is not forced");
        assert!(policies >= 1, "{name}: no policy binds its rows");
    }
}
