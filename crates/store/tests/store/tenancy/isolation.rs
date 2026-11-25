//! What only SQL can prove: a session sees nothing outside the scope its
//! transaction set, whatever statement it sends.

use std::time::{Duration, Instant};

use pgcore::pool::PoolSettings;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE};
use saffui_core::app::App;
use saffui_core::error::ErrorCode;
use saffui_core::ports::storage::{StorageError, StorageUnavailable};
use saffui_core::tenancy::RealmName;
use saffui_core::tenancy::realm::{NewRealm, Provisioned, provision_first_realm};
use tokio_postgres::Client;
use tokio_postgres::error::{DbError, SqlState};

use crate::support::{self, connect};

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
    // No store changes a realm yet: the serving role may not, in its scope or
    // out of it.
    let disabled = session
        .execute("UPDATE realms SET enabled = false", &[])
        .await
        .expect_err("an update of a realm");
    assert_eq!(disabled.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    session.batch_execute("ROLLBACK").await.expect("a rollback");
    open_scope(&session, &acme).await;

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
        .expect_err("an update of a realm");
    assert_eq!(
        disabled.code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE),
        "no store changes a realm yet: the serving role may not"
    );
    session.batch_execute("ROLLBACK").await.expect("a rollback");
    open_scope(&session, &acme).await;
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
    let maintenance = connect(&database, MAINTENANCE_ROLE).await;
    // Written by hand, with no history: a realm the product creates has its
    // creation in its chain, and a chain is not deleted with its realm.
    let (tenant, realm) = (uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2));
    maintenance
        .execute(
            "INSERT INTO tenants (tenant_id, name, created_at) VALUES ($1, 'Acme', now())",
            &[&tenant],
        )
        .await
        .expect("a tenant");
    maintenance
        .execute(
            "INSERT INTO realms (tenant_id, realm_id, name, enabled, created_at) \
             VALUES ($1, $2, 'acme', true, now())",
            &[&tenant, &realm],
        )
        .await
        .expect("a realm");
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
async fn a_statement_waits_for_a_lock_as_long_as_the_pool_waits_then_is_told_busy() {
    // The bound of a lock is the patience of the pool, not a figure of its own.
    let short_pool = PoolSettings {
        wait_timeout: Duration::from_secs(2),
        ..PoolSettings::default()
    };
    let (app, database) = support::wire_on_postgres(short_pool).await;
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
    let started = std::time::Instant::now();
    // Bounded here too: without a bound, the read would wait forever.
    let read = tokio::time::timeout(Duration::from_secs(20), work.read_realm())
        .await
        .expect("the read gave up the lock before 20 s");
    let waited = started.elapsed();
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
    assert!(
        waited >= Duration::from_secs(2) && waited < Duration::from_secs(4),
        "the lock was waited for as long as the pool waits: {waited:?}"
    );
}

#[tokio::test]
async fn a_unit_of_work_reads_what_committed_after_it_began_under_a_repeatable_read_default() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    // Before the pool opens a session: a session reads the default as it opens.
    database.default_transactions_to_repeatable_read().await;
    let acme = provision(&app, "Acme", "acme").await;
    let (_name, scope) = saffui_core::tenancy::resolve::resolve_realm(&app, "acme")
        .await
        .expect("the realm resolves");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let first = work.read_realm().await.expect("a first read");

    connect(&database, MAINTENANCE_ROLE)
        .await
        .execute(
            "UPDATE realms SET enabled = false WHERE realm_id = $1",
            &[&acme.realm.id.as_uuid()],
        )
        .await
        .expect("the realm disabled meanwhile");
    let then = work.read_realm().await.expect("a second read");

    assert_eq!(
        (
            first.map(|realm| realm.enabled),
            then.map(|realm| realm.enabled)
        ),
        (Some(true), Some(false)),
        "the second read sees what committed after the first"
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

/// A consent is removed by the serving role in its realm only, whatever the
/// statement asks, and only its scopes and its instant ever change.
#[tokio::test]
async fn a_statement_under_one_scope_removes_no_consent_of_another_realm() {
    use saffui_core::consent::Consent;
    use saffui_core::tenancy::RealmScope;
    use saffui_core::testkit::fixtures::{
        Application, create_person, create_realm, register_application,
    };

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let mut scopes = Vec::new();
    for realm_name in ["acme", "globex"] {
        let scope = create_realm(&app, realm_name).await;
        let ada = create_person(&app, scope, "ada", "correct horse battery").await;
        let partner = Application {
            client_id: "partner",
            redirect_uri: "https://app.example.org/cb",
            post_logout_redirect_uri: None,
            public: true,
            requires_consent: true,
        };
        register_application(&app, scope, partner).await;
        let mut work = app.storage.begin(scope).await.expect("a unit of work");
        work.add_consent(&Consent {
            person: ada.id,
            client_id: "partner".to_owned(),
            scopes: vec!["openid".to_owned()],
            claims: Vec::new(),
            granted_at: app.now(),
        })
        .await
        .expect("a consent");
        work.commit().await.expect("a commit");
        scopes.push(scope);
    }
    let session = connect(&database, APP_ROLE).await;
    let open = async |scope: RealmScope| {
        session
            .batch_execute(&format!(
                "BEGIN; SELECT set_config('saffui.tenant', '{}', true), \
                 set_config('saffui.realm', '{}', true)",
                scope.tenant().as_uuid(),
                scope.realm().as_uuid()
            ))
            .await
            .expect("a scoped transaction");
    };

    open(scopes[0]).await;
    assert_eq!(count_rows(&session, "consents").await, 1);
    let removed = session
        .execute("DELETE FROM consents", &[])
        .await
        .expect("a removal without a filter");
    assert_eq!(removed, 1, "the consent of its own realm, and no other");
    session.batch_execute("COMMIT").await.expect("a commit");

    open(scopes[1]).await;
    let moved = session
        .execute("UPDATE consents SET client_id = 'another'", &[])
        .await
        .expect_err("a consent given to another client");
    assert_eq!(moved.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    session.batch_execute("ROLLBACK").await.expect("a rollback");

    let maintenance = connect(&database, MAINTENANCE_ROLE).await;
    let left: Vec<uuid::Uuid> = maintenance
        .query("SELECT realm_id FROM consents", &[])
        .await
        .expect("the consents")
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(left, [scopes[1].realm().as_uuid()]);
}

/// The serving role may update of a client its realm for the lock of its
/// row, the capabilities the operator grants, the two forms of its secret
/// and its method, what a registered client says of itself and whether it
/// is enabled, and the attributes of a person: row security keeps the first
/// where it is and each in its realm, the schema keeps the capabilities to
/// its list and to the clients that act as themselves, a secret to the form
/// its method keeps and a method between the two ways of presenting one
/// secret, and nothing else of either changes.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario, read from top to bottom"
)]
async fn the_rights_to_update_a_client_and_a_person_reach_their_columns_in_their_realm() {
    use saffui_core::testkit::fixtures::{
        Application, create_person, create_realm, create_service_client, register_application,
    };

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let acme = create_realm(&app, "acme").await;
    let globex = create_realm(&app, "globex").await;
    create_service_client(&app, acme, "billing", &["invoices:read"]).await;
    let webapp = Application {
        client_id: "webapp",
        redirect_uri: "https://app.example.org/callback",
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: false,
    };
    register_application(&app, acme, webapp).await;
    // A confidential application: public, it would break no rule of its row.
    let portal = Application {
        client_id: "portal",
        redirect_uri: "https://portal.example.org/callback",
        post_logout_redirect_uri: None,
        public: false,
        requires_consent: false,
    };
    register_application(&app, acme, portal).await;
    plant_registered_client(&app, acme, "registered").await;
    create_person(&app, acme, "ada", "correct horse battery").await;
    let bob = create_person(&app, globex, "bob", "correct horse battery").await;
    let session = connect(&database, APP_ROLE).await;
    let open_acme = format!(
        "BEGIN; SELECT set_config('saffui.tenant', '{}', true), \
         set_config('saffui.realm', '{}', true)",
        acme.tenant().as_uuid(),
        acme.realm().as_uuid()
    );
    let refuse = async |statement: String| {
        session
            .batch_execute(&open_acme)
            .await
            .expect("a scoped transaction");
        let refused = session
            .execute(&statement, &[])
            .await
            .expect_err("a statement the serving role may not run");
        session.batch_execute("ROLLBACK").await.expect("a rollback");
        refused
    };

    let moved = refuse(format!(
        "UPDATE clients SET realm_id = '{}' WHERE client_id = 'billing'",
        globex.realm().as_uuid()
    ))
    .await;
    let read_message = |error: &tokio_postgres::Error| {
        error
            .as_db_error()
            .map(|refusal| refusal.message().to_owned())
            .unwrap_or_default()
    };
    assert_eq!(
        moved.code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE),
        "{moved}"
    );
    assert!(
        read_message(&moved).contains("row-level security"),
        "row security keeps the row where it is: {moved}"
    );
    for (statement, rule) in [
        (
            "UPDATE clients SET capabilities = '{key:read}' WHERE client_id = 'webapp'",
            "clients_capabilities_for_services",
        ),
        (
            "UPDATE clients SET capabilities = '{key:*}' WHERE client_id = 'billing'",
            "clients_capabilities_known",
        ),
        (
            "UPDATE clients SET secret_digest = NULL WHERE client_id = 'billing'",
            "clients_proof_fits_method",
        ),
        (
            "UPDATE clients SET sealed_secret = '\\x00' WHERE client_id = 'billing'",
            "clients_proof_fits_method",
        ),
        (
            "UPDATE clients SET secret_digest = '\\x07' WHERE client_id = 'webapp'",
            "clients_proof_fits_method",
        ),
    ] {
        let refused = refuse(statement.to_owned()).await;
        assert_eq!(
            refused.code(),
            Some(&SqlState::CHECK_VIOLATION),
            "{statement}: {refused}"
        );
        assert_eq!(
            refused
                .as_db_error()
                .and_then(|refusal| refusal.constraint()),
            Some(rule),
            "{statement}"
        );
    }
    for statement in [
        "UPDATE clients SET auth_method = 'none', secret_digest = NULL \
         WHERE client_id = 'portal'",
        "UPDATE clients SET auth_method = 'client_secret_jwt', secret_digest = NULL, \
         sealed_secret = '\\x00' WHERE client_id = 'billing'",
        "UPDATE clients SET auth_method = 'client_secret_post', secret_digest = '\\x09' \
         WHERE client_id = 'billing'",
        "UPDATE clients SET auth_method = 'client_secret_basic' WHERE client_id = 'webapp'",
    ] {
        let refused = refuse(statement.to_owned()).await;
        assert_eq!(
            refused.code(),
            Some(&SqlState::CHECK_VIOLATION),
            "a method changes between the two ways of presenting one secret: {statement}"
        );
    }
    for statement in [
        "UPDATE clients SET client_id = 'x'",
        "UPDATE clients SET requires_consent = false",
        "UPDATE clients SET allows_client_credentials = true",
        "UPDATE clients SET allows_authorization_code = false",
        "UPDATE clients SET created_at = now()",
        "UPDATE clients SET self_registered = true",
        "UPDATE persons SET email_verified = true",
    ] {
        let refused = refuse(statement.to_owned()).await;
        assert_eq!(
            refused.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{statement}: {refused}"
        );
        assert!(
            read_message(&refused).contains("permission denied"),
            "{statement}: {refused}"
        );
    }

    session
        .batch_execute(&open_acme)
        .await
        .expect("a scoped transaction");
    let reached = session
        .execute(
            "UPDATE persons SET attributes = '{}' WHERE person_id = $1",
            &[&bob.id],
        )
        .await
        .expect("an update that reaches nothing");
    let granted = session
        .execute(
            "UPDATE clients SET capabilities = '{key:write}' WHERE client_id = 'billing'",
            &[],
        )
        .await
        .expect("a capability granted to a service");
    let turned_over = session
        .execute(
            "UPDATE clients SET secret_digest = '\\x08' WHERE client_id = 'billing'",
            &[],
        )
        .await
        .expect("a secret turned over");
    let said = session
        .execute(
            "UPDATE clients SET name = 'Renamed', scopes = '{openid}', enabled = false \
             WHERE client_id = 'registered'",
            &[],
        )
        .await
        .expect("what a registered client says of itself, and its end");
    let mut moved = 0;
    for method in ["client_secret_post", "client_secret_basic"] {
        moved += session
            .execute(
                "UPDATE clients SET auth_method = $1 WHERE client_id = 'billing'",
                &[&method],
            )
            .await
            .expect("a secret moved between the header and the form");
    }
    session.batch_execute("ROLLBACK").await.expect("a rollback");
    assert_eq!(reached, 0, "a person of another realm");
    assert_eq!(granted, 1, "the column the operator writes");
    assert_eq!(turned_over, 1, "the column an administrator turns over");
    assert_eq!(moved, 2, "there and back");
    assert_eq!(said, 1, "the columns a registered client writes");
}

/// The trigger that bounds a method compares under a path of its own. An
/// operator the serving role plants first on its path, true for any two
/// texts it is given, would otherwise let an application that signs with
/// its secret become public: its digest is null before and after, and its
/// row breaks no rule. True for an empty text, the operator would hide every
/// row instead, as the scope is read through `NULLIF`.
#[tokio::test]
async fn an_operator_the_serving_role_plants_does_not_unbind_a_change_of_method() {
    use saffui_core::clients::ClientAuthMethod;
    use saffui_core::clients::register::NewClient;
    use saffui_core::testkit::fixtures::{check_and_register_client, create_realm};

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let acme = create_realm(&app, "acme").await;
    let callbacks = ["https://portal.example.org/callback".to_owned()];
    let mut work = app.storage.begin(acme).await.expect("a unit of work");
    check_and_register_client(
        &app,
        work.as_mut(),
        NewClient {
            client_id: "portal",
            name: "Portal",
            scopes: &[],
            capabilities: &[],
            redirect_uris: &callbacks,
            post_logout_redirect_uris: &[],
            response_types: &[],
            public: false,
            requires_consent: false,
            id_token_signed_response_alg: None,
            auth_method: Some(ClientAuthMethod::ClientSecretJwt),
            jwks: None,
            jwks_uri: None,
            auth_signing_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: false,
            created_by: None,
        },
    )
    .await
    .expect("an application that signs with its secret");
    work.commit().await.expect("a commit");
    let owner = connect(&database, OWNER).await;
    owner
        .batch_execute(&format!(
            "CREATE SCHEMA planted; GRANT USAGE, CREATE ON SCHEMA planted TO {APP_ROLE}"
        ))
        .await
        .expect("a schema the serving role may write in");
    let session = connect(&database, APP_ROLE).await;
    session
        .batch_execute(
            "CREATE FUNCTION planted.agree(text, text) RETURNS boolean LANGUAGE sql
                 AS $$ SELECT $1 OPERATOR(pg_catalog.<>) '' AND $2 OPERATOR(pg_catalog.<>) '' $$;
             CREATE OPERATOR planted.= (LEFTARG = text, RIGHTARG = text, FUNCTION = planted.agree);
             CREATE FUNCTION planted.agree(bytea, bytea) RETURNS boolean LANGUAGE sql
                 AS 'SELECT true';
             CREATE OPERATOR planted.= (LEFTARG = bytea, RIGHTARG = bytea, FUNCTION = planted.agree);
             SET search_path = planted, pg_catalog, public",
        )
        .await
        .expect("an operator planted first on the path of the serving role");
    session
        .batch_execute(&format!(
            "BEGIN; SELECT set_config('saffui.tenant', '{}', true), \
             set_config('saffui.realm', '{}', true)",
            acme.tenant().as_uuid(),
            acme.realm().as_uuid()
        ))
        .await
        .expect("a scoped transaction");

    // `LIKE`, not `=`: the planted operator would pick every row.
    let made_public = session
        .execute(
            "UPDATE clients SET auth_method = 'none', sealed_secret = NULL \
             WHERE client_id LIKE 'portal'",
            &[],
        )
        .await;
    session.batch_execute("ROLLBACK").await.expect("a rollback");
    drop(session);
    owner
        .batch_execute("DROP SCHEMA planted CASCADE")
        .await
        .expect("the schema dropped");

    let refused = made_public.expect_err("a confidential application made public");
    assert_eq!(
        refused.code(),
        Some(&SqlState::CHECK_VIOLATION),
        "{refused}"
    );
    assert_eq!(
        refused
            .as_db_error()
            .map(|refusal| (refusal.constraint(), refusal.message())),
        Some((None, "a client changes only how it presents its secret")),
        "the trigger refuses it, not a rule of the row"
    );
}

#[tokio::test]
async fn the_function_that_bounds_a_method_is_granted_to_no_role() {
    let (_app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let owner = connect(&database, OWNER).await;

    for role in [APP_ROLE, MAINTENANCE_ROLE] {
        let granted: bool = owner
            .query_one(
                "SELECT has_function_privilege($1, 'saffui_bound_auth_method_change()', 'EXECUTE')",
                &[&role],
            )
            .await
            .expect("a privilege read")
            .get(0);
        assert!(!granted, "{role} may call it");
    }
}

/// The settings of a realm, its initial access tokens and the tokens of its
/// registrations: the serving role reads only those of its realm, writes
/// none for another, and changes only the column each statement of the
/// product writes. A setting is never removed, a token's maker and instants
/// never change, and a registration never moves to another client.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario, read from top to bottom"
)]
async fn the_rows_of_registration_stay_in_their_realm_and_change_only_where_granted() {
    use saffui_core::clients::registration::InitialAccessToken;
    use saffui_core::tenancy::RealmScope;
    use saffui_core::testkit::fixtures::{Application, create_realm, register_application};

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let mut scopes: Vec<RealmScope> = Vec::new();
    for realm_name in ["acme", "globex"] {
        let scope = create_realm(&app, realm_name).await;
        let portal = Application {
            client_id: "portal",
            redirect_uri: "https://app.example.org/cb",
            post_logout_redirect_uri: None,
            public: true,
            requires_consent: true,
        };
        register_application(&app, scope, portal).await;
        plant_registered_client(&app, scope, "registered").await;
        let mut work = app.storage.begin(scope).await.expect("a unit of work");
        work.write_realm_settings(&serde_json::json!({ "registration": "open" }))
            .await
            .expect("settings");
        let token = InitialAccessToken {
            id: saffui_core::ids::mint_id(&app).expect("an identifier"),
            uses_left: 3,
            expires_at: app.now() + time::Duration::hours(1),
            created_at: app.now(),
            created_by: "operator".to_owned(),
        };
        work.insert_initial_access_token(&token, &[4; 32])
            .await
            .expect("a token");
        work.insert_client_registration("registered", &[6; 32], app.now())
            .await
            .expect("a registration");
        work.commit().await.expect("a commit");
        scopes.push(scope);
    }
    let session = connect(&database, APP_ROLE).await;
    let open = |scope: RealmScope| {
        format!(
            "BEGIN; SELECT set_config('saffui.tenant', '{}', true), \
             set_config('saffui.realm', '{}', true)",
            scope.tenant().as_uuid(),
            scope.realm().as_uuid()
        )
    };
    let refuse = async |statement: &str| {
        session
            .batch_execute(&open(scopes[0]))
            .await
            .expect("a scoped transaction");
        let refused = session
            .execute(statement, &[])
            .await
            .expect_err("a statement the serving role may not run");
        session.batch_execute("ROLLBACK").await.expect("a rollback");
        refused
    };

    session
        .batch_execute(&open(scopes[0]))
        .await
        .expect("a scoped transaction");
    for table in [
        "realm_settings",
        "initial_access_tokens",
        "client_registrations",
    ] {
        assert_eq!(
            count_rows(&session, table).await,
            1,
            "{table} of its realm alone"
        );
    }
    let spent = session
        .execute(
            "UPDATE initial_access_tokens SET uses_left = uses_left - 1",
            &[],
        )
        .await
        .expect("a use spent");
    let rotated = session
        .execute(
            "UPDATE client_registrations SET token_digest = $1",
            &[&vec![8_u8; 32]],
        )
        .await
        .expect("a token replaced");
    let rewritten = session
        .execute(
            "UPDATE realm_settings SET settings = '{\"registration\": \"closed\"}'",
            &[],
        )
        .await
        .expect("settings replaced");
    let ended = session
        .execute(
            "UPDATE client_registrations SET token_digest = NULL, ended_at = now()",
            &[],
        )
        .await
        .expect("a registration ended");
    let removed = session
        .execute("DELETE FROM initial_access_tokens", &[])
        .await
        .expect("a token taken back");
    session.batch_execute("ROLLBACK").await.expect("a rollback");
    assert_eq!(
        (spent, rotated, rewritten, ended, removed),
        (1, 1, 1, 1, 1),
        "each reaches the one row of its realm"
    );

    let (globex_tenant, globex_realm) = (
        scopes[1].tenant().as_uuid().to_string(),
        scopes[1].realm().as_uuid().to_string(),
    );
    for planted in [
        format!(
            "INSERT INTO initial_access_tokens (tenant_id, realm_id, token_id, token_digest, \
             uses_left, expires_at, created_at, created_by) VALUES ('{globex_tenant}', \
             '{globex_realm}', gen_random_uuid(), '\\x{}', 1, now(), now(), 'x')",
            "05".repeat(32)
        ),
        format!(
            "INSERT INTO client_registrations (tenant_id, realm_id, client_id, token_digest, \
             registered_at) VALUES ('{globex_tenant}', '{globex_realm}', 'portal', '\\x{}', now())",
            "09".repeat(32)
        ),
        format!("UPDATE realm_settings SET realm_id = '{globex_realm}'"),
    ] {
        let refused = refuse(&planted).await;
        assert_eq!(
            refused.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{planted}: {refused}"
        );
    }
    for statement in [
        "DELETE FROM realm_settings",
        "DELETE FROM client_registrations",
        "UPDATE initial_access_tokens SET created_by = 'someone'",
        "UPDATE initial_access_tokens SET expires_at = now() + interval '1 year'",
        "UPDATE initial_access_tokens SET token_digest = token_digest",
        "UPDATE client_registrations SET client_id = 'another'",
        "UPDATE client_registrations SET registered_at = now()",
    ] {
        let refused = refuse(statement).await;
        assert_eq!(
            refused.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{statement}: {refused}"
        );
    }
    for (statement, rule) in [
        (
            "UPDATE realm_settings SET settings = '[]'",
            "realm_settings_settings_check",
        ),
        (
            "UPDATE initial_access_tokens SET uses_left = 101",
            "initial_access_tokens_uses_left_check",
        ),
        (
            "UPDATE client_registrations SET token_digest = '\\x01'",
            "client_registrations_token_digest_check",
        ),
        (
            "UPDATE client_registrations SET ended_at = now()",
            "client_registrations_token_while_live",
        ),
        (
            "UPDATE client_registrations SET token_digest = NULL",
            "client_registrations_token_while_live",
        ),
    ] {
        let refused = refuse(statement).await;
        assert_eq!(
            refused.code(),
            Some(&SqlState::CHECK_VIOLATION),
            "{statement}: {refused}"
        );
        assert_eq!(
            refused
                .as_db_error()
                .and_then(|refusal| refusal.constraint()),
            Some(rule),
            "{statement}"
        );
    }

    let maintenance = connect(&database, MAINTENANCE_ROLE).await;
    for table in [
        "realm_settings",
        "initial_access_tokens",
        "client_registrations",
    ] {
        assert_eq!(
            count_rows(&maintenance, table).await,
            2,
            "{table}: nothing of another realm was touched"
        );
    }
}

/// The end of a registration holds in the database: a client turned off is
/// turned on again by no role, the owner included, and the statement that
/// rewrites what a client says of itself writes only a client that
/// registered itself, while its registration lasts. A client an
/// administrator made is given no registration, and what it says of itself
/// is rewritten by no statement of the serving role.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario, read from top to bottom"
)]
async fn a_client_turned_off_stays_off_and_only_a_live_registration_is_rewritten() {
    use saffui_core::clients::{Client, ClientAuthMethod, KeptProof};
    use saffui_core::testkit::fixtures::{Application, create_realm, register_application};

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let acme = create_realm(&app, "acme").await;
    let portal = Application {
        client_id: "portal",
        redirect_uri: "https://app.example.org/cb",
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: true,
    };
    register_application(&app, acme, portal).await;
    let mut work = app.storage.begin(acme).await.expect("a unit of work");
    let made = work
        .read_client("portal")
        .await
        .expect("a read")
        .expect("portal");
    let registered = |client_id: &str| Client {
        id: saffui_core::ids::mint_id(&app).expect("an identifier"),
        client_id: client_id.to_owned(),
        auth_method: ClientAuthMethod::None,
        self_registered: true,
        ..made.clone()
    };
    let nothing = || KeptProof {
        secret_digest: None,
        sealed_secret: None,
        jwks: None,
    };
    for (client_id, digest) in [("live", 1_u8), ("ended", 2)] {
        work.insert_client(&registered(client_id), &nothing())
            .await
            .expect("a registered client");
        work.insert_client_registration(client_id, &[digest; 32], app.now())
            .await
            .expect("its registration");
    }
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(acme).await.expect("a unit of work");
    assert!(
        work.insert_client_registration("portal", &[3; 32], app.now())
            .await
            .is_err(),
        "a client an administrator made registered nothing"
    );
    drop(work);
    let mut work = app.storage.begin(acme).await.expect("a unit of work");
    assert_eq!(
        work.end_client_registration("ended", &[2; 32], app.now())
            .await,
        Ok(true)
    );
    for client_id in ["live", "ended", "portal"] {
        let renamed = Client {
            name: "Renamed".to_owned(),
            ..work
                .read_client(client_id)
                .await
                .expect("a read")
                .expect("the client")
        };
        assert_eq!(
            work.write_client_metadata(&renamed, None).await,
            Ok(client_id == "live"),
            "{client_id}"
        );
    }
    assert_eq!(work.disable_client("live").await, Ok(true));
    work.commit().await.expect("a commit");

    for role in [APP_ROLE, OWNER] {
        let session = connect(&database, role).await;
        session
            .batch_execute(&format!(
                "BEGIN; SELECT set_config('saffui.tenant', '{}', true), \
                 set_config('saffui.realm', '{}', true)",
                acme.tenant().as_uuid(),
                acme.realm().as_uuid()
            ))
            .await
            .expect("a scoped transaction");
        let refused = session
            .execute(
                "UPDATE clients SET enabled = true WHERE client_id = 'live'",
                &[],
            )
            .await
            .expect_err("a client turned on again");
        session.batch_execute("ROLLBACK").await.expect("a rollback");
        assert_eq!(refused.code(), Some(&SqlState::CHECK_VIOLATION), "{role}");
        assert_eq!(
            refused.as_db_error().map(DbError::message),
            Some("a client turned off stays off"),
            "{role}"
        );
    }
    let session = connect(&database, APP_ROLE).await;
    let (tenant, realm) = (acme.tenant().as_uuid(), acme.realm().as_uuid());
    let plant = |client_id: &str, self_registered: bool| {
        format!(
            "INSERT INTO client_registrations (tenant_id, realm_id, client_id, \
             self_registered, token_digest, registered_at) VALUES ('{tenant}', '{realm}', \
             '{client_id}', {self_registered}, '\\x{}', now())",
            "03".repeat(32)
        )
    };
    let rewrite = |column: &str| format!("UPDATE clients SET {column} WHERE client_id = 'portal'");
    let kept_by_the_trigger = Some("a client an administrator made keeps what it says of itself");
    for (statement, code, message) in [
        (plant("portal", true), SqlState::FOREIGN_KEY_VIOLATION, None),
        (plant("live", false), SqlState::CHECK_VIOLATION, None),
        (
            rewrite("name = 'Renamed'"),
            SqlState::CHECK_VIOLATION,
            kept_by_the_trigger,
        ),
        (
            rewrite("redirect_uris = '{https://evil.example/cb}'"),
            SqlState::CHECK_VIOLATION,
            kept_by_the_trigger,
        ),
        (
            rewrite("scopes = scopes"),
            SqlState::CHECK_VIOLATION,
            kept_by_the_trigger,
        ),
        (
            rewrite("post_logout_redirect_uris = post_logout_redirect_uris"),
            SqlState::CHECK_VIOLATION,
            kept_by_the_trigger,
        ),
        (
            rewrite("id_token_signed_response_alg = id_token_signed_response_alg"),
            SqlState::CHECK_VIOLATION,
            kept_by_the_trigger,
        ),
        (
            rewrite("auth_signing_alg = auth_signing_alg"),
            SqlState::CHECK_VIOLATION,
            kept_by_the_trigger,
        ),
        (
            rewrite("jwks = jwks"),
            SqlState::CHECK_VIOLATION,
            kept_by_the_trigger,
        ),
    ] {
        session
            .batch_execute(&format!(
                "BEGIN; SELECT set_config('saffui.tenant', '{tenant}', true), \
                 set_config('saffui.realm', '{realm}', true)"
            ))
            .await
            .expect("a scoped transaction");
        let refused = session
            .execute(&statement, &[])
            .await
            .expect_err("a statement the schema refuses");
        session.batch_execute("ROLLBACK").await.expect("a rollback");
        assert_eq!(refused.code(), Some(&code), "{statement}: {refused}");
        if message.is_some() {
            assert_eq!(
                refused.as_db_error().map(DbError::message),
                message,
                "{statement}"
            );
        }
    }
    let owner = connect(&database, OWNER).await;
    for function in [
        "saffui_keep_client_disabled()",
        "saffui_rewrite_registered_clients_only()",
        "saffui_remove_ended_clients_only()",
        "saffui_remove_ended_registrations_only()",
    ] {
        for role in [APP_ROLE, MAINTENANCE_ROLE, pgcore::RETENTION_ROLE] {
            let granted: bool = owner
                .query_one(
                    "SELECT has_function_privilege($1, $2, 'EXECUTE')",
                    &[&role, &function],
                )
                .await
                .expect("a privilege read")
                .get(0);
            assert!(!granted, "{role} may call {function}");
        }
    }
}

/// Writes `client_id`, a public client that registered itself, without its
/// registration: as the insertion of a registration does.
async fn plant_registered_client(
    app: &App,
    scope: saffui_core::tenancy::RealmScope,
    client_id: &str,
) {
    use saffui_core::clients::{Client, ClientAuthMethod, KeptProof};

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let registered = Client {
        id: saffui_core::ids::mint_id(app).expect("an identifier"),
        client_id: client_id.to_owned(),
        name: client_id.to_owned(),
        auth_method: ClientAuthMethod::None,
        auth_signing_alg: None,
        allows_client_credentials: false,
        allows_authorization_code: true,
        redirect_uris: vec!["https://registered.example.org/cb".to_owned()],
        response_types: vec![saffui_core::oidc::response::ResponseType::Code],
        post_logout_redirect_uris: Vec::new(),
        requires_consent: true,
        scopes: vec!["openid".to_owned()],
        capabilities: Vec::new(),
        id_token_signed_response_alg: None,
        request_object_signing_alg: None,
        require_signed_request_object: false,
        enabled: true,
        self_registered: true,
        created_at: app.now(),
    };
    let nothing = KeptProof {
        secret_digest: None,
        sealed_secret: None,
        jwks: None,
    };
    work.insert_client(&registered, &nothing)
        .await
        .expect("a client that registered itself");
    work.commit().await.expect("a commit");
}
