use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, CryptoProvider};
use deadpool_postgres::{Manager, Pool};
use pgcore::migrations::MigrationRunner;
use pgcore::tls::PgConnector;
use store::error::StoreError;
use store::schema::migrations;
use store::tenancy::{Tenancy, TenantContext};
use tokio_postgres::{Config, NoTls};

static DATABASE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn owner_config() -> Config {
    std::env::var("SAFFUI_TEST_PG")
        .unwrap_or_else(|_| panic!("these tests need a database: set SAFFUI_TEST_PG"))
        .parse()
        .expect("SAFFUI_TEST_PG is a connection string")
}

fn app_config() -> Config {
    let mut config = owner_config();
    config.user("saffui_app").password("saffui_app_test");
    config
}

fn provider() -> OpenSslProvider {
    OpenSslProvider::new(&CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .expect("a software provider")
}

/// A clean database with the schema, and a pool of exactly one connection so a
/// second borrow is the same physical connection as the first.
async fn one_connection_pool() -> Pool {
    let (owner, connection) = owner_config().connect(NoTls).await.expect("the owner");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    owner
        .batch_execute(
            "DROP SCHEMA public CASCADE; CREATE SCHEMA public; \
             GRANT ALL ON SCHEMA public TO CURRENT_USER;",
        )
        .await
        .expect("the database resets");

    MigrationRunner::new(migrations())
        .run(
            &owner_config(),
            &PgConnector::disabled(),
            provider().digest(),
        )
        .await
        .expect("the schema applies");
    owner
        .batch_execute("ALTER ROLE saffui_app LOGIN PASSWORD 'saffui_app_test'")
        .await
        .expect("the application role gets a password");

    Pool::builder(Manager::new(app_config(), NoTls))
        .max_size(1)
        .build()
        .expect("a pool of one")
}

async fn plant(pool: &Pool, tenancy: &Tenancy, tenant: &str) {
    let mut connection = pool.get().await.expect("a connection");
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide(tenant))
        .await
        .expect("a scoped transaction");
    transaction
        .execute(
            "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
            &[&tenant],
        )
        .await
        .expect("its own tenant");
    transaction.commit().await.expect("it commits");
}

/// A scoped transaction reads its own tenant and nobody else's.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_scoped_transaction_reads_only_its_own() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned();

    plant(&pool, &tenancy, "acme").await;
    plant(&pool, &tenancy, "globex").await;

    for tenant in ["acme", "globex"] {
        let mut connection = pool.get().await.unwrap();
        let transaction = tenancy
            .transaction(&mut connection, &TenantContext::tenant_wide(tenant))
            .await
            .unwrap();
        let seen: Vec<String> = transaction
            .query("SELECT tenant_id FROM tenants", &[])
            .await
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(seen, vec![tenant.to_owned()]);
        transaction.commit().await.unwrap();
    }
}

/// The setting does not survive onto the next borrower.
///
/// The pool holds one connection, so the second borrow is the first one handed
/// back. A setting written for the session rather than the transaction would
/// still be there, and the next caller would read another tenant's rows while
/// believing the rules were doing their work.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_returned_connection_carries_no_tenant() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned();

    plant(&pool, &tenancy, "acme").await;

    let connection = pool.get().await.unwrap();
    let left_over: Option<String> = connection
        .query_one("SELECT current_setting('saffui.current_tenant', true)", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        left_over.is_none() || left_over.as_deref() == Some(""),
        "the connection came back still scoped to {left_over:?}"
    );

    let seen: i64 = connection
        .query_one("SELECT count(*) FROM tenants", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(seen, 0, "an unscoped borrow read a tenant");
}

/// Dropping without committing rolls back, so the boundary is the drop rather
/// than a call somebody has to remember.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn dropping_the_transaction_rolls_it_back() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned();

    {
        let mut connection = pool.get().await.unwrap();
        let transaction = tenancy
            .transaction(&mut connection, &TenantContext::tenant_wide("acme"))
            .await
            .unwrap();
        transaction
            .execute(
                "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
                &[&"acme"],
            )
            .await
            .unwrap();
        // No commit.
    }

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("acme"))
        .await
        .unwrap();
    let seen: i64 = transaction
        .query_one("SELECT count(*) FROM tenants", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(seen, 0, "a dropped transaction left a row behind");
}

/// A pinned node refuses a realm pinned elsewhere before opening anything.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_mismatched_region_is_refused_before_anything_opens() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;

    let elsewhere = Tenancy::in_region("eu-west");
    let context = TenantContext::new("acme", "realm-1").with_region(Some("af-south".into()));

    let mut connection = pool.get().await.unwrap();
    assert_eq!(
        elsewhere
            .transaction(&mut connection, &context)
            .await
            .expect_err("a mismatched region is refused"),
        StoreError::Residency {
            node: "eu-west".to_owned(),
            pin: "af-south".to_owned()
        }
    );

    // And nothing was left open on the connection.
    let inside: bool = connection
        .query_one("SELECT pg_current_xact_id_if_assigned() IS NOT NULL", &[])
        .await
        .unwrap()
        .get(0);
    assert!(!inside, "a refused call left a transaction open");

    // The same node serves a realm that pins nothing.
    let unpinned = TenantContext::tenant_wide("acme");
    let transaction = elsewhere
        .transaction(&mut connection, &unpinned)
        .await
        .expect("an unpinned realm is served anywhere");
    transaction.commit().await.unwrap();
}

/// A snapshot transaction is read only and holds one snapshot, so two reads of
/// the same table agree even when another connection writes between them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_snapshot_does_not_move_under_a_reader() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned();

    plant(&pool, &tenancy, "acme").await;

    // A second connection, so the write is not on the reader's own.
    let (writer, connection) = app_config().connect(NoTls).await.expect("a second client");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut reading = pool.get().await.unwrap();
    let snapshot = tenancy
        .snapshot(&mut reading, &TenantContext::tenant_wide("acme"))
        .await
        .unwrap();

    let before: i64 = snapshot
        .query_one("SELECT count(*) FROM realms", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(before, 0);

    writer.batch_execute("BEGIN").await.unwrap();
    writer
        .execute(
            "SELECT set_config('saffui.current_tenant', $1, true)",
            &[&"acme"],
        )
        .await
        .unwrap();
    writer
        .execute(
            "INSERT INTO realms (tenant, realm_id, name, display_name) VALUES ($1, $2, $2, $2)",
            &[&"acme", &"written-after"],
        )
        .await
        .unwrap();
    writer.batch_execute("COMMIT").await.unwrap();

    let after: i64 = snapshot
        .query_one("SELECT count(*) FROM realms", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(after, before, "the snapshot moved under the reader");

    // The write really did land, so the reader is holding a snapshot rather than
    // reading a table nothing changed.
    writer.batch_execute("BEGIN").await.unwrap();
    writer
        .execute(
            "SELECT set_config('saffui.current_tenant', $1, true)",
            &[&"acme"],
        )
        .await
        .unwrap();
    let landed: i64 = writer
        .query_one("SELECT count(*) FROM realms", &[])
        .await
        .unwrap()
        .get(0);
    writer.batch_execute("COMMIT").await.unwrap();
    assert_eq!(landed, 1, "the write did not land at all");

    // And it will not write.
    assert!(
        snapshot
            .execute(
                "INSERT INTO realms (tenant, realm_id, name, display_name) \
                 VALUES ('acme','x','x','x')",
                &[]
            )
            .await
            .is_err(),
        "a read only transaction wrote"
    );
}
