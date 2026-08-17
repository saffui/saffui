//! What the providers do under the rules, against a database.

use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, CryptoProvider};
use deadpool_postgres::{Manager, Pool};
use models::auditable::AuditableModel;
use models::entities::realm::{RealmCreateModel, RealmModel};
use models::entities::tenant::{TenantCreateModel, TenantLimits, TenantModel, TenantState};
use models::paging::PagingParams;
use pgcore::migrations::MigrationRunner;
use pgcore::tls::PgConnector;
use store::providers::{realms, tenants};
use store::query::list_query::ListQuery;
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

async fn pool() -> Pool {
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

    let provider = OpenSslProvider::new(&CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .expect("a software provider");
    MigrationRunner::new(migrations())
        .run(&owner_config(), &PgConnector::disabled(), provider.digest())
        .await
        .expect("the schema applies");
    owner
        .batch_execute("ALTER ROLE saffui_app LOGIN PASSWORD 'saffui_app_test'")
        .await
        .expect("the role gets a password");

    let mut app = owner_config();
    app.user("saffui_app").password("saffui_app_test");
    Pool::builder(Manager::new(app, NoTls))
        .max_size(4)
        .build()
        .expect("a pool")
}

fn tenant(id: &str) -> TenantModel {
    TenantCreateModel {
        tenant_id: id.to_owned(),
        display_name: id.to_owned(),
        region: None,
        limits: Some(TenantLimits {
            max_realms: Some(10),
            ..Default::default()
        }),
        created_by: Some("root".to_owned()),
    }
    .into()
}

fn realm(tenant: &str, id: &str) -> RealmModel {
    RealmCreateModel {
        name: id.to_owned(),
        display_name: id.to_owned(),
        enabled: true,
    }
    .into_model(
        id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), "root".to_owned()),
    )
}

/// Plant a tenant and its realms, each under its own scope.
async fn plant(pool: &Pool, tenancy: &Tenancy, name: &str, realm_ids: &[&str]) {
    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide(name))
        .await
        .unwrap();

    tenants::create(&transaction, &tenant(name)).await.unwrap();
    for realm_id in realm_ids {
        realms::create(&transaction, &realm(name, realm_id))
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();
}

/// A tenant reads itself back, with everything it was written with.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_tenant_reads_itself_back() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant(&pool, &tenancy, "acme", &["one"]).await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("acme"))
        .await
        .unwrap();

    let loaded = tenants::load(&transaction)
        .await
        .unwrap()
        .expect("its own tenant");
    assert_eq!(loaded.tenant_id, "acme");
    assert_eq!(loaded.state, TenantState::Active);
    assert_eq!(
        loaded.limits.expect("the ceilings survived").max_realms,
        Some(10),
        "the limits went through the wire and came back"
    );
    assert_eq!(loaded.version, 1);
    assert!(loaded.created_at.is_some(), "the column default stamped it");

    assert!(tenants::exists(&transaction).await.unwrap());
    assert_eq!(tenants::count_realms(&transaction).await.unwrap(), 1);
    transaction.commit().await.unwrap();
}

/// Another tenant's row is nothing rather than theirs, and its realms do not
/// count towards this one's ceiling.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn another_tenant_reads_as_nothing() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant(&pool, &tenancy, "acme", &["one", "two"]).await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("globex"))
        .await
        .unwrap();

    assert!(tenants::load(&transaction).await.unwrap().is_none());
    assert!(!tenants::exists(&transaction).await.unwrap());
    assert_eq!(
        tenants::count_realms(&transaction).await.unwrap(),
        0,
        "another tenant's realms counted towards this one's ceiling"
    );
    assert!(
        realms::load(&transaction, "one").await.unwrap().is_none(),
        "a realm identifier is not a way past the rules"
    );
    assert!(
        !realms::name_taken(&transaction, "one").await.unwrap(),
        "a name taken elsewhere is free here"
    );
    transaction.commit().await.unwrap();
}

/// A model naming another tenant is refused by the rules rather than written
/// under a name nobody would look for it by.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_model_naming_another_tenant_is_refused() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant(&pool, &tenancy, "acme", &[]).await;
    plant(&pool, &tenancy, "globex", &[]).await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("acme"))
        .await
        .unwrap();

    assert!(
        realms::create(&transaction, &realm("globex", "planted"))
            .await
            .is_err(),
        "a realm was written under a tenant this transaction is not for"
    );
}

/// A page is bounded and its total counts the same set, not the page.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_page_is_bounded_and_its_total_is_not() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant(&pool, &tenancy, "acme", &["a", "b", "c", "d", "e"]).await;
    plant(&pool, &tenancy, "globex", &["x", "y"]).await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("acme"))
        .await
        .unwrap();

    let window = PagingParams {
        first: Some(0),
        max: Some(2),
        ..Default::default()
    }
    .window()
    .unwrap();

    let page = realms::list(&transaction, &ListQuery::new(window), true)
        .await
        .unwrap();

    assert_eq!(
        page.items.len(),
        2,
        "the page is the size that was asked for"
    );
    assert_eq!(
        page.total,
        Some(5),
        "the total counts the tenant's realms, not the page and not everyone's"
    );
    assert!(page.may_have_more());

    // And without asking, the total is absent rather than a number nobody paid
    // for.
    let unasked = realms::list(&transaction, &ListQuery::new(window), false)
        .await
        .unwrap();
    assert_eq!(unasked.total, None);
    transaction.commit().await.unwrap();
}

/// Changing a state bumps the version from the stored value rather than from
/// whatever the writer last read.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_state_change_bumps_the_stored_version() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant(&pool, &tenancy, "acme", &[]).await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("acme"))
        .await
        .unwrap();

    assert!(
        tenants::set_state(&transaction, TenantState::Suspended, "root")
            .await
            .unwrap()
    );
    let loaded = tenants::load(&transaction).await.unwrap().unwrap();
    assert_eq!(loaded.state, TenantState::Suspended);
    assert_eq!(loaded.version, 2);
    assert_eq!(loaded.updated_by.as_deref(), Some("root"));
    assert!(loaded.updated_at.is_some());
    transaction.commit().await.unwrap();

    // A tenant that is not there is not an error, and says nothing changed.
    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("nobody"))
        .await
        .unwrap();
    assert!(
        !tenants::set_state(&transaction, TenantState::Archived, "root")
            .await
            .unwrap(),
        "a state was changed on a tenant this transaction cannot see"
    );
    transaction.commit().await.unwrap();
}
