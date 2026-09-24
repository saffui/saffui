//! A pooler in transaction mode between the served pool and the database, the
//! way a cloud deployment often puts one: here PgBouncer, keeping prepared
//! statements as it does by default, lending each transaction whichever server
//! connection comes next.

mod support;

use std::time::Duration;

use deadpool_postgres::{Manager, Pool, Runtime};
use pgcore::database::{Bounds, Database};
use store::error::StoreError;
use store::providers::directory::users;
use store::tenancy::{Reached, RealmNamed, Tenancy, TenantContext};
use support::Fixture;
use tokio_postgres::{Config, NoTls};

const IDLE: Duration = Duration::from_secs(7);

/// The pooler's address as the application role, or a line saying there is
/// no pooler to cross.
fn pooled() -> Option<String> {
    let pooled = support::pooled_address();
    if pooled.is_none() {
        eprintln!("SAFFUI_TEST_PG_POOLER unset; there is no pooler to cross");
    }
    pooled
}

fn pool_of(address: &str, size: usize) -> Pool {
    let config: Config = address.parse().expect("a connection string");
    // The probe bounds each phase of taking a connection, which needs one.
    Pool::builder(Manager::new(config, NoTls))
        .max_size(size)
        .runtime(Runtime::Tokio1)
        .build()
        .expect("a pool")
}

/// Two server connections opened behind the pooler and handed back, so it
/// has two to lend in turn.
async fn two_server_connections(address: &str) {
    let config: Config = address.parse().expect("a connection string");
    let (first, one) = config.connect(NoTls).await.expect("a first client");
    let (second, two) = config.connect(NoTls).await.expect("a second client");
    tokio::spawn(one);
    tokio::spawn(two);
    first.batch_execute("BEGIN; SELECT 1").await.unwrap();
    second.batch_execute("BEGIN; SELECT 1").await.unwrap();
    first.batch_execute("COMMIT").await.unwrap();
    second.batch_execute("COMMIT").await.unwrap();
}

async fn read_ada(tenancy: &Tenancy) -> Result<(), StoreError> {
    let unit = tenancy.begin(&TenantContext::new("acme", "main")).await?;
    users::load_by_name(&unit, "ada").await?;
    unit.commit().await
}

/// Behind a pooler every door the store opens crosses it: units by context,
/// by name and on a snapshot, reads and writes, the realm resolved and
/// listed, the probe, and the served role read back.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG) and a pooler (SAFFUI_TEST_PG_POOLER)"]
async fn a_tenancy_behind_a_pooler_crosses_it() {
    let Some(pooled) = pooled() else {
        return;
    };
    let _fixture = Fixture::with_user().await;
    support::cut_lingering_connections().await;
    two_server_connections(&pooled).await;

    let tenancy = Tenancy::unpinned(pool_of(&pooled, 2)).behind_a_pooler(IDLE);
    let main = TenantContext::new("acme", "main");
    for round in 0..12 {
        read_ada(&tenancy).await.unwrap();

        let unit = tenancy.begin_in(RealmNamed::ByName("main")).await.unwrap();
        let mut ada = users::load_by_name(&unit, "ada")
            .await
            .unwrap()
            .expect("ada, in her own realm");
        ada.email = format!("ada+{round}@example.test");
        users::update(&unit, &ada).await.unwrap();
        unit.commit().await.unwrap();

        let unit = tenancy.begin_snapshot(&main).await.unwrap();
        let read = users::load_by_name(&unit, "ada").await.unwrap().unwrap();
        assert_eq!(read.email, format!("ada+{round}@example.test"));
        unit.commit().await.unwrap();
    }

    assert_eq!(
        tenancy
            .resolve(RealmNamed::ByName("main"))
            .await
            .unwrap()
            .realm_id,
        "main"
    );
    assert!(!tenancy.every_realm().await.unwrap().is_empty());
    let reached = tenancy.reach(Duration::from_secs(5)).await;
    assert!(matches!(reached, Reached::Schema(Some(_))), "{reached:?}");
    let served = tenancy.read_served_role().await.unwrap();
    assert_eq!(served.name, "saffui_app");
    assert!(!served.above_the_rules);
}

/// The served pool the process builds keeps its startup options off the
/// pooler, which refuses any it cannot keep track of; opened the old way, it
/// could not get a single connection.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG) and a pooler (SAFFUI_TEST_PG_POOLER)"]
async fn startup_options_are_kept_off_what_crosses_a_pooler() {
    let Some(pooled) = pooled() else {
        return;
    };
    let _fixture = Fixture::with_user().await;
    support::cut_lingering_connections().await;

    let alone = Database::new(&pooled, None, None, Bounds::default()).unwrap();
    assert!(
        alone.pool().unwrap().get().await.is_err(),
        "the pooler took a startup option it cannot keep track of"
    );

    let through = Database::new(&support::direct_address(), None, None, Bounds::default())
        .unwrap()
        .with_pooler(&pooled, None, None)
        .unwrap();
    let tenancy = Tenancy::unpinned(through.pool().unwrap())
        .behind_a_pooler(through.bounds().idle_in_transaction);
    read_ada(&tenancy).await.unwrap();
}
