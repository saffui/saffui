//! The contract of the core, played on Postgres: the adapter must answer as
//! the double does.

use pgcore::pool::PoolSettings;
use saffui_core::testkit::contract::check_tenancy_contract;

mod support;

#[tokio::test]
async fn postgres_passes_the_tenancy_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_tenancy_contract(&app).await;
}
