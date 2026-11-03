//! The contract of the core, played on Postgres: the adapter must answer as
//! the double does.

use pgcore::pool::PoolSettings;
use saffui_core::testkit::contract::{
    check_clients_contract, check_keys_contract, check_persons_contract, check_sign_in_contract,
    check_tenancy_contract,
};

mod support;

#[tokio::test]
async fn postgres_passes_the_tenancy_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_tenancy_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_keys_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_keys_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_clients_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_clients_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_persons_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_persons_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_sign_in_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_sign_in_contract(&app).await;
}
