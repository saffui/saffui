//! The audit chain on Postgres, verified with the digest the binary links:
//! the database hashes each link, and the verification hashes it again.
//! This is the one crate that sees the store and the cryptography together.

use std::sync::Arc;

use crypto::adapters::digest::ProviderDigester;
use crypto::adapters::open_provider;
use pgcore::APP_ROLE;
use pgcore::migrate::EMBEDDED;
use pgcore::migrate::window::SchemaWindow;
use pgcore::pool::{PoolSettings, build_pool};
use pgcore::testkit::TestDatabase;
use saffui_core::app::App;
use saffui_core::settings::{PublicOrigin, Settings};
use saffui_core::testkit::clock::FixedClock;
use saffui_core::testkit::contract::check_audit_contract;
use saffui_core::testkit::random::CountingRandom;
use store::PgStorage;

/// An application on a database of its own, with the digest of the provider.
async fn wire_on_postgres() -> (App, TestDatabase) {
    let database = TestDatabase::create(EMBEDDED).await;
    let pool = build_pool(&database.plan(APP_ROLE), PoolSettings::default()).expect("a pool");
    let app = App {
        settings: Settings {
            public_origin: PublicOrigin::parse("https://id.example.test").expect("an origin"),
        },
        storage: Arc::new(PgStorage::new(pool, SchemaWindow::of_exactly(EMBEDDED))),
        clock: Arc::new(FixedClock::default()),
        random: Arc::new(CountingRandom::default()),
        digester: Arc::new(ProviderDigester::new(open_provider().expect("a provider"))),
    };
    (app, database)
}

#[tokio::test]
async fn postgres_passes_the_audit_contract() {
    let (app, _database) = wire_on_postgres().await;

    check_audit_contract(&app).await;
}
