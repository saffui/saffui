//! An application wired on a database of its own.

use std::sync::Arc;

use pgcore::APP_ROLE;
use pgcore::migrate::EMBEDDED;
use pgcore::migrate::window::SchemaWindow;
use pgcore::pool::{PoolSettings, build_pool};
use pgcore::testkit::TestDatabase;
use saffui_core::app::App;
use saffui_core::settings::{PublicOrigin, Settings};
use saffui_core::testkit::clock::FixedClock;
use saffui_core::testkit::random::CountingRandom;
use store::PgStorage;

pub async fn wire_on_postgres(pool: PoolSettings) -> (App, TestDatabase) {
    let database = TestDatabase::create(EMBEDDED).await;
    let pool = build_pool(&database.plan(APP_ROLE), pool).expect("a pool");
    let app = App {
        settings: Settings {
            public_origin: PublicOrigin::parse("https://id.example.test").expect("an origin"),
        },
        storage: Arc::new(PgStorage::new(pool, SchemaWindow::of_exactly(EMBEDDED))),
        clock: Arc::new(FixedClock::default()),
        // Each test has a database of its own: identifiers need only differ within one.
        random: Arc::new(CountingRandom::default()),
    };
    (app, database)
}
