//! A database of its own for one journey.

use pgcore::migrate::Migration;
use pgcore::testkit::TestDatabase;

/// Creates a database with `migrations` applied, from a test that has no runtime.
pub fn create_database(migrations: &[Migration]) -> TestDatabase {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime to create the test database")
        .block_on(TestDatabase::create(migrations))
}
