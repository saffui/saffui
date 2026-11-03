//! The product in process, on a database of its own, with the adapters of
//! the provider: what the binary wires, without its command line. This is
//! the one crate that sees the store and the cryptography together.

use std::sync::Arc;

use crypto::adapters::digest::ProviderDigester;
use crypto::adapters::open_provider;
use crypto::adapters::password::BoundedPasswordHasher;
use crypto::adapters::seal::EnvelopeSealer;
use crypto::adapters::sign::JoseSigner;
use pgcore::APP_ROLE;
use pgcore::migrate::EMBEDDED;
use pgcore::migrate::window::SchemaWindow;
use pgcore::pool::{PoolSettings, build_pool};
use pgcore::testkit::TestDatabase;
use saffui_core::app::App;
use saffui_core::secret::Secret;
use saffui_core::settings::{PublicOrigin, Settings};
use saffui_core::tenancy::RealmScope;
use saffui_core::tenancy::realm::{NewRealm, provision_first_realm};
use saffui_core::tenancy::resolve::resolve_realm;
use saffui_core::testkit::clock::FixedClock;
use saffui_core::testkit::random::CountingRandom;
use store::PgStorage;

/// The root key the product of a test runs under, unless a test names another.
pub const ROOT_KEY: [u8; 32] = [7; 32];

/// The product on `database`, under `root_key`.
pub fn wire_app(database: &TestDatabase, root_key: &Secret) -> App {
    let pool = build_pool(&database.plan(APP_ROLE), PoolSettings::default()).expect("a pool");
    let provider = open_provider().expect("a provider");
    App {
        settings: Settings::reached_directly(
            PublicOrigin::parse("https://id.example.test").expect("an origin"),
        ),
        storage: Arc::new(PgStorage::new(pool, SchemaWindow::of_exactly(EMBEDDED))),
        clock: Arc::new(FixedClock::default()),
        random: Arc::new(CountingRandom::default()),
        digester: Arc::new(ProviderDigester::new(Arc::clone(&provider))),
        sealer: Arc::new(EnvelopeSealer::new(Arc::clone(&provider), root_key).expect("a sealer")),
        hasher: Arc::new(BoundedPasswordHasher::new(Arc::clone(&provider), 2).expect("a hasher")),
        hashing_shares: Arc::new(saffui_core::login::fairness::HashingShares::new(2)),
        signer: Arc::new(JoseSigner::new(provider)),
        decoy_hash: Arc::new(std::sync::OnceLock::new()),
    }
}

/// The product on a migrated database of its own.
pub async fn wire_on_postgres() -> (App, TestDatabase) {
    let database = TestDatabase::create(EMBEDDED).await;
    let app = wire_app(&database, &Secret::new(ROOT_KEY.to_vec()));
    (app, database)
}

pub async fn create_realm(app: &App, name: &str) -> RealmScope {
    provision_first_realm(
        app,
        NewRealm {
            tenant_name: "Acme",
            realm_name: name,
        },
    )
    .await
    .expect("a realm");
    resolve_realm(app, name)
        .await
        .expect("the realm resolves")
        .1
}

/// The statement that sets `scope` for the transaction, for a hand in the database.
pub fn scope_statement(scope: RealmScope) -> String {
    format!(
        "SELECT set_config('saffui.tenant', '{}', true), set_config('saffui.realm', '{}', true)",
        scope.tenant().as_uuid(),
        scope.realm().as_uuid()
    )
}

pub async fn connect_as(database: &TestDatabase, role: &str) -> tokio_postgres::Client {
    database
        .plan(role)
        .connect_directly()
        .await
        .expect("a connection")
}
