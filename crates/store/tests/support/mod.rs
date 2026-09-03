use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, CryptoProvider};
use deadpool_postgres::{Manager, Object, Pool, Transaction};
use models::auditable::AuditableModel;
use models::entities::client::ClientCreateModel;
use models::entities::realm::RealmCreateModel;
use models::entities::tenant::TenantCreateModel;
use models::entities::user::UserCreateModel;
use pgcore::migrations::MigrationRunner;
use pgcore::tls::PgConnector;
use store::providers::{clients, realms, tenants, users};
use store::schema::migrations;
use store::tenancy::{Tenancy, TenantContext};
use tokio::sync::{Mutex, MutexGuard};
use tokio_postgres::{Config, NoTls};

static DATABASE: Mutex<()> = Mutex::const_new(());

/// The provider these tests reach crypto through, as everything else does.
pub fn provider() -> OpenSslProvider {
    OpenSslProvider::new(&CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .expect("a software provider")
}

fn owner_config() -> Config {
    let mut config: Config = std::env::var("SAFFUI_TEST_PG")
        .unwrap_or_else(|_| panic!("these tests need a database: set SAFFUI_TEST_PG"))
        .parse()
        .expect("SAFFUI_TEST_PG is a connection string");
    // One database per test binary, its name derived from the binary's own,
    // so grouped binaries run side by side without trampling each other's
    // schema. `ensured_database` creates it on first contact.
    if let Some(binary) = binary_stem() {
        let base = config.get_dbname().unwrap_or("saffui").to_owned();
        config.dbname(format!("{base}_{binary}"));
    }
    config
}

/// The test binary's own name, hash suffix shorn: `suite_admin-3fe9` is
/// `suite_admin`, and one binary is one database.
fn binary_stem() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let stem = exe.file_stem()?.to_str()?.to_owned();
    Some(match stem.rsplit_once('-') {
        Some((name, _)) => name.to_owned(),
        None => stem,
    })
}

/// Make this binary's database exist, from the base one the variable names.
/// Creation races between two binaries land on the duplicate error, which is
/// the other one having won, and winning is all that was wanted.
async fn ensured_database() {
    let base: Config = std::env::var("SAFFUI_TEST_PG")
        .expect("checked at owner_config")
        .parse()
        .expect("checked at owner_config");
    let mine = owner_config();
    let (Some(base_db), Some(my_db)) = (base.get_dbname(), mine.get_dbname()) else {
        return;
    };
    if base_db == my_db {
        return;
    }
    let my_db = my_db.to_owned();
    let (client, connection) = base.connect(NoTls).await.expect("the base database");
    tokio::spawn(connection);
    let _ = client
        .execute(&format!("CREATE DATABASE \"{my_db}\""), &[])
        .await;
}

/// A migrated database with a turn on it, and whatever rows were asked for.
pub struct Fixture {
    pool: Pool,
    _turn: MutexGuard<'static, ()>,
    tenancy: Tenancy,
}

impl Fixture {
    /// A clean database with the schema and nothing in it.
    pub async fn empty() -> Self {
        let turn = DATABASE.lock().await;

        ensured_database().await;
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
            .expect("the role gets a password");

        let mut app = owner_config();
        app.user("saffui_app").password("saffui_app_test");
        let pool = Pool::builder(Manager::new(app, NoTls))
            .max_size(4)
            .build()
            .expect("a pool");

        Fixture {
            pool,
            _turn: turn,
            tenancy: Tenancy::unpinned(),
        }
    }

    /// The same, with a tenant, a realm and a user in it.
    #[allow(dead_code, reason = "each test binary compiles this module on its own")]
    pub async fn with_user() -> Self {
        let fixture = Self::empty().await;
        fixture.plant(false).await;
        fixture
    }

    /// A connection as the role that owns the tables.
    ///
    /// The application role is refused a good deal on purpose, so a test that
    /// needs to do what only an owner can, such as altering a record the
    /// application may only read, asks for this instead of being given rights
    /// the application should not have.
    #[allow(dead_code, reason = "each test binary compiles this module on its own")]
    pub async fn owner(&self) -> tokio_postgres::Client {
        ensured_database().await;
        let (client, connection) = owner_config().connect(NoTls).await.expect("the owner");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
    }

    /// The same again, and a client.
    #[allow(dead_code, reason = "each test binary compiles this module on its own")]
    pub async fn with_user_and_client() -> Self {
        let fixture = Self::empty().await;
        fixture.plant(true).await;
        fixture
    }

    /// A connection from the pool.
    ///
    /// Released once its transaction has committed. A guard stays borrowed until
    /// it leaves scope and shadowing it does not release one, so a test taking
    /// more in a row than the pool holds waits on one that is never coming back.
    pub async fn connection(&self) -> Object {
        self.pool.get().await.expect("a connection")
    }

    /// A transaction saying who it is for.
    pub async fn scoped<'c>(
        &self,
        connection: &'c mut Object,
        context: &TenantContext,
    ) -> Transaction<'c> {
        self.tenancy
            .transaction(connection, context)
            .await
            .expect("a scoped transaction")
    }

    async fn plant(&self, with_client: bool) {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::tenant_wide("acme"))
            .await;

        let tenant: models::entities::tenant::TenantModel = TenantCreateModel {
            tenant_id: "acme".into(),
            display_name: "Acme".into(),
            region: None,
            limits: None,
            created_by: Some("root".into()),
        }
        .into();
        tenants::create(&transaction, &tenant).await.unwrap();

        let realm = RealmCreateModel {
            name: "main".into(),
            display_name: "Main".into(),
            enabled: true,
        }
        .into_model(
            "main".into(),
            AuditableModel::from_creator("acme".into(), "root".into()),
        );
        realms::create(&transaction, &realm).await.unwrap();
        transaction.commit().await.unwrap();
        drop(connection);

        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new("acme", "main"))
            .await;

        let user = UserCreateModel {
            user_name: "ada".into(),
            enabled: true,
            email: "ada@example.test".into(),
            email_verified: Some(true),
            phone_number: None,
            phone_number_verified: None,
            required_actions: None,
            not_before: None,
            user_storage: None,
            attributes: None,
            is_service_account: None,
            service_account_client_link: None,
        }
        .into_model(
            "ada".into(),
            "main".into(),
            AuditableModel::from_creator("acme".into(), "root".into()),
        );
        users::create(&transaction, &user).await.unwrap();

        if with_client {
            let client = ClientCreateModel {
                name: "app".into(),
                display_name: "App".into(),
                description: String::new(),
                enabled: Some(true),
            }
            .into_model(
                "app".into(),
                "main".into(),
                AuditableModel::from_creator("acme".into(), "root".into()),
            );
            clients::create(&transaction, &client).await.unwrap();
        }

        transaction.commit().await.unwrap();
    }
}
