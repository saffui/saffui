use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, CryptoProvider};
use pgcore::migrations::MigrationRunner;
use pgcore::tls::PgConnector;
use store::schema::migrations;
use tokio_postgres::{Client, Config, NoTls};

fn provider() -> OpenSslProvider {
    OpenSslProvider::new(&CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .expect("a software provider")
}

fn config() -> Config {
    std::env::var("SAFFUI_TEST_PG")
        .unwrap_or_else(|_| {
            panic!("these tests need a database: set SAFFUI_TEST_PG to a connection string")
        })
        .parse()
        .expect("SAFFUI_TEST_PG is a connection string")
}

async fn connect_with(config: &Config) -> Client {
    let (client, connection) = config
        .connect(NoTls)
        .await
        .expect("the test database accepts a connection");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

async fn connect() -> Client {
    connect_with(&config()).await
}

/// A connection as the application role, which is the one the rules apply to.
async fn connect_as_app() -> Client {
    let mut app = config();
    app.user("saffui_app").password("saffui_app_test");
    connect_with(&app).await
}

/// One database, so the tests take turns on it.
///
/// Each of these resets the schema, and two doing that at once is one test
/// reading rows another planted. Held for the whole body rather than around the
/// reset, since the rows a test writes have to be gone before the next starts.
static DATABASE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A clean database, then the schema.
async fn migrated() -> Client {
    let client = connect().await;
    client
        .batch_execute(
            "DROP SCHEMA public CASCADE; \
             CREATE SCHEMA public; \
             GRANT ALL ON SCHEMA public TO CURRENT_USER;",
        )
        .await
        .expect("the test database can be reset");

    MigrationRunner::new(migrations())
        .run(&config(), &PgConnector::disabled(), provider().digest())
        .await
        .expect("the schema applies");

    // The schema creates the role without a login, since a password belongs to
    // a deployment. A test is a deployment.
    client
        .batch_execute("ALTER ROLE saffui_app LOGIN PASSWORD 'saffui_app_test'")
        .await
        .expect("the application role can be given a password");

    connect_as_app().await
}

/// Say who this connection is reading for, until the end of the transaction.
async fn governed_by(client: &Client, tenant: &str) {
    client
        .execute(
            "SELECT set_config('saffui.current_tenant', $1, true)",
            &[&tenant],
        )
        .await
        .expect("the setting is writable");
}

/// The schema applies to an empty database, and applies once.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_schema_applies_and_stops() {
    let _turn = DATABASE.lock().await;
    let _ = migrated().await;

    let report = MigrationRunner::new(migrations())
        .run(&config(), &PgConnector::disabled(), provider().digest())
        .await
        .expect("a second run");
    assert!(
        report.is_up_to_date(),
        "the schema reapplied {:?}",
        report.applied
    );
}

/// Security is on and forced on every table the schema creates.
///
/// Read from the catalogue rather than from the text this time: what the
/// migration says and what the database ended up with are different claims, and
/// only one of them decides whether a row is visible.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn every_table_has_security_enabled_and_forced() {
    let _turn = DATABASE.lock().await;
    let client = migrated().await;

    let rows = client
        .query(
            "SELECT c.relname::text, c.relrowsecurity, c.relforcerowsecurity \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' AND c.relkind = 'r' \
               AND c.relname <> 'schema_migrations' \
             ORDER BY c.relname",
            &[],
        )
        .await
        .expect("the catalogue is readable");

    assert!(!rows.is_empty(), "the schema created no table");
    for row in rows {
        let table: String = row.get(0);
        assert!(row.get::<_, bool>(1), "{table} has security disabled");
        assert!(
            row.get::<_, bool>(2),
            "{table} does not force security, so the owning role bypasses it"
        );
    }
}

/// A connection that never said who it is reads nothing and writes nothing.
///
/// This is the property the whole layer rests on. A rule that matched everything
/// on an unset setting would be worse than no rule, because it would look like
/// one.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_ungoverned_connection_sees_and_writes_nothing() {
    let _turn = DATABASE.lock().await;
    let client = migrated().await;

    // Plant a tenant while governed, in its own transaction.
    client
        .batch_execute("BEGIN")
        .await
        .expect("a transaction opens");
    governed_by(&client, "acme").await;
    client
        .execute(
            "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $2)",
            &[&"acme", &"Acme"],
        )
        .await
        .expect("a governed connection may write its own tenant");
    client.batch_execute("COMMIT").await.expect("it commits");

    // And now, ungoverned, it is not there.
    let visible: i64 = client
        .query_one("SELECT count(*) FROM tenants", &[])
        .await
        .expect("the count runs")
        .get(0);
    assert_eq!(visible, 0, "an ungoverned connection read a tenant");

    let written = client
        .execute(
            "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $2)",
            &[&"other", &"Other"],
        )
        .await;
    assert!(
        written.is_err(),
        "an ungoverned connection wrote a tenant it could never read back"
    );
}

/// One tenant does not read another's, in either direction.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn one_tenant_never_reads_another() {
    let _turn = DATABASE.lock().await;
    let client = migrated().await;

    for tenant in ["acme", "globex"] {
        client.batch_execute("BEGIN").await.unwrap();
        governed_by(&client, tenant).await;
        client
            .execute(
                "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
                &[&tenant],
            )
            .await
            .expect("its own tenant");
        client
            .execute(
                "INSERT INTO realms (tenant, realm_id, name, display_name) \
                 VALUES ($1, $2, $2, $2)",
                &[&tenant, &format!("{tenant}-realm")],
            )
            .await
            .expect("its own realm");
        client.batch_execute("COMMIT").await.unwrap();
    }

    for (reader, expected) in [("acme", "acme-realm"), ("globex", "globex-realm")] {
        client.batch_execute("BEGIN").await.unwrap();
        governed_by(&client, reader).await;

        let tenants: Vec<String> = client
            .query("SELECT tenant_id FROM tenants", &[])
            .await
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(tenants, vec![reader.to_owned()], "{reader} read another");

        let realms: Vec<String> = client
            .query("SELECT realm_id FROM realms", &[])
            .await
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(realms, vec![expected.to_owned()]);

        client.batch_execute("COMMIT").await.unwrap();
    }
}

/// A tenant cannot plant a row under another's name, which is the write half of
/// the same rule and the one a read test would miss.
///
/// Both tenants are created first, each under its own governance. Without that,
/// a cross tenant realm is refused by the foreign key rather than by the policy,
/// and the test passes whether or not the rule is there.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_tenant_cannot_write_under_another_name() {
    let _turn = DATABASE.lock().await;
    let client = migrated().await;

    for tenant in ["acme", "globex"] {
        client.batch_execute("BEGIN").await.unwrap();
        governed_by(&client, tenant).await;
        client
            .execute(
                "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
                &[&tenant],
            )
            .await
            .expect("its own tenant");
        client.batch_execute("COMMIT").await.unwrap();
    }

    client.batch_execute("BEGIN").await.unwrap();
    governed_by(&client, "acme").await;

    let planted = client
        .execute(
            "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
            &[&"another"],
        )
        .await;
    assert!(planted.is_err(), "acme planted a tenant of its own naming");
    client.batch_execute("ROLLBACK").await.unwrap();

    // The realm policy is a separate rule, and the tenant it names exists, so
    // only the policy can refuse this.
    client.batch_execute("BEGIN").await.unwrap();
    governed_by(&client, "acme").await;
    client
        .execute(
            "INSERT INTO realms (tenant, realm_id, name, display_name) \
             VALUES ($1, $2, $2, $2)",
            &[&"acme", &"mine"],
        )
        .await
        .expect("acme may write its own realm");

    let planted = client
        .execute(
            "INSERT INTO realms (tenant, realm_id, name, display_name) \
             VALUES ($1, $2, $2, $2)",
            &[&"globex", &"theirs"],
        )
        .await;
    assert!(planted.is_err(), "acme planted a realm belonging to globex");

    client.batch_execute("ROLLBACK").await.unwrap();
}

/// The setting lasts for the transaction and no longer, so a pooled connection
/// handed on does not carry the last caller's tenant.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_setting_does_not_outlive_its_transaction() {
    let _turn = DATABASE.lock().await;
    let client = migrated().await;

    client.batch_execute("BEGIN").await.unwrap();
    governed_by(&client, "acme").await;
    let inside: Option<String> = client
        .query_one("SELECT current_setting('saffui.current_tenant', true)", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(inside.as_deref(), Some("acme"));
    client.batch_execute("COMMIT").await.unwrap();

    let after: Option<String> = client
        .query_one("SELECT current_setting('saffui.current_tenant', true)", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        after.is_none() || after.as_deref() == Some(""),
        "the tenant outlived its transaction as {after:?}"
    );
}

/// The application role holds nothing that would let it past the rules.
///
/// This is the half the schema owns. Everything above proves the policies work
/// for a role that is subject to them, and this proves the role the schema
/// creates is one of those: a superuser ignores row level security outright, and
/// so does any role granted BYPASSRLS, whatever a table says about forcing it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_application_role_cannot_step_past_the_rules() {
    let _turn = DATABASE.lock().await;
    let _client = migrated().await;

    let owner = connect().await;
    let row = owner
        .query_one(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'saffui_app'",
            &[],
        )
        .await
        .expect("the schema created the application role");

    assert!(
        !row.get::<_, bool>(0),
        "the application role is a superuser"
    );
    assert!(
        !row.get::<_, bool>(1),
        "the application role may bypass row level security"
    );

    // And the connection these tests use really is that role, so what they
    // proved was proved under it.
    let app = connect_as_app().await;
    let who: String = app
        .query_one("SELECT current_user::text", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(who, "saffui_app");
}

/// A realm's contents are scoped by both keys, so a directory-wide transaction
/// that names no realm sees none of them.
///
/// That is what the empty realm on a tenant-wide context buys: it matches
/// nothing on a table keyed by both rather than everything.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realms_contents_need_both_keys() {
    let _turn = DATABASE.lock().await;
    let client = migrated().await;

    client.batch_execute("BEGIN").await.unwrap();
    governed_by(&client, "acme").await;
    client
        .execute(
            "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
            &[&"acme"],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO realms (tenant, realm_id, name, display_name) VALUES ($1, $2, $2, $2)",
            &[&"acme", &"main"],
        )
        .await
        .unwrap();
    client.batch_execute("COMMIT").await.unwrap();

    // Naming only the tenant, a user cannot be written or read.
    client.batch_execute("BEGIN").await.unwrap();
    governed_by(&client, "acme").await;
    assert!(
        client
            .execute(
                "INSERT INTO users (tenant, realm_id, user_id, user_name) \
                 VALUES ($1, $2, $3, $3)",
                &[&"acme", &"main", &"ada"],
            )
            .await
            .is_err(),
        "a user was written by a transaction that named no realm"
    );
    client.batch_execute("ROLLBACK").await.unwrap();

    // Naming both, it can.
    client.batch_execute("BEGIN").await.unwrap();
    governed_by(&client, "acme").await;
    client
        .execute(
            "SELECT set_config('saffui.current_realm', $1, true)",
            &[&"main"],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO users (tenant, realm_id, user_id, user_name) VALUES ($1, $2, $3, $3)",
            &[&"acme", &"main", &"ada"],
        )
        .await
        .expect("both keys named");

    // And a realm it does not name stays invisible even inside the same tenant.
    assert!(
        client
            .execute(
                "INSERT INTO users (tenant, realm_id, user_id, user_name) \
                 VALUES ($1, $2, $3, $3)",
                &[&"acme", &"other", &"eve"],
            )
            .await
            .is_err(),
        "a user was written into a realm the transaction did not name"
    );
    client.batch_execute("ROLLBACK").await.unwrap();
}

/// An identifier is unique within its realm and nowhere else.
///
/// Made globally unique, creating a user with a chosen identifier tells the
/// caller whether it already exists somewhere they cannot read, which is one
/// tenant learning another's identifiers by collision.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_identifier_says_nothing_about_another_realm() {
    let _turn = DATABASE.lock().await;
    let client = migrated().await;

    for tenant in ["acme", "globex"] {
        client.batch_execute("BEGIN").await.unwrap();
        governed_by(&client, tenant).await;
        client
            .execute(
                "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
                &[&tenant],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO realms (tenant, realm_id, name, display_name) VALUES ($1, $2, $2, $2)",
                &[&tenant, &"main"],
            )
            .await
            .unwrap();
        client.batch_execute("COMMIT").await.unwrap();

        client.batch_execute("BEGIN").await.unwrap();
        governed_by(&client, tenant).await;
        client
            .execute(
                "SELECT set_config('saffui.current_realm', $1, true)",
                &[&"main"],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO users (tenant, realm_id, user_id, user_name) VALUES ($1, $2, $3, $3)",
                &[&tenant, &"main", &"shared-id"],
            )
            .await
            .expect("the same identifier is free in each realm");
        client.batch_execute("COMMIT").await.unwrap();
    }

    // And reading needs both keys too, not only writing. A realm's users are
    // invisible from another realm of the same tenant.
    client.batch_execute("BEGIN").await.unwrap();
    governed_by(&client, "acme").await;
    client
        .execute(
            "SELECT set_config('saffui.current_realm', $1, true)",
            &[&"main"],
        )
        .await
        .unwrap();
    let own: i64 = client
        .query_one("SELECT count(*) FROM users", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(own, 1, "its own realm's user");

    client
        .execute(
            "SELECT set_config('saffui.current_realm', $1, true)",
            &[&"another"],
        )
        .await
        .unwrap();
    let elsewhere: i64 = client
        .query_one("SELECT count(*) FROM users", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        elsewhere, 0,
        "a realm read another realm's users inside the same tenant"
    );
    client.batch_execute("COMMIT").await.unwrap();
}

/// A row cannot name a realm belonging to somebody else.
///
/// Referencing the realm alone leaves the pair free to disagree, and a row whose
/// tenant is not its realm's tenant is visible to one and owned by the other.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_row_cannot_name_another_tenants_realm() {
    let _turn = DATABASE.lock().await;
    let client = migrated().await;

    client.batch_execute("BEGIN").await.unwrap();
    governed_by(&client, "globex").await;
    client
        .execute(
            "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
            &[&"globex"],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO realms (tenant, realm_id, name, display_name) VALUES ($1, $2, $2, $2)",
            &[&"globex", &"theirs"],
        )
        .await
        .unwrap();
    client.batch_execute("COMMIT").await.unwrap();

    client.batch_execute("BEGIN").await.unwrap();
    governed_by(&client, "acme").await;
    client
        .execute(
            "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
            &[&"acme"],
        )
        .await
        .unwrap();
    client
        .execute(
            "SELECT set_config('saffui.current_realm', $1, true)",
            &[&"theirs"],
        )
        .await
        .unwrap();

    assert!(
        client
            .execute(
                "INSERT INTO users (tenant, realm_id, user_id, user_name) \
                 VALUES ($1, $2, $3, $3)",
                &[&"acme", &"theirs", &"ada"],
            )
            .await
            .is_err(),
        "a user was written naming a realm that belongs to another tenant"
    );
    client.batch_execute("ROLLBACK").await.unwrap();
}

/// An encryption registration is a pair. Half of one is not a registration, and
/// the column that holds the other half has nothing to say on its own.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn half_an_encryption_registration_is_refused() {
    let _turn = DATABASE.lock().await;
    let client = migrated().await;

    client.batch_execute("BEGIN").await.unwrap();
    governed_by(&client, "acme").await;
    client
        .execute(
            "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
            &[&"acme"],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO realms (tenant, realm_id, name, display_name) VALUES ($1, $2, $2, $2)",
            &[&"acme", &"main"],
        )
        .await
        .unwrap();
    client
        .execute(
            "SELECT set_config('saffui.current_realm', $1, true)",
            &[&"main"],
        )
        .await
        .unwrap();

    for (alg, enc) in [(Some("RSA-OAEP"), None), (None, Some("A128GCM"))] {
        // A refused write aborts the transaction, so each attempt gets a point
        // to come back to rather than taking the setup down with it.
        client.batch_execute("SAVEPOINT attempt").await.unwrap();
        let attempt = client
            .execute(
                "INSERT INTO clients (tenant, realm_id, client_id, name, display_name, \
                 id_token_encryption_alg, id_token_encryption_enc) \
                 VALUES ($1, $2, $3, $3, $3, $4, $5)",
                &[&"acme", &"main", &"app", &alg, &enc],
            )
            .await;
        assert!(attempt.is_err(), "half a registration was written");
        client
            .batch_execute("ROLLBACK TO SAVEPOINT attempt")
            .await
            .unwrap();
    }

    client
        .execute(
            "INSERT INTO clients (tenant, realm_id, client_id, name, display_name, \
             id_token_encryption_alg, id_token_encryption_enc) \
             VALUES ($1, $2, $3, $3, $3, $4, $5)",
            &[&"acme", &"main", &"app", &"RSA-OAEP", &"A128GCM"],
        )
        .await
        .expect("both halves together");

    client.batch_execute("ROLLBACK").await.unwrap();
}
