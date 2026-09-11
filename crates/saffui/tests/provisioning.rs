use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, CryptoProvider};
use pgcore::migrations::MigrationRunner;
use pgcore::tls::PgConnector;
use std::process::{Command, Output};
use store::schema::migrations;
use tokio_postgres::{Config, NoTls};

fn provider() -> OpenSslProvider {
    OpenSslProvider::new(&CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .unwrap()
}

fn provision(base_url: &str, database: &str, extra: &[String]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_saffui"));
    command.args(["provision", "--tenant=cli-atomic", "--realm=cli-atomic"]);
    command.args(extra).env(
        "SAFFUI_DATABASE_URL",
        format!("{base_url} user=saffui_app password=saffui_app_test dbname={database}"),
    );
    command
        .env("SAFFUI_PUBLIC_ORIGIN", "https://saffui.test")
        .env("SAFFUI_ADMIN_AUDIENCES", "saffui-console")
        .env("SAFFUI_ADMIN_PARTIES", "saffui-console")
        .env(
            "SAFFUI_CRYPTO_KEK",
            "a-development-wrapping-key-of-decent-length",
        )
        .output()
        .unwrap()
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn cli_provision_is_atomic_and_idempotent() {
    let base_url = std::env::var("SAFFUI_TEST_PG").expect("SAFFUI_TEST_PG");
    let base: Config = base_url.parse().unwrap();
    let database = format!("{}_cli_provision", base.get_dbname().unwrap_or("saffui"));
    let (root, connection) = base.connect(NoTls).await.unwrap();
    tokio::spawn(connection);
    let _ = root
        .execute(&format!("CREATE DATABASE \"{database}\""), &[])
        .await;

    let mut owner_config = base.clone();
    owner_config.dbname(&database);
    let (owner, connection) = owner_config.connect(NoTls).await.unwrap();
    tokio::spawn(connection);
    owner
        .batch_execute(
            "DROP SCHEMA public CASCADE; CREATE SCHEMA public; \
             GRANT ALL ON SCHEMA public TO CURRENT_USER;",
        )
        .await
        .unwrap();
    MigrationRunner::new(migrations())
        .run(&owner_config, &PgConnector::disabled(), provider().digest())
        .await
        .unwrap();
    owner
        .batch_execute("ALTER ROLE saffui_app LOGIN PASSWORD 'saffui_app_test'")
        .await
        .unwrap();
    let missing = format!("/tmp/saffui-missing-jwks-{}", std::process::id());
    let outcome = provision(
        &base_url,
        &database,
        &[format!("--fapi-client=broken={missing}")],
    );
    assert!(!outcome.status.success());
    assert!(
        String::from_utf8_lossy(&outcome.stderr).contains("cannot read"),
        "the command failed before the late provisioning step: {}",
        String::from_utf8_lossy(&outcome.stderr)
    );

    let tenant_count: i64 = owner
        .query_one(
            "SELECT count(*) FROM tenants WHERE tenant_id = 'cli-atomic'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let realm_count: i64 = owner
        .query_one(
            "SELECT count(*) FROM realms WHERE realm_id = 'cli-atomic'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!((tenant_count, realm_count), (0, 0));

    for _ in 0..2 {
        let outcome = provision(&base_url, &database, &[]);
        assert!(
            outcome.status.success(),
            "idempotent provisioning failed: {}",
            String::from_utf8_lossy(&outcome.stderr)
        );
    }
    let tenant_count: i64 = owner
        .query_one(
            "SELECT count(*) FROM tenants WHERE tenant_id = 'cli-atomic'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let realm_count: i64 = owner
        .query_one(
            "SELECT count(*) FROM realms WHERE realm_id = 'cli-atomic'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!((tenant_count, realm_count), (1, 1));
}
