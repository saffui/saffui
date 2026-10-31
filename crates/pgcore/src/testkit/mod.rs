//! A database per test, cloned from a template that carries the migrations.
//! The cluster is named by `SAFFUI_TEST_PG`, a connection string of a role
//! that may create databases and runs the migrations: neither a superuser nor
//! a role with BYPASSRLS, which `migrate` refuses. It holds `pg_signal_backend`
//! to end the sessions other roles keep on a database it drops, but not those
//! of a superuser: a test ends its own. A database test without it fails: it
//! never passes by being skipped.

use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio_postgres::config::Host;
use tokio_postgres::{Client, Config, NoTls};

use crate::connect::{ConnectionPlan, TlsMode, plan_connection};
use crate::migrate::{Migration, apply_pending};

const CLUSTER_VARIABLE: &str = "SAFFUI_TEST_PG";
const TEMPLATE_LOCK: i64 = 0x7361_6666_7569_0002;

static CREATED: AtomicU32 = AtomicU32::new(0);

/// One database, dropped when the value goes.
pub struct TestDatabase {
    name: String,
    cluster: Config,
}

impl TestDatabase {
    /// Creates a database with `migrations` applied.
    ///
    /// # Panics
    ///
    /// Panics when the cluster is not named, cannot be reached, or refuses.
    pub async fn create(migrations: &[Migration]) -> Self {
        let cluster = read_cluster();
        let admin = connect(&cluster).await;
        let template = prepare_template(&admin, &cluster, migrations).await;

        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after 1970");
        let name = format!(
            "saffui_t_{}_{}_{}",
            std::process::id(),
            CREATED.fetch_add(1, Ordering::Relaxed),
            since_epoch.subsec_nanos()
        );
        admin
            .batch_execute(&format!("CREATE DATABASE {name} TEMPLATE {template}"))
            .await
            .expect("a database cloned from the template");
        Self { name, cluster }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// A connection string to this database as `role`.
    #[must_use]
    pub fn connection_string(&self, role: &str) -> String {
        describe_connection(&self.cluster, role, &self.name)
    }

    /// The accepted plan of a connection to this database as `role`.
    ///
    /// # Panics
    ///
    /// Panics when the test cluster is not on this machine.
    #[must_use]
    pub fn plan(&self, role: &str) -> ConnectionPlan {
        plan_connection(&self.connection_string(role), Some(TlsMode::Disable), None)
            .expect("a plan for the test cluster")
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let (cluster, name) = (self.cluster.clone(), self.name.clone());
        // Dropping cannot wait on the runtime of the test: a thread of its own does.
        let dropped = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime to drop the test database");
            runtime.block_on(async {
                let admin = connect(&cluster).await;
                // The role of the cluster string must be allowed to end the
                // sessions other roles hold, or the database outlives the test.
                if let Err(error) = admin
                    .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                    .await
                {
                    eprintln!("the test database {name} was not dropped: {error}");
                }
            });
        });
        let _ = dropped.join();
    }
}

fn read_cluster() -> Config {
    let written = std::env::var(CLUSTER_VARIABLE).unwrap_or_else(|_| {
        panic!("{CLUSTER_VARIABLE} is not set: this test needs a PostgreSQL cluster")
    });
    written
        .parse()
        .unwrap_or_else(|_| panic!("{CLUSTER_VARIABLE} is not a connection string"))
}

async fn connect(config: &Config) -> Client {
    let (client, connection) = config
        .connect(NoTls)
        .await
        .expect("a connection to the test cluster");
    tokio::spawn(connection);
    client
}

/// Builds the template once per set of migrations, whichever test or process
/// asks first: the others wait on the lock and find it there.
async fn prepare_template(admin: &Client, cluster: &Config, migrations: &[Migration]) -> String {
    let texts: Vec<&str> = migrations.iter().map(|migration| migration.sql).collect();
    let digest: String = admin
        .query_one(
            "SELECT encode(sha256(convert_to(array_to_string($1::text[], chr(30)), 'UTF8')), 'hex')",
            &[&texts],
        )
        .await
        .expect("the digest of the migrations")
        .get(0);
    let template = format!("saffui_tpl_{}_{}", migrations.len(), &digest[..16]);

    admin
        .execute("SELECT pg_advisory_lock($1)", &[&TEMPLATE_LOCK])
        .await
        .expect("the template lock");
    let known = admin
        .query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&template])
        .await
        .expect("the list of databases");
    if known.is_none() {
        admin
            .batch_execute(&format!("CREATE DATABASE {template}"))
            .await
            .expect("an empty template");
        let owner = cluster
            .get_user()
            .expect("a user in the test cluster string");
        let plan = plan_connection(
            &describe_connection(cluster, owner, &template),
            Some(TlsMode::Disable),
            None,
        )
        .expect("a plan for the template");
        if let Err(error) = apply_pending(&plan, migrations).await {
            let _ = admin
                .batch_execute(&format!("DROP DATABASE {template} WITH (FORCE)"))
                .await;
            panic!("the template cannot be migrated: {error:?}");
        }
    }
    admin
        .execute("SELECT pg_advisory_unlock($1)", &[&TEMPLATE_LOCK])
        .await
        .expect("the template lock released");
    template
}

fn describe_connection(cluster: &Config, role: &str, database: &str) -> String {
    let host = match cluster.get_hosts().first() {
        Some(Host::Tcp(name)) => name.clone(),
        #[cfg(unix)]
        Some(Host::Unix(path)) => path.display().to_string(),
        None => "127.0.0.1".to_owned(),
    };
    let port = cluster.get_ports().first().copied().unwrap_or(5432);
    format!("host={host} port={port} user={role} dbname={database}")
}
