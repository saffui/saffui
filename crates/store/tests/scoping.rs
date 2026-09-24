use std::time::{Duration, Instant};

use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, CryptoProvider};
use deadpool_postgres::{Manager, Pool};
use pgcore::migrations::MigrationRunner;
use pgcore::tls::PgConnector;
use store::error::StoreError;
use store::schema::migrations;
use store::tenancy::{Tenancy, TenantContext};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_postgres::config::Host;
use tokio_postgres::{Config, NoTls};

static DATABASE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn owner_config() -> Config {
    std::env::var("SAFFUI_TEST_PG")
        .unwrap_or_else(|_| panic!("these tests need a database: set SAFFUI_TEST_PG"))
        .parse()
        .expect("SAFFUI_TEST_PG is a connection string")
}

fn app_config() -> Config {
    let mut config = owner_config();
    config.user("saffui_app").password("saffui_app_test");
    config
}

fn provider() -> OpenSslProvider {
    OpenSslProvider::new(&CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .expect("a software provider")
}

/// A clean database with the schema, and a pool of exactly one connection so a
/// second borrow is the same physical connection as the first.
async fn one_connection_pool() -> Pool {
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
        .expect("the application role gets a password");

    Pool::builder(Manager::new(app_config(), NoTls))
        .max_size(1)
        .build()
        .expect("a pool of one")
}

async fn plant(tenancy: &Tenancy, tenant: &str) {
    let transaction = tenancy
        .begin(&TenantContext::tenant_wide(tenant))
        .await
        .expect("a scoped unit of work");
    transaction
        .execute(
            "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
            &[&tenant],
        )
        .await
        .expect("its own tenant");
    transaction.commit().await.expect("it commits");
}

/// A scoped transaction reads its own tenant and nobody else's.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_scoped_transaction_reads_only_its_own() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned(pool.clone());

    plant(&tenancy, "acme").await;
    plant(&tenancy, "globex").await;

    for tenant in ["acme", "globex"] {
        let transaction = tenancy
            .begin(&TenantContext::tenant_wide(tenant))
            .await
            .unwrap();
        let seen: Vec<String> = transaction
            .query("SELECT tenant_id FROM tenants", &[])
            .await
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(seen, vec![tenant.to_owned()]);
        transaction.commit().await.unwrap();
    }
}

/// The setting does not survive onto the next borrower.
///
/// The pool holds one connection, so the second borrow is the first one handed
/// back. A setting written for the session rather than the transaction would
/// still be there, and the next caller would read another tenant's rows while
/// believing the rules were doing their work.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_returned_connection_carries_no_tenant() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned(pool.clone());

    plant(&tenancy, "acme").await;

    let connection = pool.get().await.unwrap();
    let left_over: Option<String> = connection
        .query_one("SELECT current_setting('saffui.current_tenant', true)", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        left_over.is_none() || left_over.as_deref() == Some(""),
        "the connection came back still scoped to {left_over:?}"
    );

    let seen: i64 = connection
        .query_one("SELECT count(*) FROM tenants", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(seen, 0, "an unscoped borrow read a tenant");
}

/// Dropping without committing rolls back, so the boundary is the drop rather
/// than a call somebody has to remember.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn dropping_a_unit_rolls_it_back() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned(pool.clone());

    {
        let transaction = tenancy
            .begin(&TenantContext::tenant_wide("acme"))
            .await
            .unwrap();
        transaction
            .execute(
                "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
                &[&"acme"],
            )
            .await
            .unwrap();
        // No commit.
    }

    let transaction = tenancy
        .begin(&TenantContext::tenant_wide("acme"))
        .await
        .unwrap();
    let seen: i64 = transaction
        .query_one("SELECT count(*) FROM tenants", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(seen, 0, "a dropped unit left a row behind");
}

/// A statement that failed leaves nothing to commit, and the commit says so
/// instead of reporting writes the database already threw away.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_commit_after_a_failed_statement_is_refused() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned(pool.clone());

    let transaction = tenancy
        .begin(&TenantContext::tenant_wide("acme"))
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
            &[&"acme"],
        )
        .await
        .unwrap();
    assert!(transaction.batch_execute("SELECT 1 / 0").await.is_err());
    assert!(
        matches!(transaction.commit().await, Err(StoreError::Backend)),
        "a rolled back transaction was reported as committed"
    );

    // The one connection comes back idle, and nothing was kept.
    let transaction = tenancy
        .begin(&TenantContext::tenant_wide("acme"))
        .await
        .unwrap();
    let seen: i64 = transaction
        .query_one("SELECT count(*) FROM tenants", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(seen, 0);
}

/// A unit whose rollback never gets to run leaves the pool instead of going
/// back into it half way through a transaction.
///
/// The connection is opened on the test's runtime, so it outlives the one the
/// unit is abandoned on, and the unit is dropped as that runtime stops, which
/// is exactly when the rollback it hands over is thrown away unrun.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_abandoned_unit_never_goes_back_dirty() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned(pool.clone());
    drop(pool.get().await.unwrap());

    let abandoning = tenancy.clone();
    tokio::task::spawn_blocking(move || {
        let stopping = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        stopping.block_on(async {
            let unit = abandoning
                .begin(&TenantContext::tenant_wide("acme"))
                .await
                .unwrap();
            unit.execute(
                "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
                &[&"acme"],
            )
            .await
            .unwrap();
            drop(unit);
        });
        drop(stopping);
    })
    .await
    .unwrap();

    assert_eq!(
        pool.status().size,
        0,
        "the abandoned connection went back into the pool"
    );
    let next = tenancy
        .begin(&TenantContext::tenant_wide("acme"))
        .await
        .unwrap();
    let seen: i64 = next
        .query_one("SELECT count(*) FROM tenants", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(seen, 0, "the next caller saw an abandoned write");
}

/// A pinned node refuses a realm pinned elsewhere before a connection is taken.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_mismatched_region_is_refused_before_anything_opens() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;

    let elsewhere = Tenancy::in_region(pool.clone(), "eu-west");
    let context = TenantContext::new("acme", "realm-1").with_region(Some("af-south".into()));

    assert_eq!(
        elsewhere
            .begin(&context)
            .await
            .err()
            .expect("a mismatched region is refused"),
        StoreError::Residency {
            node: "eu-west".to_owned(),
            pin: "af-south".to_owned()
        }
    );
    assert_eq!(
        pool.status().size,
        0,
        "a refused unit took a connection on its way to the refusal"
    );

    // The same node serves a realm that pins nothing.
    let transaction = elsewhere
        .begin(&TenantContext::tenant_wide("acme"))
        .await
        .expect("an unpinned realm is served anywhere");
    transaction.commit().await.unwrap();
}

/// A snapshot transaction is read only and holds one snapshot, so two reads of
/// the same table agree even when another connection writes between them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_snapshot_does_not_move_under_a_reader() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned(pool.clone());

    plant(&tenancy, "acme").await;

    // A second connection, so the write is not on the reader's own.
    let (writer, connection) = app_config().connect(NoTls).await.expect("a second client");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let snapshot = tenancy
        .begin_snapshot(&TenantContext::tenant_wide("acme"))
        .await
        .unwrap();

    let before: i64 = snapshot
        .query_one("SELECT count(*) FROM realms", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(before, 0);

    writer.batch_execute("BEGIN").await.unwrap();
    writer
        .execute(
            "SELECT set_config('saffui.current_tenant', $1, true)",
            &[&"acme"],
        )
        .await
        .unwrap();
    writer
        .execute(
            "INSERT INTO realms (tenant, realm_id, name, display_name) VALUES ($1, $2, $2, $2)",
            &[&"acme", &"written-after"],
        )
        .await
        .unwrap();
    writer.batch_execute("COMMIT").await.unwrap();

    let after: i64 = snapshot
        .query_one("SELECT count(*) FROM realms", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(after, before, "the snapshot moved under the reader");

    // The write really did land, so the reader is holding a snapshot rather than
    // reading a table nothing changed.
    writer.batch_execute("BEGIN").await.unwrap();
    writer
        .execute(
            "SELECT set_config('saffui.current_tenant', $1, true)",
            &[&"acme"],
        )
        .await
        .unwrap();
    let landed: i64 = writer
        .query_one("SELECT count(*) FROM realms", &[])
        .await
        .unwrap()
        .get(0);
    writer.batch_execute("COMMIT").await.unwrap();
    assert_eq!(landed, 1, "the write did not land at all");

    // And it will not write.
    assert!(
        snapshot
            .execute(
                "INSERT INTO realms (tenant, realm_id, name, display_name) \
                 VALUES ('acme','x','x','x')",
                &[]
            )
            .await
            .is_err(),
        "a read only transaction wrote"
    );
}

/// A statement is prepared once on a connection and kept, so running it again
/// is one round trip rather than a preparation and then an execution.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_statement_is_prepared_once_per_connection() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned(pool.clone());
    let acme = TenantContext::tenant_wide("acme");

    for _ in 0..2 {
        let unit = tenancy.begin(&acme).await.unwrap();
        unit.query("SELECT tenant_id FROM tenants", &[])
            .await
            .unwrap();
        unit.commit().await.unwrap();
    }

    let unit = tenancy.begin(&acme).await.unwrap();
    let kept: i64 = unit
        .query_one(
            "SELECT count(*) FROM pg_prepared_statements \
             WHERE statement = 'SELECT tenant_id FROM tenants'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(kept, 1, "the statement was not kept between the two units");
}

/// Behind a pooler the bound on an idle transaction rides in the transaction,
/// a pooler refusing it at startup, and leaves the connection as it was.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn behind_a_pooler_the_idle_bound_rides_in_the_unit() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned(pool.clone()).behind_a_pooler(Duration::from_secs(7));

    let unit = tenancy
        .begin(&TenantContext::tenant_wide("acme"))
        .await
        .unwrap();
    let inside: String = unit
        .query_one("SHOW idle_in_transaction_session_timeout", &[])
        .await
        .unwrap()
        .get(0);
    unit.commit().await.unwrap();
    assert_eq!(inside, "7s");

    let after: String = pool
        .get()
        .await
        .unwrap()
        .query_typed_one("SHOW idle_in_transaction_session_timeout", &[])
        .await
        .unwrap()
        .get(0);
    assert_ne!(
        after, "7s",
        "the bound outlived the transaction it was set in"
    );
}

/// Behind a pooler the bound rides in the request that opens the unit, so a
/// unit still opens in one round trip and reads and commits as it did.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn behind_a_pooler_a_unit_still_opens_in_one_round_trip() {
    const READ: &str = "SELECT tenant_id FROM tenants";

    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    plant(&Tenancy::unpinned(pool), "acme").await;
    let acme = TenantContext::tenant_wide("acme");

    let relay = Relay::start().await;
    let relayed =
        Tenancy::unpinned(relay.one_connection_pool()).behind_a_pooler(Duration::from_secs(7));
    // The first unit opens the connection, whose handshake waits on answers,
    // and prepares the scope and the read.
    let first = relayed.begin(&acme).await.unwrap();
    first.query(READ, &[]).await.unwrap();
    first.commit().await.unwrap();

    let unit = relay
        .run_in_one_round_trip("opening", 2, relayed.begin(&acme))
        .await
        .unwrap();
    relay
        .run_in_one_round_trip("reading", 1, unit.query(READ, &[]))
        .await
        .unwrap();
    relay
        .run_in_one_round_trip("committing", 2, unit.commit())
        .await
        .unwrap();
}

/// The role the served connections log in as, as the database sees it: the
/// application role answers to row security, the owner's superuser does not.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_served_role_is_read_as_the_database_sees_it() {
    let _turn = DATABASE.lock().await;
    let served = Tenancy::unpinned(one_connection_pool().await)
        .read_served_role()
        .await
        .unwrap();
    assert_eq!(served.name, "saffui_app");
    assert!(!served.above_the_rules);

    let owner = Pool::builder(Manager::new(owner_config(), NoTls))
        .max_size(1)
        .build()
        .expect("a pool of one");
    assert!(
        Tenancy::unpinned(owner)
            .read_served_role()
            .await
            .unwrap()
            .above_the_rules,
        "a superuser was read as answering to row security"
    );
}

/// What a connection keeps has a ceiling. A statement built at run time is a
/// new text for every shape, and a long lived connection would otherwise keep
/// one of each on both sides of the wire.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn kept_statements_stay_under_a_ceiling() {
    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned(pool.clone());

    let unit = tenancy
        .begin(&TenantContext::tenant_wide("acme"))
        .await
        .unwrap();
    for shape in 0..600 {
        unit.query_one(format!("SELECT {shape}::int").as_str(), &[])
            .await
            .unwrap();
    }
    let kept: i64 = unit
        .query_one("SELECT count(*) FROM pg_prepared_statements", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        kept < 512,
        "600 distinct statements left {kept} prepared on one connection"
    );
}

/// A relay between a pool and the database that counts the requests the client
/// sends and can hold back the answers.
///
/// A request is a simple query or a sync closing an extended one, and the
/// database answers each. Requests that all leave while the answers are held
/// share one round trip.
struct Relay {
    port: u16,
    requests: watch::Receiver<usize>,
    answering: watch::Sender<bool>,
}

impl Relay {
    async fn start() -> Self {
        let database = owner_config();
        let [Host::Tcp(host), ..] = database.get_hosts() else {
            panic!("the relay reaches the database over TCP");
        };
        let upstream = (
            host.clone(),
            database.get_ports().first().copied().unwrap_or(5432),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (counted, requests) = watch::channel(0);
        let (answering, held) = watch::channel(true);
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let database = TcpStream::connect(&upstream).await.unwrap();
                let (from_client, to_client) = client.into_split();
                let (from_database, to_database) = database.into_split();
                tokio::spawn(count_requests(from_client, to_database, counted.clone()));
                tokio::spawn(hold_answers(from_database, to_client, held.clone()));
            }
        });
        Self {
            port,
            requests,
            answering,
        }
    }

    fn one_connection_pool(&self) -> Pool {
        let app = app_config();
        let mut config = Config::new();
        config
            .host("127.0.0.1")
            .port(self.port)
            .user(app.get_user().expect("the application role"))
            .password(app.get_password().expect("its password"));
        if let Some(database) = app.get_dbname() {
            config.dbname(database);
        }
        Pool::builder(Manager::new(config, NoTls))
            .max_size(1)
            .build()
            .expect("a pool of one")
    }

    /// Run `work` with every answer held until `requests` have left, then let
    /// the answers through: one round trip means nothing was sent after them.
    ///
    /// A request that waits for an answer cannot leave while they are held, so
    /// the hold gives up after ten seconds; pipelined work never comes near it.
    async fn run_in_one_round_trip<T>(
        &self,
        step: &str,
        requests: usize,
        work: impl Future<Output = T>,
    ) -> T {
        let before = *self.requests.borrow();
        let mut counted = self.requests.clone();
        self.answering.send_replace(false);
        let (done, ahead) = tokio::join!(work, async {
            let _ = tokio::time::timeout(
                Duration::from_secs(10),
                counted.wait_for(|&sent| sent - before >= requests),
            )
            .await;
            let ahead = *counted.borrow() - before;
            self.answering.send_replace(true);
            ahead
        });
        let sent = *self.requests.borrow() - before;
        assert_eq!(
            (ahead, sent),
            (requests, requests),
            "{step} took more than one round trip: requests sent before an answer \
             came back, then in all"
        );
        done
    }
}

/// Pass what the client sends on to the database, counting each request before
/// it is forwarded, so no answer to it can come back first.
async fn count_requests(
    mut from_client: OwnedReadHalf,
    mut to_database: OwnedWriteHalf,
    counted: watch::Sender<usize>,
) {
    let mut chunk = [0u8; 8192];
    let mut unread = Vec::new();
    // The startup message alone has no type byte before its length.
    let mut started = false;
    loop {
        let read = match from_client.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        unread.extend_from_slice(&chunk[..read]);
        loop {
            let tagged = usize::from(started);
            let Some(length) = unread.get(tagged..tagged + 4) else {
                break;
            };
            let whole = tagged + u32::from_be_bytes(length.try_into().unwrap()) as usize;
            if unread.len() < whole {
                break;
            }
            if started && matches!(unread[0], b'Q' | b'S') {
                counted.send_modify(|sent| *sent += 1);
            }
            started = true;
            unread.drain(..whole);
        }
        if to_database.write_all(&chunk[..read]).await.is_err() {
            return;
        }
    }
}

/// Pass the database's answers back to the client, unless they are held.
async fn hold_answers(
    mut from_database: OwnedReadHalf,
    mut to_client: OwnedWriteHalf,
    mut answering: watch::Receiver<bool>,
) {
    let mut chunk = [0u8; 8192];
    loop {
        let read = match from_database.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        if answering.wait_for(|open| *open).await.is_err() {
            return;
        }
        if to_client.write_all(&chunk[..read]).await.is_err() {
            return;
        }
    }
}

/// What the unit saves, counted rather than timed.
///
/// Opening used to be a `BEGIN` and two settings sent as text, each prepared
/// and then executed: five round trips. The unit pipelines one. A statement
/// sent as text is prepared on every run; the unit prepares it once per
/// connection, so running it again is one round trip. A relay counts both.
///
/// Both shapes are also timed side by side and the figures printed, but not
/// asserted: one run on a busy machine had the kept reads slower (0.9x), and a
/// ratio cannot tell that noise from a unit that stopped pipelining or keeping.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_unit_opens_and_reads_in_fewer_round_trips() {
    const RUNS: u32 = 200;
    const READ: &str = "SELECT tenant_id FROM tenants";

    let _turn = DATABASE.lock().await;
    let pool = one_connection_pool().await;
    let tenancy = Tenancy::unpinned(pool.clone());
    plant(&tenancy, "acme").await;
    let acme = TenantContext::tenant_wide("acme");

    let started = Instant::now();
    {
        let connection = pool.get().await.unwrap();
        for _ in 0..RUNS {
            connection.batch_execute("BEGIN").await.unwrap();
            connection
                .execute(
                    "SELECT set_config($1, $2, true)",
                    &[&"saffui.current_tenant", &"acme"],
                )
                .await
                .unwrap();
            connection
                .execute(
                    "SELECT set_config($1, $2, true)",
                    &[&"saffui.current_realm", &""],
                )
                .await
                .unwrap();
            connection.batch_execute("COMMIT").await.unwrap();
        }
    }
    let opened_one_by_one = started.elapsed();

    let started = Instant::now();
    for _ in 0..RUNS {
        tenancy.begin(&acme).await.unwrap().commit().await.unwrap();
    }
    let opened_as_units = started.elapsed();

    let started = Instant::now();
    {
        let connection = pool.get().await.unwrap();
        connection.batch_execute("BEGIN").await.unwrap();
        for _ in 0..RUNS {
            connection.query(READ, &[]).await.unwrap();
        }
        connection.batch_execute("COMMIT").await.unwrap();
    }
    let read_prepared_each_time = started.elapsed();

    let started = Instant::now();
    {
        let unit = tenancy.begin(&acme).await.unwrap();
        for _ in 0..RUNS {
            unit.query(READ, &[]).await.unwrap();
        }
        unit.commit().await.unwrap();
    }
    let read_kept = started.elapsed();

    eprintln!(
        "{RUNS} openings: one statement at a time {opened_one_by_one:?}, as units \
         {opened_as_units:?} ({:.1}x) | {RUNS} reads: prepared each time \
         {read_prepared_each_time:?}, kept {read_kept:?} ({:.1}x)",
        opened_one_by_one.as_secs_f64() / opened_as_units.as_secs_f64(),
        read_prepared_each_time.as_secs_f64() / read_kept.as_secs_f64(),
    );

    let relay = Relay::start().await;
    let relayed = Tenancy::unpinned(relay.one_connection_pool());
    // The first unit on a connection prepares the scope and the read; every
    // later one has to find them kept.
    let first = relayed.begin(&acme).await.unwrap();
    first.query(READ, &[]).await.unwrap();
    first.commit().await.unwrap();

    let unit = relay
        .run_in_one_round_trip("opening", 2, relayed.begin(&acme))
        .await
        .unwrap();
    relay
        .run_in_one_round_trip("reading", 1, unit.query(READ, &[]))
        .await
        .unwrap();
    relay
        .run_in_one_round_trip("committing", 2, unit.commit())
        .await
        .unwrap();
}
