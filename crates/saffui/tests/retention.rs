//! A journey through the real binary: a node that is given the maintenance
//! role purges what expired, and a node that is not serves all the same.

use std::thread;
use std::time::{Duration, Instant};

use pgcore::migrate::EMBEDDED;
use pgcore::testkit::TestDatabase;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE};

#[path = "support/database.rs"]
mod database;
#[path = "support/http.rs"]
mod http;
#[path = "support/node.rs"]
mod node;
mod support;

const OWNER: &str = "saffui_owner";

fn run<T>(work: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(work)
}

fn bootstrap(database: &TestDatabase) {
    let created = support::saffui_command()
        .args(["bootstrap", "--tenant", "Acme", "--realm", "acme"])
        .env("SAFFUI_DATABASE_URL", database.connection_string(APP_ROLE))
        .env("SAFFUI_PUBLIC_ORIGIN", node::PUBLIC_ORIGIN)
        .output()
        .expect("the saffui binary starts");
    assert_eq!(
        created.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
}

/// Writes a pending request that expired an hour ago, as nothing of the
/// product would: the product only writes requests that are still to come.
fn plant_an_expired_request(database: &TestDatabase) {
    run(async {
        let owner = database
            .plan(OWNER)
            .connect_directly()
            .await
            .expect("a connection");
        owner
            .batch_execute(
                "BEGIN;
                 SELECT set_config('saffui.tenant', tenant_id::text, true),
                        set_config('saffui.realm', realm_id::text, true)
                 FROM realm_directory WHERE name = 'acme';
                 INSERT INTO authorization_requests (tenant_id, realm_id, request_id,
                     browser_digest, client_id, redirect_uri, scopes, code_challenge, expires_at)
                 SELECT tenant_id, realm_id, gen_random_uuid(), '\\x00', 'portal',
                        'https://app.example.test/cb', '{}', 'c', now() - interval '1 hour'
                 FROM realm_directory WHERE name = 'acme';
                 COMMIT;",
            )
            .await
            .expect("an expired request");
    });
}

fn count_pending_requests(database: &TestDatabase) -> i64 {
    run(async {
        let maintenance = database
            .plan(MAINTENANCE_ROLE)
            .connect_directly()
            .await
            .expect("a connection");
        maintenance
            .query_one("SELECT count(*) FROM authorization_requests", &[])
            .await
            .expect("a count")
            .get(0)
    })
}

#[test]
fn a_node_given_the_maintenance_role_purges_what_expired_and_one_without_it_still_serves() {
    let database = database::create_database(EMBEDDED);
    bootstrap(&database);
    plant_an_expired_request(&database);
    assert_eq!(count_pending_requests(&database), 1);

    // Told off: the node serves, and removes nothing.
    {
        let serving_only = node::Node::start(support::saffui_command(), &database);
        let ready = http::get(serving_only.ops, "/readyz").expect("an answer");
        assert_eq!(ready.status, 200, "{}", ready.body);
        let published = http::get(
            serving_only.data,
            "/realms/acme/.well-known/openid-configuration",
        )
        .expect("an answer");
        assert_eq!(published.status, 200, "{}", published.body);
        assert!(
            published
                .head
                .to_lowercase()
                .contains("content-type: application/json"),
            "{}",
            published.head
        );
        assert_eq!(count_pending_requests(&database), 1);
    }

    let mut with_maintenance = support::saffui_command();
    with_maintenance.env("SAFFUI_RETENTION", "on").env(
        "SAFFUI_MAINTENANCE_DATABASE_URL",
        database.connection_string(MAINTENANCE_ROLE),
    );
    let _node = node::Node::start(with_maintenance, &database);
    // The first pass runs when the node starts: it is waited for, not timed.
    let deadline = Instant::now() + Duration::from_secs(10);
    while count_pending_requests(&database) > 0 {
        assert!(
            Instant::now() < deadline,
            "the node did not purge the expired request"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

/// Starts `serve` with these settings, and returns its exit code and what
/// it wrote, for a node that refuses before it serves.
fn refuse_to_serve(database: &TestDatabase, settings: &[(&str, String)]) -> (Option<i32>, String) {
    let mut command = support::saffui_command();
    command
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--ops-listen",
            "127.0.0.1:0",
        ])
        .env_remove("SAFFUI_RETENTION")
        .env("SAFFUI_DATABASE_URL", database.connection_string(APP_ROLE))
        .env("SAFFUI_PUBLIC_ORIGIN", node::PUBLIC_ORIGIN);
    for (name, value) in settings {
        command.env(name, value);
    }
    let refused = command.output().expect("the saffui binary starts");
    (
        refused.status.code(),
        String::from_utf8_lossy(&refused.stderr).into_owned(),
    )
}

#[test]
fn a_node_told_nothing_of_retention_or_given_the_serving_role_for_it_does_not_serve() {
    let database = database::create_database(EMBEDDED);
    bootstrap(&database);

    let (code, said) = refuse_to_serve(&database, &[]);
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains("SAFFUI_MAINTENANCE_DATABASE_URL is required"),
        "{said}"
    );

    let (code, said) = refuse_to_serve(
        &database,
        &[(
            "SAFFUI_MAINTENANCE_DATABASE_URL",
            database.connection_string(APP_ROLE),
        )],
    );
    assert_eq!(code, Some(1), "{said}");
    assert!(said.contains("the maintenance link cannot purge"), "{said}");
}
