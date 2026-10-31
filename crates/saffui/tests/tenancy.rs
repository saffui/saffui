//! Journeys through the real binary: a realm is created by `bootstrap`, and a
//! node then answers for it.

use std::process::Output;
use std::time::Duration;

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

/// The role the migrations run as, which owns every table.
const OWNER: &str = "saffui_owner";

fn bootstrap_over(connection: &str, tenant: &str, realm: &str) -> Output {
    support::saffui_command()
        .args(["bootstrap", "--tenant", tenant, "--realm", realm])
        .env("SAFFUI_DATABASE_URL", connection)
        .env("SAFFUI_PUBLIC_ORIGIN", node::PUBLIC_ORIGIN)
        .output()
        .expect("the saffui binary starts")
}

fn bootstrap(database: &TestDatabase, tenant: &str, realm: &str) -> Output {
    bootstrap_over(&database.connection_string(APP_ROLE), tenant, realm)
}

/// Runs `sql` as `role`, from a test that has no runtime.
fn run_as(database: &TestDatabase, role: &str, sql: &str) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime for the statements")
        .block_on(async {
            database
                .plan(role)
                .connect_directly()
                .await
                .expect("a connection")
                .batch_execute(sql)
                .await
                .expect("the statements ran");
        });
}

#[test]
fn a_bootstrapped_realm_is_published_by_a_node_on_its_data_plane_only() {
    let database = database::create_database(EMBEDDED);

    let created = bootstrap(&database, "Acme", "acme");
    let stdout = String::from_utf8_lossy(&created.stdout);
    assert_eq!(
        created.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(
        stdout.contains("issuer http://localhost:8080/realms/acme\n"),
        "the issuer is told: {stdout}"
    );

    let node = node::Node::start(support::saffui_command(), &database);
    let path = "/realms/acme/.well-known/openid-configuration";

    let published = http::get(node.data, path).expect("an answer");
    assert_eq!(published.status, 200, "{}", published.body);
    assert!(
        published
            .head
            .to_lowercase()
            .contains("content-type: application/json"),
        "{}",
        published.head
    );
    assert_eq!(
        published.body,
        r#"{"issuer":"http://localhost:8080/realms/acme"}"#
    );

    let unknown =
        http::get(node.data, "/realms/nobody/.well-known/openid-configuration").expect("an answer");
    assert_eq!(unknown.status, 404);
    assert!(
        unknown.body.contains(r#""code":"realm.not_found""#),
        "{}",
        unknown.body
    );

    let on_ops = http::get(node.ops, path).expect("an answer");
    assert_eq!(on_ops.status, 404, "the operations plane serves no realm");
}

#[test]
fn a_realm_name_is_given_once_and_a_name_that_cannot_be_used_is_a_usage_error() {
    let database = database::create_database(EMBEDDED);
    assert_eq!(bootstrap(&database, "Acme", "acme").status.code(), Some(0));

    let taken = bootstrap(&database, "Globex", "acme");
    assert_eq!(taken.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&taken.stderr),
        "error: This realm name is already taken.\n"
    );

    let unusable = bootstrap(&database, "Globex", "Globex Prod");
    assert_eq!(unusable.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&unusable.stderr).starts_with("error: A realm name is 1 to 63"),
        "the rule is told"
    );
}

#[test]
fn bootstrap_refuses_a_database_that_was_not_migrated() {
    let database = database::create_database(&[]);

    let refused = bootstrap(&database, "Acme", "acme");

    assert_eq!(refused.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("migrations are pending"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

#[test]
fn bootstrap_refuses_to_write_under_a_role_that_row_security_does_not_bind() {
    let database = database::create_database(EMBEDDED);
    // A superuser lowered by a setting of its connection is still one.
    let lowered = format!(
        "{} options='-c role={APP_ROLE}'",
        database.connection_string("postgres")
    );

    for (connection, role, reason) in [
        (
            database.connection_string(MAINTENANCE_ROLE),
            MAINTENANCE_ROLE,
            "bypasses row security",
        ),
        (
            database.connection_string(OWNER),
            OWNER,
            "has the privileges of an owner",
        ),
        (lowered, "postgres", "bypasses row security"),
    ] {
        let refused = bootstrap_over(&connection, "Acme", "acme");
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert_eq!(refused.status.code(), Some(1), "{role}: {stderr}");
        assert!(
            stderr.contains(&format!("refusing to write: the role {role} {reason}")),
            "{stderr}"
        );
    }
    assert_eq!(
        bootstrap(&database, "Acme", "acme").status.code(),
        Some(0),
        "the refused runs wrote nothing that takes the name"
    );
}

#[test]
fn bootstrap_tells_its_journal_why_a_write_failed() {
    let database = database::create_database(EMBEDDED);
    run_as(
        &database,
        OWNER,
        &format!("REVOKE INSERT ON tenants FROM {APP_ROLE}"),
    );

    let failed = bootstrap(&database, "Acme", "acme");

    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert_eq!(failed.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("a statement failed") && stderr.contains("42501"),
        "the journal says why: {stderr}"
    );
}

#[test]
fn bootstrap_tells_its_journal_why_the_role_cannot_be_read() {
    let database = database::create_database(EMBEDDED);
    run_as(
        &database,
        "postgres",
        "REVOKE SELECT ON pg_catalog.pg_roles FROM PUBLIC",
    );

    let refused = bootstrap(&database, "Acme", "acme");

    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(refused.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("the role of the database link cannot be read")
            && stderr.contains("42501")
            && stderr.contains("permission denied"),
        "the journal says why: {stderr}"
    );
    assert!(
        stderr.contains("refusing to write: the role of the database link cannot be read"),
        "the refusal says what failed: {stderr}"
    );
}

#[test]
fn a_node_tells_its_journal_why_the_realm_directory_cannot_be_read() {
    let database = database::create_database(EMBEDDED);
    assert_eq!(bootstrap(&database, "Acme", "acme").status.code(), Some(0));
    let node = node::Node::start(support::saffui_command(), &database);
    run_as(
        &database,
        OWNER,
        &format!("REVOKE EXECUTE ON FUNCTION saffui_locate_realm(text) FROM {APP_ROLE}"),
    );

    let answer =
        http::get(node.data, "/realms/acme/.well-known/openid-configuration").expect("an answer");

    assert_eq!(answer.status, 503, "{}", answer.body);
    assert!(
        node.wait_for_journal_line(
            &[
                "the realm directory cannot be read",
                "42501",
                "permission denied"
            ],
            Duration::from_secs(5)
        )
        .is_some(),
        "the journal says why the directory cannot be read"
    );
}

#[test]
fn a_node_reads_the_realm_directory_of_the_product_whatever_schema_bears_its_name() {
    let database = database::create_database(EMBEDDED);
    assert_eq!(bootstrap(&database, "Acme", "acme").status.code(), Some(0));
    // A schema that bears the name of the serving role comes first by default:
    // its directory would answer acme for every name.
    run_as(
        &database,
        "postgres",
        &format!(
            "CREATE SCHEMA {APP_ROLE};
             GRANT USAGE ON SCHEMA {APP_ROLE} TO {APP_ROLE};
             CREATE FUNCTION {APP_ROLE}.saffui_locate_realm(text)
                 RETURNS TABLE (tenant_id uuid, realm_id uuid, enabled boolean)
                 LANGUAGE sql AS 'SELECT * FROM public.saffui_locate_realm(''acme'')';"
        ),
    );
    let node = node::Node::start(support::saffui_command(), &database);

    let answer =
        http::get(node.data, "/realms/nobody/.well-known/openid-configuration").expect("an answer");

    assert_eq!(answer.status, 404, "{}", answer.body);
    assert!(
        answer.body.contains(r#""code":"realm.not_found""#),
        "the directory found no realm: {}",
        answer.body
    );
}
