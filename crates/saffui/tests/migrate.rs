//! Journeys through the real binary: `migrate`, then a node that serves from
//! what it left.

use std::io::{BufRead, BufReader};
use std::process::{Command, Output, Stdio};

use pgcore::APP_ROLE;

#[path = "support/database.rs"]
mod database;
mod support;

const OWNER: &str = "saffui_owner";

fn run_migrate(configure: impl FnOnce(&mut Command)) -> Output {
    let mut command = support::saffui_command();
    command.arg("migrate");
    configure(&mut command);
    command.output().expect("the saffui binary starts")
}

#[test]
fn migrate_without_a_connection_string_exits_with_2_and_names_the_variable() {
    let refused = run_migrate(|_| {});

    assert_eq!(refused.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("SAFFUI_MIGRATION_DATABASE_URL is required"),
        "{stderr}"
    );
}

#[test]
fn migrate_brings_an_empty_database_to_the_schema_a_node_then_serves_from() {
    let database = database::create_database(&[]);
    let as_owner = |command: &mut Command| {
        command.env(
            "SAFFUI_MIGRATION_DATABASE_URL",
            database.connection_string(OWNER),
        );
    };

    let first = run_migrate(as_owner);
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        String::from_utf8_lossy(&first.stdout).starts_with("schema at version "),
        "the run says where the schema stands"
    );

    let second = run_migrate(as_owner);
    assert_eq!(second.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("nothing to apply"),
        "a second run applies nothing"
    );

    let mut serving = support::saffui_command()
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--ops-listen",
            "127.0.0.1:0",
        ])
        .env("SAFFUI_DATABASE_URL", database.connection_string(APP_ROLE))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the saffui binary starts");
    let mut first_line = String::new();
    BufReader::new(serving.stderr.take().expect("standard error is piped"))
        .read_line(&mut first_line)
        .expect("a first line of the journal");
    let _ = serving.kill();
    let _ = serving.wait();
    assert!(
        first_line.contains(" listening "),
        "a node serves from the migrated schema: {first_line:?}"
    );
}

#[test]
fn migrate_refuses_a_remote_host_without_a_tls_mode() {
    let refused = run_migrate(|command| {
        command.env(
            "SAFFUI_MIGRATION_DATABASE_URL",
            "host=db.example.internal user=saffui_owner password=hunter2 dbname=saffui",
        );
    });

    assert_eq!(refused.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("say the TLS mode"), "{stderr}");
    assert!(
        !stderr.contains("hunter2"),
        "the password is never repeated"
    );
}
