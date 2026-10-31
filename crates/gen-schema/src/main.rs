//! `gen-schema` writes the table and column constants of the store, and
//! `gen-schema --check` fails when the committed file is stale. Run it as
//! `scripts/dev-postgres.sh gen-schema`, which makes it an empty database.
//!
//! It builds a schema from nothing, in a database named by a variable that
//! is its own: never the address of a deployment.

mod emit;
mod schema;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use pgcore::connect::plan_connection;
use pgcore::migrate::{EMBEDDED, apply_pending};

/// A connection string to an empty, throwaway database, as its owner.
const DATABASE: &str = "GEN_SCHEMA_DATABASE_URL";
const GENERATED: &str = "../store/src/schema/generated.rs";

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error("{DATABASE} is required: a connection string to an empty, throwaway database")]
    NoDatabase,
    #[error(
        "the database is not empty: this tool builds a schema from nothing, in a database made for it"
    )]
    NotThrowaway,
    #[error("the connection is refused: {0}")]
    Connection(String),
    #[error("the migrations cannot be applied: {0}")]
    Migration(String),
    #[error("the catalog cannot be read: {0}")]
    Catalog(String),
    #[error(transparent)]
    Emit(#[from] emit::EmitError),
    #[error("rustfmt cannot format the module: {0}")]
    Format(String),
    #[error("{0} cannot be written: {1}")]
    Write(String, String),
    #[error("{0} is stale: run `scripts/dev-postgres.sh gen-schema` and commit the result")]
    Stale(String),
}

fn locate_generated_file() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(GENERATED)
}

/// Formats the module as the rest of the tree is, so that the freshness
/// check and the format check never disagree.
fn format_module(module: &str) -> Result<String, Failure> {
    let failed = |error: std::io::Error| Failure::Format(error.to_string());
    let mut rustfmt = Command::new("rustfmt")
        .args(["--edition", "2024", "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(failed)?;
    if let Some(mut input) = rustfmt.stdin.take() {
        input.write_all(module.as_bytes()).map_err(failed)?;
    }
    let output = rustfmt.wait_with_output().map_err(failed)?;
    if !output.status.success() {
        return Err(Failure::Format(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| Failure::Format(error.to_string()))
}

async fn generate_module() -> Result<String, Failure> {
    let address = std::env::var(DATABASE).map_err(|_| Failure::NoDatabase)?;
    // The policy of every other connection, at its strictest: a database
    // that is not on this machine is no throwaway one.
    let plan = plan_connection(&address, None, None)
        .map_err(|error| Failure::Connection(error.to_string()))?
        .named("gen-schema");
    let before = plan
        .connect_directly()
        .await
        .map_err(|error| Failure::Connection(error.to_string()))?;
    if !schema::read_tables(&before)
        .await
        .map_err(|error| Failure::Catalog(error.to_string()))?
        .is_empty()
    {
        return Err(Failure::NotThrowaway);
    }
    drop(before);

    // The real runner, with its lock and its checksums: a second applier
    // could generate against a schema no deployment has.
    apply_pending(&plan, EMBEDDED)
        .await
        .map_err(|error| Failure::Migration(error.to_string()))?;
    let client = plan
        .connect_directly()
        .await
        .map_err(|error| Failure::Connection(error.to_string()))?;
    let tables = schema::read_tables(&client)
        .await
        .map_err(|error| Failure::Catalog(error.to_string()))?;
    format_module(&emit::write_module(&tables)?)
}

fn run(check: bool) -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| Failure::Connection(error.to_string()))?;
    let module = runtime.block_on(generate_module())?;
    let path = locate_generated_file();
    let shown = path.display().to_string();
    if check {
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        return if committed == module {
            Ok(())
        } else {
            Err(Failure::Stale(shown))
        };
    }
    std::fs::write(&path, module).map_err(|error| Failure::Write(shown, error.to_string()))
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let check = match arguments.as_slice() {
        [] => false,
        [flag] if flag == "--check" => true,
        _ => {
            let _ = writeln!(std::io::stderr(), "usage: gen-schema [--check]");
            return ExitCode::from(2);
        }
    };
    match run(check) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            let _ = writeln!(std::io::stderr(), "error: {failure}");
            ExitCode::FAILURE
        }
    }
}
