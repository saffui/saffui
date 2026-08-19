//! One artifact, several subcommands.
//!
//! One rather than two because the pieces share their configuration, their
//! schema window and their store, and two binaries would carry two copies of
//! that agreement. Splitting later moves this file; splitting the crates before
//! anything needed it would have been a shape chosen in advance.

use std::process::ExitCode;
use std::time::Duration;

use actix_web::{App, HttpServer};
use clap::{Parser, Subcommand};
use deadpool_postgres::{Manager, Pool};
use server::api::config::{Plane, mount, mount_ops};
use server::api::rest::endpoints::ops::health::Vitals;
use server::middleware::admin_policy::AdminPolicy;
use store::tenancy::Tenancy;
use tokio::signal;
use tokio_postgres::NoTls;

#[derive(Parser)]
#[command(
    name = "saffui",
    version,
    about = "identity, and the plane that administers it"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the admin plane.
    Serve {
        /// Where to listen.
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
        /// Where an orchestrator asks. Its own port, so a probe never queues
        /// behind traffic and is not reachable from wherever traffic is.
        #[arg(long, default_value = "127.0.0.1:8081")]
        ops: String,
    },
}

fn main() -> ExitCode {
    let Command::Serve { bind, ops } = Cli::parse().command;

    let outcome = tokio::runtime::Runtime::new()
        .map_err(|reason| reason.to_string())
        .and_then(|runtime| runtime.block_on(serve(&bind, &ops)));

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("{reason}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(bind: &str, ops: &str) -> Result<(), String> {
    let plane = plane()?;

    // What this build reads. A pod whose database has migrated past it cannot
    // read what its peers now write, so it takes itself out of service.
    let schema = store::schema::migrations()
        .iter()
        .map(pgcore::migrations::Migration::version)
        .max()
        .unwrap_or(0);
    let vitals = Vitals::new(plane.pool.clone(), schema);

    // Bound before anything is announced, and before the probes say started.
    let probes = {
        let vitals = vitals.clone();
        HttpServer::new(move || mount_ops(App::new(), &vitals))
            .bind(ops)
            .map_err(|reason| format!("cannot listen on {ops}: {reason}"))?
            .run()
    };

    // Bound before anything is announced, so a port already taken fails here
    // rather than after the log line says it is serving.
    let plane = HttpServer::new(move || mount(App::new(), &plane))
        .bind(bind)
        .map_err(|reason| format!("cannot listen on {bind}: {reason}"))?
        .run();

    // Both ports are bound, so a probe asking now gets a true answer.
    vitals.started();

    let draining = vitals.clone();
    let plane_handle = plane.handle();
    let probes_handle = probes.handle();
    tokio::spawn(async move {
        if signal::ctrl_c().await.is_err() {
            return;
        }
        // Readiness fails first, and only then is anything stopped. Stopping
        // first would refuse requests an orchestrator is still routing here,
        // since it learns this pod is going away one probe period later.
        draining.drain();
        tokio::time::sleep(DRAIN).await;
        plane_handle.stop(true).await;
        probes_handle.stop(true).await;
    });

    let (served, _) = tokio::join!(plane, probes);
    served.map_err(|reason| reason.to_string())
}

/// How long readiness is allowed to be false before anything is stopped.
///
/// Longer than a probe period so an orchestrator sees the pod leave, and
/// shorter than any sane grace period so what is in flight finishes before the
/// process is killed rather than asked.
const DRAIN: Duration = Duration::from_secs(5);

/// Everything the plane needs, read once at startup.
///
/// Neither the accepted audiences nor the accepted clients have a default. A
/// plane that admitted anything until configured would be open on first boot,
/// which is the one moment nobody is looking. The two are asked separately
/// because they are different questions: who a token is for, and which client
/// obtained it.
fn plane() -> Result<Plane, String> {
    let connection = config::required("DATABASE_URL").map_err(|e| e.to_string())?;
    let audiences: Vec<String> = config::required("ADMIN_AUDIENCES")
        .map_err(|e| e.to_string())?
        .split(',')
        .map(str::trim)
        .filter(|audience| !audience.is_empty())
        .map(str::to_owned)
        .collect();
    if audiences.is_empty() {
        return Err(
            "SAFFUI_ADMIN_AUDIENCES names no audience, so nothing could be admitted".into(),
        );
    }

    let parties: Vec<String> = config::required("ADMIN_PARTIES")
        .map_err(|e| e.to_string())?
        .split(',')
        .map(str::trim)
        .filter(|party| !party.is_empty())
        .map(str::to_owned)
        .collect();
    if parties.is_empty() {
        return Err("SAFFUI_ADMIN_PARTIES names no client, so nothing could be admitted".into());
    }

    let scope = config::optional("ADMIN_SCOPE").unwrap_or_else(|| "admin".to_owned());
    let region = config::optional("REGION");

    let pg: tokio_postgres::Config = connection
        .parse()
        .map_err(|_| "DATABASE_URL is not a connection string".to_owned())?;
    let pool = Pool::builder(Manager::new(pg, NoTls))
        .build()
        .map_err(|reason| format!("cannot build a pool: {reason}"))?;

    Ok(Plane {
        pool,
        tenancy: match region {
            Some(region) => Tenancy::in_region(region),
            None => Tenancy::unpinned(),
        },
        policy: AdminPolicy {
            audiences,
            parties,
            scope,
        },
    })
}
