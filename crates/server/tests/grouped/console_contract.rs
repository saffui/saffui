use super::support::{self, Plane};
use actix_web::App;
use models::entities::authz::AdminAction;
use server::api::config::{Plane as Mounted, register};
use std::path::Path;
use std::process::Command;

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
        ceiling: support::ceiling(),
    }
}

/// The console's own service calls, run by its contract suite against this
/// server on a real socket. Its mocked transport tests prove what the console
/// does with an answer; this proves the server still gives that answer: every
/// path and body the console sends is taken, and every answer it keeps fits
/// the type the console reads it as.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG) and the console's packages (pnpm install)"]
async fn the_console_contract_holds_against_a_live_server() {
    let plane = Plane::with_actions(AdminAction::ALL).await;
    let bearer = plane.token(&support::claims());

    let served = mounted(&plane);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let server = actix_web::HttpServer::new(move || App::new().configure(register(&served)))
        .listen(listener)
        .expect("a listener")
        .workers(1)
        .disable_signals()
        .run();
    tokio::spawn(server);

    let console = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../admin");
    assert!(
        console.join("node_modules").is_dir(),
        "the console's packages are not installed: run pnpm install"
    );
    let run = tokio::task::spawn_blocking(move || {
        Command::new("pnpm")
            .args(["run", "contract"])
            .current_dir(console)
            .env("SAFFUI_CONTRACT_ORIGIN", format!("http://127.0.0.1:{port}"))
            .env("SAFFUI_CONTRACT_TOKEN", bearer)
            .env("SAFFUI_CONTRACT_REALM", support::REALM)
            .output()
    })
    .await
    .expect("the run comes back")
    .expect("pnpm starts");
    assert!(
        run.status.success(),
        "the console contract broke:\n{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}
