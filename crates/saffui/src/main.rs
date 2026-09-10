use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use actix_web::{App, HttpServer};
use clap::{Parser, Subcommand};
use crypto::envelope::Envelope;
use crypto::provider::CryptoProvider;
use crypto::provider::openssl::OpenSslProvider;
use deadpool_postgres::{Manager, Pool};
use models::entities::realm::RegistrationBounds;
use secrecy::ExposeSecret;
use server::api::config::{Plane, Sealing, observed_with, register, register_ops};
use server::api::rest::endpoints::ops::health::Vitals;
use server::middleware::admin_policy::AdminPolicy;
use services::provisioning;
use store::tenancy::{Tenancy, TenantContext};
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
#[allow(
    clippy::large_enum_variant,
    reason = "parsed once, at startup, into the one command that runs"
)]
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
    /// Apply the schema, as the database owner.
    ///
    /// `SAFFUI_DATABASE_URL` is the owner's here, where `serve` reads the
    /// application role's. With `SAFFUI_APP_ROLE_PASSWORD` set, the role the
    /// schema creates is also given its login, so one command leaves a fresh
    /// database ready to be served.
    Migrate,
    /// Create what a deployment needs before anybody can log in.
    ///
    /// A tenant, a realm with its signing key, scopes and console, the browser
    /// flow, and optionally one client and one user. Everything that exists is
    /// left as it is, so this can run on every start.
    Provision {
        #[arg(long, default_value = "default")]
        tenant: String,
        #[arg(long, default_value = "main")]
        realm: String,
        /// Where the admin console is served. A login is only ever sent back
        /// to a value written here.
        #[arg(long = "console-redirect")]
        console_redirects: Vec<String>,
        /// Clients to register, every one with the same redirect URIs and,
        /// when `SAFFUI_PROVISION_CLIENT_SECRET` is set, the same secret.
        /// One secret for several clients is a local deployment's shortcut,
        /// not a registration policy: absent, they are public.
        #[arg(long = "client")]
        clients: Vec<String>,
        /// The clients' redirect URIs.
        #[arg(long = "redirect")]
        redirects: Vec<String>,
        /// A client held to the FAPI 2.0 Security Profile, as
        /// `id=/path/to/public.jwks.json`: confidential, private_key_jwt
        /// against the published set in that file, ES256 identity tokens.
        #[arg(long = "fapi-client")]
        fapi_clients: Vec<String>,
        /// Where the clients may send a browser after a logout.
        #[arg(long = "after-logout")]
        after_logout: Vec<String>,
        /// Where the clients are posted a logout token when a login ends.
        #[arg(long = "backchannel-logout")]
        backchannel_logout: Option<String>,
        /// Where the browser loads a frame for the clients when a login ends.
        #[arg(long = "frontchannel-logout")]
        frontchannel_logout: Option<String>,
        /// A user to create. The password is read from
        /// `SAFFUI_PROVISION_USER_PASSWORD`.
        #[arg(long)]
        user: Option<String>,
        /// Grant the user the administrator role, which carries every admin
        /// plane action. Without one, the provisioned console admits nobody.
        #[arg(long, default_value_t = false)]
        administrator: bool,
        #[arg(long, default_value = "")]
        email: String,
        #[arg(long)]
        given_name: Option<String>,
        #[arg(long)]
        family_name: Option<String>,
        #[arg(long)]
        phone: Option<String>,
        /// Any other attribute of the user, as `name=value`.
        #[arg(long = "attribute")]
        attributes: Vec<String>,
        /// Offer a mailed sign-in link as an alternative to the password. What
        /// a login costs then includes whoever can read the mailbox.
        #[arg(long = "magic-link", default_value_t = false)]
        magic_link: bool,
        /// Offer a texted one-time code as an alternative to the password.
        /// What a login costs then includes whoever holds the phone.
        #[arg(long = "texted-login", default_value_t = false)]
        texted_login: bool,
        /// Let the registered clients receive what the authorization endpoint
        /// mints, rather than only a code to exchange.
        #[arg(long = "implicit", default_value_t = false)]
        implicit: bool,
        /// Let a client register itself here, RFC 7591. Open registration:
        /// anyone who can reach the endpoint may create a client.
        #[arg(long = "open-registration", default_value_t = false)]
        open_registration: bool,
        /// How many clients open registration may create here. Absent is no
        /// ceiling, and the count is over what registration created rather
        /// than over the realm.
        #[arg(long = "registration-max-clients")]
        registration_max_clients: Option<i32>,
        /// Whether a client that registered itself has to be consented to.
        /// On unless a deployment says otherwise: it was vetted by nobody.
        #[arg(
            long = "registration-consent",
            default_value_t = true,
            action = clap::ArgAction::Set
        )]
        registration_consent: bool,
        /// Who may reach the registration endpoint, as addresses or prefixes
        /// such as `10.0.0.0/8`. Repeatable. None is every caller.
        #[arg(long = "registration-host")]
        registration_hosts: Vec<String>,
    },
    /// Operate the plane from here: one command, one call, one answer.
    Admin {
        #[command(flatten)]
        plane: saffui::cli::PlaneArgs,
        #[command(subcommand)]
        command: saffui::cli::AdminCmd,
    },
    /// Read what happened to this deployment's realms.
    ///
    /// A realm's own journal is keyed to the realm and goes when it does, so
    /// the record of a realm arriving or leaving is kept above them, in the
    /// tenant's chain. The served plane may write there and may not read: a
    /// tenant-wide reader would tell an administrator of one realm which
    /// realms neighbour it. Reading is from here, with the owner's
    /// credentials, which is what `SAFFUI_DATABASE_URL` holds for this
    /// command as it does for `migrate`.
    Chronicle {
        #[arg(long, default_value = "default")]
        tenant: String,
        /// How many entries, newest first.
        #[arg(long, default_value_t = 50)]
        max: i64,
        /// Recompute every link from the stored bytes and say where the chain
        /// first breaks, rather than listing it.
        #[arg(long)]
        verify: bool,
    },
    /// Name, keep and switch the places this terminal speaks to.
    Ctx {
        #[command(subcommand)]
        command: saffui::cli::CtxCmd,
    },
    /// Write the completion script for a shell to stdout.
    Completion {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Write the manual pages into a directory, one per command.
    Manpages {
        /// Where the pages land, created if absent.
        #[arg(long, default_value = ".")]
        out: std::path::PathBuf,
    },
}

fn main() -> ExitCode {
    let command = Cli::parse().command;

    // The operator commands are one blocking call each and speak over HTTP;
    // they neither need the runtime the server does nor its logging setup,
    // and starting either would be noise on somebody's terminal.
    match &command {
        Command::Admin { plane, command } => {
            return saffui::cli::run(plane, command, &mut std::io::stdout());
        }
        Command::Ctx { command } => {
            return saffui::cli::run_ctx(command, &mut std::io::stdout());
        }
        Command::Completion { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(
                *shell,
                &mut Cli::command(),
                "saffui",
                &mut std::io::stdout(),
            );
            return ExitCode::SUCCESS;
        }
        Command::Manpages { out } => {
            use clap::CommandFactory;
            if let Err(reason) = std::fs::create_dir_all(out) {
                eprintln!("cannot create {}: {reason}", out.display());
                return ExitCode::FAILURE;
            }
            return match clap_mangen::generate_to(Cli::command(), out) {
                Ok(_) => ExitCode::SUCCESS,
                Err(reason) => {
                    eprintln!("cannot write into {}: {reason}", out.display());
                    ExitCode::FAILURE
                }
            };
        }
        _ => {}
    }

    // Resolved before the logger, because both the logger's shape and the
    // refusal below come out of it: a capability asked for and not carried
    // refuses the whole start in words, whichever command was asked.
    let features = match commons::feature::FeatureSet::resolve(&config::features(), |feature| {
        crypto::compiled_features().contains(&feature.slug())
            || commons::feature::locally_compiled(feature)
            || server::metrics::compiled(feature)
            || server::otel::compiled(feature)
    }) {
        Ok(resolved) => resolved,
        Err(reason) => {
            eprintln!("SAFFUI_FEATURES could not be honoured: {reason}");
            return ExitCode::FAILURE;
        }
    };
    server::api::config::install_features(features.clone());

    // The export pipeline, only under `serve`, only when the switch is on,
    // and only against a named collector: absent an endpoint nothing is
    // built, so nothing can dial.
    let telemetry = match telemetry_for(&command, &features) {
        Ok(started) => started,
        Err(reason) => {
            eprintln!("{reason}");
            return ExitCode::FAILURE;
        }
    };

    // Before anything that could have something to say. What is logged and
    // how are the operator's, from the environment; absent, every record at
    // `info` and above, as text a person reads at a terminal. A collector
    // that wants one JSON object per line asks for `json`.
    #[cfg(feature = "otel")]
    let (telemetry, exporting) = match telemetry {
        Some((held, layer)) => (Some(held), Some(layer)),
        None => (None, None),
    };
    #[cfg(not(feature = "otel"))]
    let (telemetry, exporting): (
        Option<Exported>,
        Option<Box<dyn tracing_subscriber::Layer<commons::observability::Watched> + Send + Sync>>,
    ) = (telemetry, None);
    commons::observability::init_with(
        &config::optional("LOG").unwrap_or_else(|| "info".to_owned()),
        &config::optional("LOG_FORMAT").unwrap_or_else(|| "text".to_owned()),
        exporting,
    );

    let outcome = tokio::runtime::Runtime::new()
        .map_err(|reason| reason.to_string())
        .and_then(|runtime| {
            runtime.block_on(async {
                match command {
                    Command::Serve { bind, ops } => serve(&bind, &ops).await,
                    Command::Migrate => migrate().await,
                    Command::Chronicle {
                        tenant,
                        max,
                        verify,
                    } => read_chronicle(&tenant, max, verify).await,
                    Command::Provision {
                        tenant,
                        realm,
                        console_redirects,
                        clients,
                        redirects,
                        fapi_clients,
                        after_logout,
                        backchannel_logout,
                        frontchannel_logout,
                        user,
                        administrator,
                        email,
                        given_name,
                        family_name,
                        phone,
                        attributes,
                        magic_link,
                        texted_login,
                        implicit,
                        open_registration,
                        registration_max_clients,
                        registration_consent,
                        registration_hosts,
                    } => {
                        provision(&Wanted {
                            tenant,
                            realm,
                            console_redirects,
                            clients,
                            redirects,
                            fapi_clients,
                            after_logout,
                            backchannel_logout,
                            frontchannel_logout,
                            user,
                            administrator,
                            email,
                            given_name,
                            family_name,
                            phone,
                            attributes,
                            magic_link,
                            texted_login,
                            implicit,
                            open_registration,
                            registration_max_clients,
                            registration_consent,
                            registration_hosts,
                        })
                        .await
                    }
                    // Answered before the runtime was built; unreachable here,
                    // and spelled so the match stays exhaustive by name.
                    Command::Admin { .. }
                    | Command::Ctx { .. }
                    | Command::Completion { .. }
                    | Command::Manpages { .. } => Ok(()),
                }
            })
        });

    // After the servers have stopped, so the last requests' spans leave too.
    #[cfg(feature = "otel")]
    if let Some(telemetry) = telemetry {
        telemetry.shutdown();
    }
    #[cfg(not(feature = "otel"))]
    let _ = telemetry;

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("{reason}");
            ExitCode::FAILURE
        }
    }
}

/// The export pipeline and its layer, when `serve` was asked, the switch is
/// on, and a collector is named. Every other shape is a quiet `None`.
#[cfg(feature = "otel")]
type Exported = (
    server::otel::Telemetry,
    Box<dyn tracing_subscriber::Layer<commons::observability::Watched> + Send + Sync>,
);
#[cfg(not(feature = "otel"))]
type Exported = std::convert::Infallible;

fn telemetry_for(
    command: &Command,
    features: &commons::feature::FeatureSet,
) -> Result<Option<Exported>, String> {
    if !matches!(command, Command::Serve { .. }) {
        return Ok(None);
    }
    if !features.status(commons::feature::Feature::Otel).enabled {
        return Ok(None);
    }
    #[cfg(feature = "otel")]
    {
        let Some(endpoint) = config::otel::endpoint() else {
            return Ok(None);
        };
        let ratio = config::otel::sample_ratio().map_err(|reason| reason.to_string())?;
        server::otel::start(&endpoint, ratio).map(Some)
    }
    #[cfg(not(feature = "otel"))]
    Ok(None)
}

async fn serve(bind: &str, ops: &str) -> Result<(), String> {
    let measured = server::api::config::features()
        .status(commons::feature::Feature::Metrics)
        .enabled;

    let plane = plane()?;

    // What this build reads. A pod whose database has migrated past it cannot
    // read what its peers now write, so it takes itself out of service.
    let schema = store::schema::migrations()
        .iter()
        .map(pgcore::migrations::Migration::version)
        .max()
        .unwrap_or(0);
    let vitals = Vitals::new(plane.pool.clone(), schema);
    let (swept_pool, swept_tenancy) = (plane.pool.clone(), plane.tenancy.clone());
    let (synced_pool, synced_tenancy, synced_sealing) = (
        plane.pool.clone(),
        plane.tenancy.clone(),
        std::sync::Arc::new(plane.sealing.clone()),
    );
    let (front_pool, front_tenancy, front_provider) = (
        plane.pool.clone(),
        plane.tenancy.clone(),
        plane.sealing.provider.clone(),
    );
    #[cfg(feature = "mesh")]
    let (mesh_pool, mesh_tenancy, mesh_origin) = (
        plane.pool.clone(),
        plane.tenancy.clone(),
        plane.origin.clone(),
    );
    let (plane_pool_for_outbox, tenancy_for_outbox, origin_for_outbox) = (
        plane.pool.clone(),
        plane.tenancy.clone(),
        plane.origin.clone(),
    );

    // Bound with the other ports: a front asked for and not listenable fails
    // the deployment now, not on the first directory client. So does a key
    // pair that cannot be read, for the same reason.
    let fronting = match config::ldap::LdapFront::from_env().map_err(|reason| reason.to_string())? {
        None => None,
        Some(door) => {
            let tls = match &door.tls {
                None => None,
                Some(paths) => Some(ldap_acceptor(paths)?),
            };
            let listener = tokio::net::TcpListener::bind(door.bind)
                .await
                .map_err(|reason| format!("cannot listen on {}: {reason}", door.bind))?;
            Some(tokio::spawn(ldapfront::serve(
                listener,
                tls,
                front_pool,
                front_tenancy,
                front_provider,
                ldapfront::Front {
                    realm_id: door.realm_id,
                    base_dn: door.base_dn,
                },
            )))
        }
    };

    // The mesh door, bound with the others for the same reason: a port
    // asked for and not listenable fails the deployment now.
    #[cfg(feature = "mesh")]
    let meshing = match config::mesh::MeshFront::from_env().map_err(|reason| reason.to_string())? {
        None => None,
        Some(door) => {
            let listener = tokio::net::TcpListener::bind(door.bind)
                .await
                .map_err(|reason| format!("cannot listen on {}: {reason}", door.bind))?;
            Some(tokio::spawn(server::grpc::serve(
                listener,
                server::grpc::Door {
                    pool: mesh_pool,
                    tenancy: mesh_tenancy,
                    origin: mesh_origin,
                },
            )))
        }
    };

    // Bound before anything is announced, and before the probes say started.
    // Neither server hears signals itself: the framework's own handler would
    // stop accepting the moment one lands, ahead of the drain below that
    // fails readiness first and gives an orchestrator time to route away.
    let probes = {
        let vitals = vitals.clone();
        HttpServer::new(move || App::new().configure(register_ops(&vitals, measured)))
            .disable_signals()
            .bind(ops)
            .map_err(|reason| format!("cannot listen on {ops}: {reason}"))?
            .run()
    };

    // The live feed's own ear on the database, one per process, handed to
    // every worker: the SSE door subscribes here, the store speaks at commit.
    let live_feed = server::live::listen(
        config::required("DATABASE_URL")
            .map_err(|e| e.to_string())?
            .parse()
            .map_err(|e| format!("SAFFUI_DATABASE_URL does not parse: {e}"))?,
    );

    // Bound before anything is announced, so a port already taken fails here
    // rather than after the log line says it is serving.
    let plane = HttpServer::new(move || {
        observed_with(measured)
            .configure(register(&plane))
            .app_data(actix_web::web::Data::new(live_feed.clone()))
    })
    .disable_signals()
    .bind(bind)
    .map_err(|reason| format!("cannot listen on {bind}: {reason}"))?
    .run();

    // Both ports are bound, so a probe asking now gets a true answer.
    vitals.started();

    // After the ports, so a deployment that cannot listen fails before it has
    // deleted anything.
    let sweeping = server::jobs::sweep_expired_rows(
        swept_pool,
        swept_tenancy,
        config::jobs::sweep_every().map_err(|reason| reason.to_string())?,
    );
    let syncing = server::jobs::sync_federated_shadows(
        synced_pool,
        synced_tenancy,
        synced_sealing.clone(),
        config::jobs::federation_sync_every().map_err(|reason| reason.to_string())?,
    );
    let delivering = server::jobs::deliver_outbox_events(
        plane_pool_for_outbox,
        tenancy_for_outbox,
        synced_sealing,
        origin_for_outbox,
        config::jobs::outbox_every().map_err(|reason| reason.to_string())?,
    );

    let draining = vitals.clone();
    let plane_handle = plane.handle();
    let probes_handle = probes.handle();
    tokio::spawn(async move {
        // An orchestrator says SIGTERM where a terminal says SIGINT, and both
        // mean the same drain. Listening for SIGINT alone would have a
        // `docker stop` or a pod eviction kill this process outright, in the
        // middle of whatever it was answering.
        let interrupted = signal::ctrl_c();
        let terminated = async {
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(mut termination) => {
                    termination.recv().await;
                }
                // A listener that cannot be installed is a signal this
                // process will never hear; the other one still is.
                Err(_) => std::future::pending().await,
            }
        };
        let heard = tokio::select! {
            outcome = interrupted => outcome.is_ok(),
            () = terminated => true,
        };
        if !heard {
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
    if let Some(fronting) = fronting {
        fronting.abort();
    }
    #[cfg(feature = "mesh")]
    if let Some(meshing) = meshing {
        meshing.abort();
    }
    if let Some(delivering) = delivering {
        delivering.abort();
    }
    if let Some(syncing) = syncing {
        syncing.abort();
    }
    if let Some(sweeping) = sweeping {
        sweeping.abort();
    }
    served.map_err(|reason| reason.to_string())
}

/// The acceptor the LDAP front seals with, from the PEM pair the operator
/// named. Read once at startup: a listener that cannot seal refuses to
/// start, rather than refusing every handshake, hours later, to whoever
/// dials.
fn ldap_acceptor(paths: &config::ldap::TlsPaths) -> Result<openssl::ssl::SslContext, String> {
    let mut acceptor =
        openssl::ssl::SslAcceptor::mozilla_intermediate_v5(openssl::ssl::SslMethod::tls_server())
            .map_err(|reason| format!("cannot build the ldap acceptor: {reason}"))?;
    acceptor
        .set_certificate_chain_file(&paths.certificate)
        .map_err(|reason| format!("cannot read {}: {reason}", paths.certificate.display()))?;
    acceptor
        .set_private_key_file(&paths.key, openssl::ssl::SslFiletype::PEM)
        .map_err(|reason| format!("cannot read {}: {reason}", paths.key.display()))?;
    acceptor
        .check_private_key()
        .map_err(|reason| format!("the ldap certificate and key do not pair: {reason}"))?;
    if let Some(authority) = &paths.client_ca {
        acceptor
            .set_ca_file(authority)
            .map_err(|reason| format!("cannot read {}: {reason}", authority.display()))?;
        acceptor.set_verify(
            openssl::ssl::SslVerifyMode::PEER | openssl::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        );
    }
    Ok(acceptor.build().into_context())
}

/// Apply the schema, and give the application role its login when asked.
/// Read the tenant's chain, or check that it holds.
///
/// Its own connection rather than the plane's: the served role is granted no
/// select here on purpose, so a command that read as `saffui_app` would find
/// nothing and say the deployment had no history.
async fn read_chronicle(tenant: &str, max: i64, verify: bool) -> Result<(), String> {
    let connection = config::required("DATABASE_URL").map_err(|e| e.to_string())?;
    let pg: tokio_postgres::Config = connection
        .parse()
        .map_err(|_| "DATABASE_URL is not a connection string".to_owned())?;
    let pool = Pool::builder(Manager::new(pg, NoTls))
        .build()
        .map_err(|reason| format!("cannot build a pool: {reason}"))?;
    let tenancy = Tenancy::unpinned();
    let mut held = pool.get().await.map_err(|e| e.to_string())?;
    let transaction = tenancy
        .transaction(&mut held, &TenantContext::tenant_wide(tenant))
        .await
        .map_err(|reason| format!("the store refused: {reason:?}"))?;

    if verify {
        let crypto = config::crypto::from_env().map_err(|e| e.to_string())?;
        let provider = OpenSslProvider::new(&crypto)
            .map_err(|reason| format!("cannot build crypto: {reason}"))?;
        return match store::tenant_chain::verify(&transaction, tenant, provider.digest())
            .await
            .map_err(|reason| format!("the store refused: {reason:?}"))?
        {
            None => {
                println!("the chain holds");
                Ok(())
            }
            Some(seq) => Err(format!("the chain breaks at entry {seq}")),
        };
    }

    let entries = store::tenant_chain::list_entries(&transaction, tenant, 0, max)
        .await
        .map_err(|reason| format!("the store refused: {reason:?}"))?;
    if entries.is_empty() {
        println!("nothing has happened to a realm of {tenant}");
        return Ok(());
    }
    for entry in entries {
        let at = entry.envelope["occurred_at"].as_f64().unwrap_or_default() as i64;
        let when = chrono::DateTime::from_timestamp(at, 0)
            .map(|held| held.to_rfc3339())
            .unwrap_or_else(|| at.to_string());
        println!(
            "{:>6}  {when}  {:<14} {:<24} {}",
            entry.seq,
            entry.envelope["kind"].as_str().unwrap_or("?"),
            entry.envelope["realm"].as_str().unwrap_or("?"),
            entry.envelope["actor"].as_str().unwrap_or("?"),
        );
    }
    Ok(())
}

async fn migrate() -> Result<(), String> {
    let connection = config::required("DATABASE_URL").map_err(|e| e.to_string())?;
    let pg: tokio_postgres::Config = connection
        .parse()
        .map_err(|_| "DATABASE_URL is not a connection string".to_owned())?;
    let crypto = config::crypto::from_env().map_err(|e| e.to_string())?;
    let provider =
        OpenSslProvider::new(&crypto).map_err(|reason| format!("cannot build crypto: {reason}"))?;

    let report = pgcore::migrations::MigrationRunner::new(store::schema::migrations())
        .run(
            &pg,
            &pgcore::tls::PgConnector::disabled(),
            provider.digest(),
        )
        .await
        .map_err(|reason| format!("the schema could not be applied: {reason:?}"))?;
    if report.is_up_to_date() {
        println!("schema up to date");
    } else {
        println!("applied {:?}", report.applied);
    }

    // The schema creates the role without a login. Only an operator knows the
    // password, and only as a reference, never as a value in a process list.
    if let Some(password) =
        config::optional_secret("APP_ROLE_PASSWORD").map_err(|e| e.to_string())?
    {
        let (owner, link) = pg
            .connect(NoTls)
            .await
            .map_err(|reason| format!("cannot connect as the owner: {reason}"))?;
        tokio::spawn(async move {
            let _ = link.await;
        });
        let quoted = password.expose_secret().replace('\'', "''");
        owner
            .batch_execute(&format!("ALTER ROLE saffui_app LOGIN PASSWORD '{quoted}'"))
            .await
            .map_err(|reason| format!("cannot give the application role its login: {reason}"))?;
        println!("application role may log in");
    }
    Ok(())
}

/// What `provision` is asked for.
struct Wanted {
    tenant: String,
    realm: String,
    console_redirects: Vec<String>,
    clients: Vec<String>,
    redirects: Vec<String>,
    fapi_clients: Vec<String>,
    after_logout: Vec<String>,
    backchannel_logout: Option<String>,
    frontchannel_logout: Option<String>,
    user: Option<String>,
    administrator: bool,
    email: String,
    given_name: Option<String>,
    family_name: Option<String>,
    phone: Option<String>,
    attributes: Vec<String>,
    magic_link: bool,
    texted_login: bool,
    implicit: bool,
    open_registration: bool,
    registration_max_clients: Option<i32>,
    registration_consent: bool,
    registration_hosts: Vec<String>,
}

/// Create what is missing, and say what was created.
async fn provision(wanted: &Wanted) -> Result<(), String> {
    let plane = plane()?;
    let now = chrono::Utc::now().timestamp();
    let console = plane
        .policy
        .parties
        .first()
        .ok_or("SAFFUI_ADMIN_PARTIES names no console")?
        .clone();
    let client_secret =
        config::optional_secret("PROVISION_CLIENT_SECRET").map_err(|e| e.to_string())?;
    let user_password =
        config::optional_secret("PROVISION_USER_PASSWORD").map_err(|e| e.to_string())?;
    let unreadable = |reason: store::error::StoreError| format!("the store refused: {reason:?}");

    let mut connection = plane.pool.get().await.map_err(|e| e.to_string())?;
    // The realm row is tenant isolated, so this transaction may name the
    // future realm and keep its whole birth atomic.
    let transaction = plane
        .tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&wanted.tenant, &wanted.realm),
        )
        .await
        .map_err(|e| e.to_string())?;
    if provisioning::provision_tenant(&transaction, &wanted.tenant, &wanted.tenant)
        .await
        .map_err(unreadable)?
    {
        println!("tenant {} created", wanted.tenant);
    }
    if provisioning::provision_realm_row(&transaction, &wanted.tenant, &wanted.realm)
        .await
        .map_err(|reason| match reason {
            store::error::StoreError::AlreadyExists => {
                format!("realm {} is already used by another tenant", wanted.realm)
            }
            _ => unreadable(reason),
        })?
    {
        println!("realm {} created", wanted.realm);
    }
    let (tenant, realm) = (wanted.tenant.as_str(), wanted.realm.as_str());
    provisioning::provision_standard_scopes(&transaction, tenant, realm)
        .await
        .map_err(unreadable)?;
    provisioning::provision_admin_console(
        &transaction,
        tenant,
        realm,
        &provisioning::AdminConsole {
            client_id: &console,
            scope: &plane.policy.scope,
            redirect_uris: wanted.console_redirects.clone(),
        },
    )
    .await
    .map_err(unreadable)?;
    if provisioning::provision_signing_key(
        &transaction,
        plane.sealing.provider.as_ref(),
        &plane.sealing.envelope,
        tenant,
        realm,
        now,
    )
    .await
    .map_err(unreadable)?
    {
        println!("signing key created");
    }
    if provisioning::provision_browser_flow(&transaction, tenant, realm)
        .await
        .map_err(unreadable)?
    {
        println!("browser flow created");
    }
    let offered = provisioning::provision_offered_flows(&transaction, tenant, realm)
        .await
        .map_err(unreadable)?;
    if offered > 0 {
        println!("{offered} flows offered, none bound");
    }
    if wanted.magic_link
        && provisioning::provision_mailed_login(&transaction, tenant, realm)
            .await
            .map_err(unreadable)?
    {
        println!("mailed sign-in offered");
    }
    if wanted.texted_login
        && provisioning::provision_texted_login(&transaction, tenant, realm)
            .await
            .map_err(unreadable)?
    {
        println!("texted sign-in offered");
    }
    if provisioning::provision_levels(&transaction, realm)
        .await
        .map_err(unreadable)?
    {
        println!("levels mapped");
    }
    if wanted.open_registration
        && provisioning::open_client_registration(
            &transaction,
            realm,
            &RegistrationBounds {
                max_clients: wanted.registration_max_clients,
                requires_consent: wanted.registration_consent,
                trusted_hosts: wanted.registration_hosts.clone(),
            },
        )
        .await
        .map_err(unreadable)?
    {
        println!("client registration opened");
    }
    for client_id in &wanted.clients {
        let created = provisioning::provision_client(
            &transaction,
            plane.sealing.provider.as_ref(),
            tenant,
            realm,
            &provisioning::Registration {
                client_id,
                secret: client_secret.as_ref(),
                redirect_uris: wanted.redirects.clone(),
                post_logout_redirect_uris: wanted.after_logout.clone(),
                backchannel_logout_uri: wanted.backchannel_logout.clone(),
                frontchannel_logout_uri: wanted.frontchannel_logout.clone(),
                implicit: wanted.implicit,
            },
        )
        .await
        .map_err(unreadable)?;
        if created {
            println!("client {client_id} registered");
        }
    }
    for pair in &wanted.fapi_clients {
        let Some((client_id, jwks_path)) = pair.split_once('=') else {
            return Err(format!("--fapi-client wants id=path, got {pair}"));
        };
        let raw = std::fs::read_to_string(jwks_path)
            .map_err(|why| format!("cannot read {jwks_path}: {why}"))?;
        let public_jwks: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|why| format!("{jwks_path} is not a key set: {why}"))?;
        let created = provisioning::provision_fapi_client(
            &transaction,
            plane.sealing.provider.as_ref(),
            tenant,
            realm,
            client_id,
            public_jwks,
            wanted.redirects.clone(),
        )
        .await
        .map_err(unreadable)?;
        if created {
            println!("client {client_id} registered under the fapi2 profile");
        }
    }
    if wanted.administrator && wanted.user.is_none() {
        return Err("--administrator names nobody: give it a --user to grant".into());
    }
    if let Some(user_name) = wanted.user.as_deref() {
        let password = user_password
            .as_ref()
            .ok_or("SAFFUI_PROVISION_USER_PASSWORD is needed to create a user")?;
        let created = provisioning::provision_user(
            &transaction,
            plane.sealing.provider.as_ref(),
            tenant,
            realm,
            &provisioning::Person {
                user_name,
                email: &wanted.email,
                password,
                given_name: wanted.given_name.as_deref(),
                family_name: wanted.family_name.as_deref(),
                phone: wanted.phone.as_deref(),
                attributes: wanted
                    .attributes
                    .iter()
                    .filter_map(|pair| pair.split_once('='))
                    .collect(),
            },
        )
        .await
        .map_err(unreadable)?;
        if created {
            println!("user {user_name} created");
        }
        if wanted.administrator {
            let role_created = provisioning::provision_realm_administration(
                &transaction,
                tenant,
                realm,
                user_name,
            )
            .await
            .map_err(unreadable)?;
            if role_created {
                println!("administrator role created");
            }
            println!("user {user_name} may administer the realm");
        }
    }
    transaction.commit().await.map_err(|e| e.to_string())?;
    Ok(())
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
    // No default. A guess here is not a wrong hostname for one request, it is
    // the issuer baked into every token this deployment ever mints, and those
    // tokens outlive the correction.
    let origin = config::serving::PublicOrigin::from_env().map_err(|e| e.to_string())?;
    let login_ui = config::serving::LoginUi::from_env().map_err(|e| e.to_string())?;

    // Read at startup, not on the first request that needs it. A deployment
    // whose wrapping key is missing refuses to start rather than refusing every
    // token it is asked to mint, hours later, to whoever asked.
    let crypto = config::crypto::from_env().map_err(|e| e.to_string())?;
    let kek = config::crypto::kek_from_env().map_err(|e| e.to_string())?;
    let provider: Arc<dyn CryptoProvider> = Arc::new(
        OpenSslProvider::new(&crypto).map_err(|reason| format!("cannot build crypto: {reason}"))?,
    );
    let envelope = Envelope::new(Arc::clone(&provider), kek.expose_secret())
        .map_err(|reason| format!("cannot build the envelope: {reason}"))?;
    let region = config::optional("REGION");

    let pg: tokio_postgres::Config = connection
        .parse()
        .map_err(|_| "DATABASE_URL is not a connection string".to_owned())?;
    let pool = Pool::builder(Manager::new(pg, NoTls))
        .build()
        .map_err(|reason| format!("cannot build a pool: {reason}"))?;

    let egress = config::serving::Egress::from_env().map_err(|e| e.to_string())?;
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
        origin,
        login_ui,
        hops: config::proxying::Proxying::from_env().map_err(|e| e.to_string())?,
        egress,
        ceiling: config::serving::RealmCeiling::from_env().map_err(|e| e.to_string())?,
        sealing: Sealing {
            sender: match config::messaging::Sink::from_env().map_err(|e| e.to_string())? {
                config::messaging::Sink::None => None,
                config::messaging::Sink::Smtp => Some(Arc::new(server::messaging::Smtp)),
                config::messaging::Sink::Logged => Some(Arc::new(server::messaging::Logged)),
                config::messaging::Sink::Webhook { url } => Some(Arc::new(
                    server::messaging::Webhook::new(url, config::optional("MESSAGE_WEBHOOK_TOKEN")),
                )),
            },
            texter: match config::messaging::TextSink::from_env().map_err(|e| e.to_string())? {
                config::messaging::TextSink::None => None,
                config::messaging::TextSink::Http => {
                    Some(Arc::new(server::messaging::HttpTexter::new(egress)))
                }
                config::messaging::TextSink::Logged => {
                    Some(Arc::new(server::messaging::LoggedTexter))
                }
            },
            provider,
            envelope: Arc::new(envelope),
        },
    })
}
