//! One artifact, several subcommands.
//!
//! One rather than two because the pieces share their configuration, their
//! schema window and their store, and two binaries would carry two copies of
//! that agreement. Splitting later moves this file; splitting the crates before
//! anything needed it would have been a shape chosen in advance.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use actix_web::{App, HttpServer};
use clap::{Parser, Subcommand};
use crypto::envelope::Envelope;
use crypto::provider::CryptoProvider;
use crypto::provider::openssl::OpenSslProvider;
use deadpool_postgres::{Manager, Pool};
use secrecy::ExposeSecret;
use server::api::config::{Plane, Sealing, observed, register, register_ops};
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
        /// Let the registered clients receive what the authorization endpoint
        /// mints, rather than only a code to exchange.
        #[arg(long = "implicit", default_value_t = false)]
        implicit: bool,
    },
}

fn main() -> ExitCode {
    let command = Cli::parse().command;

    // Before anything that could have something to say. What is logged and
    // how are the operator's, from the environment; absent, every record at
    // `info` and above, as text a person reads at a terminal. A collector
    // that wants one JSON object per line asks for `json`.
    commons::observability::init(
        &config::optional("LOG").unwrap_or_else(|| "info".to_owned()),
        &config::optional("LOG_FORMAT").unwrap_or_else(|| "text".to_owned()),
    );

    let outcome = tokio::runtime::Runtime::new()
        .map_err(|reason| reason.to_string())
        .and_then(|runtime| {
            runtime.block_on(async {
                match command {
                    Command::Serve { bind, ops } => serve(&bind, &ops).await,
                    Command::Migrate => migrate().await,
                    Command::Provision {
                        tenant,
                        realm,
                        console_redirects,
                        clients,
                        redirects,
                        after_logout,
                        backchannel_logout,
                        frontchannel_logout,
                        user,
                        email,
                        given_name,
                        family_name,
                        phone,
                        attributes,
                        magic_link,
                        implicit,
                    } => {
                        provision(&Wanted {
                            tenant,
                            realm,
                            console_redirects,
                            clients,
                            redirects,
                            after_logout,
                            backchannel_logout,
                            frontchannel_logout,
                            user,
                            email,
                            given_name,
                            family_name,
                            phone,
                            attributes,
                            magic_link,
                            implicit,
                        })
                        .await
                    }
                }
            })
        });

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
    let (swept_pool, swept_tenancy) = (plane.pool.clone(), plane.tenancy.clone());

    // Bound before anything is announced, and before the probes say started.
    let probes = {
        let vitals = vitals.clone();
        HttpServer::new(move || App::new().configure(register_ops(&vitals)))
            .bind(ops)
            .map_err(|reason| format!("cannot listen on {ops}: {reason}"))?
            .run()
    };

    // Bound before anything is announced, so a port already taken fails here
    // rather than after the log line says it is serving.
    let plane = HttpServer::new(move || observed().configure(register(&plane)))
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
    if let Some(sweeping) = sweeping {
        sweeping.abort();
    }
    served.map_err(|reason| reason.to_string())
}

/// Apply the schema, and give the application role its login when asked.
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
    after_logout: Vec<String>,
    backchannel_logout: Option<String>,
    frontchannel_logout: Option<String>,
    user: Option<String>,
    email: String,
    given_name: Option<String>,
    family_name: Option<String>,
    phone: Option<String>,
    attributes: Vec<String>,
    magic_link: bool,
    implicit: bool,
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
    // Tenant wide first: a realm cannot be scoped to before it exists.
    let transaction = plane
        .tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide(&wanted.tenant))
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
        .map_err(unreadable)?
    {
        println!("realm {} created", wanted.realm);
    }
    transaction.commit().await.map_err(|e| e.to_string())?;

    let transaction = plane
        .tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&wanted.tenant, &wanted.realm),
        )
        .await
        .map_err(|e| e.to_string())?;
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
    if wanted.magic_link
        && provisioning::provision_mailed_login(&transaction, tenant, realm)
            .await
            .map_err(unreadable)?
    {
        println!("mailed sign-in offered");
    }
    if provisioning::provision_levels(&transaction, realm)
        .await
        .map_err(unreadable)?
    {
        println!("levels mapped");
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
        sealing: Sealing {
            sender: match config::messaging::Sink::from_env().map_err(|e| e.to_string())? {
                config::messaging::Sink::None => None,
                config::messaging::Sink::Smtp => Some(Arc::new(server::messaging::Smtp)),
                config::messaging::Sink::Logged => Some(Arc::new(server::messaging::Logged)),
                config::messaging::Sink::Webhook { url } => Some(Arc::new(
                    server::messaging::Webhook::new(url, config::optional("MESSAGE_WEBHOOK_TOKEN")),
                )),
            },
            provider,
            envelope: Arc::new(envelope),
        },
    })
}
