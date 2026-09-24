use std::error::Error as _;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use deadpool_postgres::{Manager, Pool, PoolError, Runtime, TimeoutType, Timeouts};
use tokio_postgres::Config;
use tokio_postgres::config::{Host, SslMode};

use crate::tls::{PgConnector, PgTlsError, PgTlsMode};

/// How much of the database the served pool may hold, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub size: usize,
    /// How long a request waits for a free connection before it is refused.
    pub wait: Duration,
    /// How long a pooled connection may sit inside a transaction nobody uses.
    pub idle_in_transaction: Duration,
    /// How long opening one connection may take.
    pub connect: Duration,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            size: 16,
            wait: Duration::from_secs(5),
            idle_in_transaction: Duration::from_secs(30),
            connect: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    /// Never repeats the address, which carries the password.
    #[error("the database address is not a connection string")]
    Unreadable,
    #[error("the database at {host} is not on this machine and no TLS mode was stated")]
    Unstated { host: String },
    /// One of the two encrypts and the other does not, and neither is picked.
    #[error("the TLS mode is {stated} and the address says sslmode={written}")]
    Contradicted {
        stated: String,
        written: &'static str,
    },
    #[error(transparent)]
    Tls(#[from] PgTlsError),
    #[error("the connection pool could not be built")]
    Pool,
}

/// Where the database is and how it is reached, settled once per process.
///
/// Every connection the process opens is built from here, so none of them is
/// secured differently from the others.
#[derive(Clone)]
pub struct Database {
    config: Config,
    tls: PgConnector,
    /// A pooler in transaction mode the served pool goes through instead,
    /// settled by the same rules as the address itself.
    pooler: Option<Reached>,
    bounds: Bounds,
}

/// One address, and how it is secured.
#[derive(Clone)]
struct Reached {
    config: Config,
    tls: PgConnector,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Database")
            .field("tls", &self.tls)
            .field("behind_a_pooler", &self.pooler.is_some())
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl Database {
    /// Read the address and settle how it is reached.
    ///
    /// An `sslmode` of `require` or `disable` in the address is a stated mode
    /// too; `prefer` states nothing, being the very fallback refused here. Two
    /// stated modes that disagree about encrypting are refused rather than one
    /// picked, since either pick is weaker than somebody wrote.
    ///
    /// Left unstated, the mode is plaintext only when every host is this
    /// machine, where nothing crosses a wire. Anywhere else nothing is assumed:
    /// the driver's own default tries encryption and falls back to the clear
    /// without a word, so the process refuses to start instead.
    pub fn new(
        address: &str,
        mode: Option<&str>,
        ca_file: Option<&str>,
        bounds: Bounds,
    ) -> Result<Self, DatabaseError> {
        let reached = settle(address, mode, ca_file, bounds.connect)?;
        Ok(Self {
            config: reached.config,
            tls: reached.tls,
            pooler: None,
            bounds,
        })
    }

    /// Serve requests through a pooler in transaction mode in front of the
    /// same database, its address settled by the same rules.
    ///
    /// Only the served pool goes through it. What needs a session of its own,
    /// the listener, the migrations and the owner's work, keeps the direct
    /// address: a pooler in transaction mode lends a server connection for one
    /// transaction at a time, and a LISTEN or a session lock would be lent
    /// along with it.
    pub fn with_pooler(
        mut self,
        address: &str,
        mode: Option<&str>,
        ca_file: Option<&str>,
    ) -> Result<Self, DatabaseError> {
        self.pooler = Some(settle(address, mode, ca_file, self.bounds.connect)?);
        Ok(self)
    }

    /// Whether the served pool goes through a pooler.
    pub fn has_pooler(&self) -> bool {
        self.pooler.is_some()
    }

    pub fn bounds(&self) -> Bounds {
        self.bounds
    }

    /// For work that holds a connection as long as it needs to: the
    /// migrations, the owner's grant, the chain reader, the listener.
    pub fn direct(&self) -> Config {
        self.config.clone()
    }

    pub fn connector(&self) -> &PgConnector {
        &self.tls
    }

    /// The served pool: through the pooler when there is one.
    pub fn pool(&self) -> Result<Pool, DatabaseError> {
        let (config, tls) = self.served();
        self.bounded(config, tls)
    }

    /// What the served pool opens its connections with. Through a pooler
    /// nothing rides at startup: it refuses the options it cannot keep track
    /// of, and the bound on an idle transaction rides in each transaction.
    fn served(&self) -> (Config, &PgConnector) {
        match &self.pooler {
            Some(pooler) => (pooler.config.clone(), &pooler.tls),
            None => (self.pooled(), &self.tls),
        }
    }

    /// A pool on the direct address, for a command working as the owner.
    pub fn direct_pool(&self) -> Result<Pool, DatabaseError> {
        self.bounded(self.pooled(), &self.tls)
    }

    fn bounded(&self, config: Config, tls: &PgConnector) -> Result<Pool, DatabaseError> {
        Pool::builder(Manager::new(config, tls.maker()))
            .max_size(self.bounds.size)
            // Bounded, where the pool would otherwise wait forever: a full pool
            // then refuses where it would have stopped answering.
            .timeouts(Timeouts {
                wait: Some(self.bounds.wait),
                create: Some(self.bounds.connect),
                ..Timeouts::default()
            })
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|_| DatabaseError::Pool)
    }

    /// What a pooled connection is opened with: the direct settings, and a
    /// transaction left open with nobody talking to it ended by the server.
    ///
    /// Never on the direct ones, whose users hold a transaction for minutes on
    /// purpose; a migration ended part way is worse than the leak this bounds.
    fn pooled(&self) -> Config {
        let mut config = self.config.clone();
        let guard = format!(
            "-c idle_in_transaction_session_timeout={}",
            self.bounds.idle_in_transaction.as_millis()
        );
        let options = match config.get_options() {
            Some(held) => format!("{held} {guard}"),
            None => guard,
        };
        config.options(options);
        config
    }
}

/// Why the pool handed out no connection, in the terms an operator acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreached {
    /// Every connection is in use, and none came back inside the wait.
    Busy,
    /// Opening a connection took longer than it may.
    TimedOut,
    /// The handshake failed: a certificate this side does not trust, one
    /// naming another host, or a server that does not speak TLS.
    Tls,
    /// The server answered and turned the connection away: the role, its
    /// password, an access rule, a database it does not hold, no slot left.
    Refused,
    /// Nothing answered at the address.
    Unreachable,
    /// The pool is closed, or a failure none of these names.
    Other,
}

/// The names the driver gives two of its kinds. The kinds are private, and
/// the message is the one trace of them it makes public.
const TLS_FAILED: &str = "error performing TLS handshake";
const AUTHENTICATION_FAILED: &str = "authentication error";

impl Unreached {
    pub fn of(error: &PoolError) -> Self {
        match error {
            PoolError::Timeout(TimeoutType::Wait) => Self::Busy,
            PoolError::Timeout(_) => Self::TimedOut,
            PoolError::Backend(failure) => Self::of_connecting(failure),
            _ => Self::Other,
        }
    }

    /// A refusal the server sent comes typed. The rest is told apart by the
    /// driver's message, or by the socket failure underneath it.
    fn of_connecting(failure: &tokio_postgres::Error) -> Self {
        if failure.as_db_error().is_some() {
            return Self::Refused;
        }
        match failure.to_string().as_str() {
            TLS_FAILED => return Self::Tls,
            AUTHENTICATION_FAILED => return Self::Refused,
            _ => {}
        }
        let mut cause = failure.source();
        while let Some(held) = cause {
            if held.is::<io::Error>() {
                return Self::Unreachable;
            }
            cause = held.source();
        }
        Self::Other
    }
}

/// A failure to connect with every cause beneath it, the driver's own words
/// naming only its kind. Not for a statement's refusal, which can carry the
/// values it was bound.
pub fn describe_connection_failure(failure: &tokio_postgres::Error) -> String {
    let mut told = failure.to_string();
    let mut cause = failure.source();
    while let Some(held) = cause {
        let said = held.to_string();
        // The TLS layer repeats the error it wraps.
        if !told.contains(&said) {
            told.push_str(": ");
            told.push_str(&said);
        }
        cause = held.source();
    }
    told
}

/// Read one address and settle how it is reached.
fn settle(
    address: &str,
    mode: Option<&str>,
    ca_file: Option<&str>,
    connect: Duration,
) -> Result<Reached, DatabaseError> {
    let mut config: Config = address.parse().map_err(|_| DatabaseError::Unreadable)?;
    let written = match config.get_ssl_mode() {
        SslMode::Disable => Some(("disable", PgTlsMode::Disabled)),
        SslMode::Require => Some(("require", PgTlsMode::Require)),
        _ => None,
    };
    let mode = match (mode, written) {
        (Some(stated), written) => {
            let chosen = PgTlsMode::from_parts(stated, ca_file)?;
            if let Some((spelled, implied)) = written
                && (implied == PgTlsMode::Disabled) != (chosen == PgTlsMode::Disabled)
            {
                return Err(DatabaseError::Contradicted {
                    stated: stated.trim().to_owned(),
                    written: spelled,
                });
            }
            chosen
        }
        (None, Some((_, implied))) => implied,
        (None, None) => match first_host_elsewhere(&config) {
            None => PgTlsMode::Disabled,
            Some(host) => return Err(DatabaseError::Unstated { host }),
        },
    };
    let tls = PgConnector::build(&mode)?;
    config.connect_timeout(connect);
    Ok(Reached {
        config: tls.apply(&config),
        tls,
    })
}

/// The first host a connection could reach that is not this machine.
///
/// A socket and a loopback address are this machine, and so is `localhost`
/// unless an address beside it says where the dialling really goes.
fn first_host_elsewhere(config: &Config) -> Option<String> {
    let hosts = config.get_hosts();
    let dialled = config.get_hostaddrs();
    for index in 0..hosts.len().max(dialled.len()) {
        let named = match hosts.get(index) {
            Some(Host::Tcp(name)) => Some(name.as_str()),
            Some(_) => None,
            None => None,
        };
        let here = match (dialled.get(index), named) {
            (Some(address), _) => address.is_loopback(),
            (None, Some(name)) => {
                name == "localhost" || name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
            }
            (None, None) => true,
        };
        if !here {
            return Some(match (named, dialled.get(index)) {
                (Some(name), Some(address)) => format!("{name} ({address})"),
                (Some(name), None) => name.to_owned(),
                (None, address) => address.map(IpAddr::to_string).unwrap_or_default(),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settled(address: &str) -> Result<Database, DatabaseError> {
        Database::new(address, None, None, Bounds::default())
    }

    /// On this machine nothing crosses a wire, so nothing has to be said.
    #[test]
    fn a_database_on_this_machine_needs_no_mode() {
        for address in [
            "host=127.0.0.1 user=saffui",
            "host=localhost user=saffui",
            "host=::1 user=saffui",
            "host=/var/run/postgresql user=saffui",
            "postgresql://saffui@localhost:5433/saffui",
        ] {
            let database = settled(address).unwrap_or_else(|why| panic!("{address}: {why}"));
            assert!(!database.connector().is_encrypted(), "{address}");
        }
    }

    /// Anywhere else the mode is the operator's to state, and the refusal says
    /// which host it was about.
    #[test]
    fn a_database_elsewhere_needs_its_mode_stated() {
        for (address, named) in [
            ("host=postgres user=saffui", "postgres"),
            ("host=db.example.com user=saffui", "db.example.com"),
            ("host=10.0.0.5 user=saffui", "10.0.0.5"),
            (
                "host=localhost hostaddr=10.0.0.5 user=saffui",
                "localhost (10.0.0.5)",
            ),
            (
                "host=localhost,db.example.com user=saffui",
                "db.example.com",
            ),
        ] {
            match settled(address) {
                Err(DatabaseError::Unstated { host }) => assert_eq!(host, named, "{address}"),
                other => panic!("{address} was settled as {other:?}"),
            }
        }
    }

    /// A stated mode is taken as stated, the clear included: saying so is the
    /// point.
    #[test]
    fn a_stated_mode_is_taken_as_stated() {
        let required =
            Database::new("host=postgres", Some("require"), None, Bounds::default()).unwrap();
        assert!(required.connector().is_encrypted());

        let clear =
            Database::new("host=postgres", Some("disabled"), None, Bounds::default()).unwrap();
        assert!(!clear.connector().is_encrypted());

        assert!(matches!(
            Database::new(
                "host=postgres",
                Some("verify-full"),
                None,
                Bounds::default()
            ),
            Err(DatabaseError::Tls(PgTlsError::MissingCaFile))
        ));
    }

    /// What the address writes is a stated mode, and it is not overridden into
    /// something weaker.
    #[test]
    fn the_address_can_state_the_mode() {
        let encrypted = Database::new(
            "host=localhost sslmode=require",
            None,
            None,
            Bounds::default(),
        )
        .unwrap();
        assert!(
            encrypted.connector().is_encrypted(),
            "a written require was dropped"
        );

        let clear = Database::new(
            "host=postgres sslmode=disable",
            None,
            None,
            Bounds::default(),
        )
        .unwrap();
        assert!(!clear.connector().is_encrypted());

        assert!(
            matches!(
                Database::new(
                    "host=postgres sslmode=prefer",
                    None,
                    None,
                    Bounds::default()
                ),
                Err(DatabaseError::Unstated { .. })
            ),
            "prefer is the fallback, and states nothing"
        );
    }

    /// Two stated modes that disagree about encrypting: neither wins.
    #[test]
    fn two_modes_that_disagree_are_refused() {
        for (address, stated) in [
            ("host=localhost sslmode=require", "disabled"),
            ("host=postgres sslmode=disable", "require"),
        ] {
            assert!(
                matches!(
                    Database::new(address, Some(stated), None, Bounds::default()),
                    Err(DatabaseError::Contradicted { .. })
                ),
                "{address} with {stated}"
            );
        }
        let agreed = Database::new(
            "host=postgres sslmode=require",
            Some("require"),
            None,
            Bounds::default(),
        )
        .unwrap();
        assert!(agreed.connector().is_encrypted());
    }

    /// The address carries the password, and an error is what reaches a log.
    #[test]
    fn an_unreadable_address_is_not_repeated() {
        let refused = settled("host=db password=hunter2 port=notaport").unwrap_err();
        assert!(!refused.to_string().contains("hunter2"));
        assert!(!format!("{refused:?}").contains("hunter2"));
    }

    /// Only the pool ends an idle transaction. The migration runner and the
    /// listener hold theirs open on purpose.
    #[test]
    fn only_the_pool_carries_the_idle_guard() {
        let database = settled("host=localhost user=saffui").unwrap();
        assert!(
            database
                .pooled()
                .get_options()
                .is_some_and(|held| held.contains("idle_in_transaction_session_timeout=30000")),
            "a pooled connection could idle inside a transaction for ever"
        );
        assert!(
            database
                .direct()
                .get_options()
                .is_none_or(|held| !held.contains("idle_in_transaction_session_timeout")),
            "the migrations would be ended part way"
        );
    }

    /// Options the address already carries are kept beside the guard.
    #[test]
    fn options_in_the_address_are_kept() {
        let database = settled("host=localhost options='-c search_path=saffui'").unwrap();
        let options = database.pooled();
        let held = options.get_options().unwrap();
        assert!(held.contains("search_path=saffui"), "{held}");
        assert!(
            held.contains("idle_in_transaction_session_timeout"),
            "{held}"
        );
    }

    /// A pooler's address is held to the rules the database's own is.
    #[test]
    fn a_pooler_is_settled_like_the_database() {
        let direct = || settled("host=localhost user=saffui_app").unwrap();
        assert!(!direct().has_pooler());
        assert!(
            direct()
                .with_pooler("host=localhost port=6432 user=saffui_app", None, None)
                .unwrap()
                .has_pooler()
        );
        match direct().with_pooler("host=pooler.internal port=6432", None, None) {
            Err(DatabaseError::Unstated { host }) => assert_eq!(host, "pooler.internal"),
            other => panic!("a pooler elsewhere was settled as {other:?}"),
        }
        let required = direct()
            .with_pooler("host=pooler.internal port=6432", Some("require"), None)
            .unwrap();
        assert!(required.served().1.is_encrypted());
        assert!(matches!(
            direct().with_pooler("host=pooler password=hunter2 port=notaport", None, None),
            Err(DatabaseError::Unreadable)
        ));
    }

    /// Through a pooler the served pool sends no startup options, which a
    /// pooler in transaction mode refuses; the direct connections are as
    /// they were, and without a pooler so is the served pool.
    #[test]
    fn nothing_rides_at_startup_through_a_pooler() {
        let alone = settled("host=localhost user=saffui_app").unwrap();
        let pooled = alone
            .clone()
            .with_pooler("host=localhost port=6432 user=saffui_app", None, None)
            .unwrap();

        let (through, _) = pooled.served();
        assert_eq!(through.get_ports(), [6432]);
        assert!(
            through
                .get_options()
                .is_none_or(|held| !held.contains("idle_in_transaction_session_timeout")),
            "the pooler would refuse every connection"
        );
        assert!(
            alone
                .served()
                .0
                .get_options()
                .is_some_and(|held| held.contains("idle_in_transaction_session_timeout")),
            "without a pooler the served pool lost its guard"
        );
        assert_eq!(pooled.direct().get_ports(), alone.direct().get_ports());
    }

    /// A pool timing out cannot say more than which phase ran out.
    #[test]
    fn a_timed_out_phase_says_which() {
        assert_eq!(
            Unreached::of(&PoolError::Timeout(TimeoutType::Wait)),
            Unreached::Busy
        );
        assert_eq!(
            Unreached::of(&PoolError::Timeout(TimeoutType::Create)),
            Unreached::TimedOut
        );
        assert_eq!(Unreached::of(&PoolError::Closed), Unreached::Other);
    }

    /// An address on this machine where every connection is handed to `answer`.
    async fn served_by<F, Answered>(answer: F) -> String
    where
        F: Fn(tokio::net::TcpStream) -> Answered + Send + 'static,
        Answered: Future<Output = ()> + Send + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(answer(socket));
            }
        });
        format!("host=127.0.0.1 port={port} user=saffui dbname=saffui")
    }

    async fn refusal_from(address: &str, mode: Option<&str>) -> PoolError {
        let bounds = Bounds {
            connect: Duration::from_millis(300),
            ..Bounds::default()
        };
        Database::new(address, mode, None, bounds)
            .unwrap()
            .pool()
            .unwrap()
            .get()
            .await
            .expect_err("a connection was handed out")
    }

    #[tokio::test]
    async fn a_port_nobody_listens_on_is_unreachable() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let refused = refusal_from(&format!("host=127.0.0.1 port={port} user=saffui"), None).await;
        assert_eq!(Unreached::of(&refused), Unreached::Unreachable);
    }

    #[tokio::test]
    async fn a_server_that_never_answers_runs_out_the_time() {
        let address = served_by(|socket| async move {
            let _held = socket;
            tokio::time::sleep(Duration::from_secs(5)).await;
        })
        .await;
        let refused = refusal_from(&address, None).await;
        assert_eq!(Unreached::of(&refused), Unreached::TimedOut);
    }

    /// A server that does not speak TLS, asked for it: the handshake is what
    /// failed, and the log line says why.
    #[tokio::test]
    async fn a_server_without_tls_fails_the_handshake() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let address = served_by(|mut socket| async move {
            let mut request = [0u8; 8];
            if socket.read_exact(&mut request).await.is_ok() {
                let _ = socket.write_all(b"N").await;
            }
        })
        .await;
        let refused = refusal_from(&address, Some("require")).await;
        assert_eq!(Unreached::of(&refused), Unreached::Tls);
        let PoolError::Backend(failure) = &refused else {
            panic!("{refused:?}");
        };
        let told = describe_connection_failure(failure);
        assert!(told.contains("server does not support TLS"), "{told}");
    }

    /// A server that reads the startup and answers with a refusal, as one
    /// turning away a password does.
    #[tokio::test]
    async fn a_server_that_turns_the_role_away_refuses() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let address = served_by(|mut socket| async move {
            let mut length = [0u8; 4];
            if socket.read_exact(&mut length).await.is_err() {
                return;
            }
            let mut startup = vec![0u8; u32::from_be_bytes(length) as usize - 4];
            if socket.read_exact(&mut startup).await.is_err() {
                return;
            }
            let mut fields = Vec::new();
            for (kind, value) in [
                (b'S', "FATAL"),
                (b'V', "FATAL"),
                (b'C', "28P01"),
                (b'M', "password authentication failed for user \"saffui\""),
            ] {
                fields.push(kind);
                fields.extend_from_slice(value.as_bytes());
                fields.push(0);
            }
            fields.push(0);
            let mut refusal = vec![b'E'];
            refusal.extend_from_slice(&(fields.len() as u32 + 4).to_be_bytes());
            refusal.extend_from_slice(&fields);
            let _ = socket.write_all(&refusal).await;
        })
        .await;
        let refused = refusal_from(&address, None).await;
        assert_eq!(Unreached::of(&refused), Unreached::Refused);
        let PoolError::Backend(failure) = &refused else {
            panic!("{refused:?}");
        };
        let told = describe_connection_failure(failure);
        assert!(told.contains("password authentication failed"), "{told}");
    }

    fn test_address() -> String {
        std::env::var("SAFFUI_TEST_PG")
            .unwrap_or_else(|_| panic!("these tests need a database: set SAFFUI_TEST_PG"))
    }

    #[tokio::test]
    #[ignore = "needs a database (SAFFUI_TEST_PG)"]
    async fn a_role_the_server_does_not_hold_is_refused() {
        let mut config: Config = test_address().parse().unwrap();
        config.user("saffui_no_such_role").password("nothing");
        let refused = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
            .runtime(Runtime::Tokio1)
            .build()
            .unwrap()
            .get()
            .await
            .expect_err("a role nobody created signed in");
        assert_eq!(Unreached::of(&refused), Unreached::Refused);
    }

    /// A full pool refuses inside its wait instead of holding the request for
    /// ever.
    #[tokio::test]
    #[ignore = "needs a database (SAFFUI_TEST_PG)"]
    async fn a_full_pool_refuses_inside_its_wait() {
        let bounds = Bounds {
            size: 1,
            wait: Duration::from_millis(300),
            ..Bounds::default()
        };
        let pool = Database::new(&test_address(), None, None, bounds)
            .unwrap()
            .pool()
            .unwrap();
        let _held = pool.get().await.expect("the one connection");

        let asked = std::time::Instant::now();
        let refused = tokio::time::timeout(Duration::from_secs(5), pool.get())
            .await
            .expect("the pool waited past its bound")
            .expect_err("a full pool handed out a connection");
        assert!(
            asked.elapsed() < Duration::from_secs(2),
            "{:?}",
            asked.elapsed()
        );
        assert_eq!(Unreached::of(&refused), Unreached::Busy);
    }

    /// A transaction left open on a pooled connection is ended by the server,
    /// with its locks.
    #[tokio::test]
    #[ignore = "needs a database (SAFFUI_TEST_PG)"]
    async fn a_transaction_left_idle_is_ended() {
        let bounds = Bounds {
            idle_in_transaction: Duration::from_millis(300),
            ..Bounds::default()
        };
        let pool = Database::new(&test_address(), None, None, bounds)
            .unwrap()
            .pool()
            .unwrap();
        let held = pool.get().await.unwrap();
        held.batch_execute("BEGIN").await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(
            held.simple_query("SELECT 1").await.is_err(),
            "a transaction idled past its bound and was still open"
        );
    }

    /// The pool dials through the stated policy: the server sees an encrypted
    /// session, verified against the bundle it was given.
    #[tokio::test]
    #[ignore = "needs a TLS-enabled server (SAFFUI_TEST_PG_TLS)"]
    async fn the_pool_speaks_tls_when_asked() {
        let address = std::env::var("SAFFUI_TEST_PG_TLS")
            .unwrap_or_else(|_| panic!("set SAFFUI_TEST_PG_TLS"));
        let certs = std::path::PathBuf::from(
            std::env::var("SAFFUI_TEST_PG_TLS_CERTS")
                .unwrap_or_else(|_| panic!("set SAFFUI_TEST_PG_TLS_CERTS")),
        );
        let bundle = certs.join("server.crt");
        let pool = Database::new(
            &address,
            Some("verify-full"),
            bundle.to_str(),
            Bounds::default(),
        )
        .unwrap()
        .pool()
        .unwrap();

        let encrypted: bool = pool
            .get()
            .await
            .expect("a verified connection")
            .query_one(
                "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(encrypted, "the server saw a session in the clear");
    }

    /// Another authority's bundle: the handshake is refused, and the log line
    /// names the check that refused it rather than only the handshake.
    #[tokio::test]
    #[ignore = "needs a TLS-enabled server (SAFFUI_TEST_PG_TLS)"]
    async fn a_certificate_from_another_authority_fails_the_handshake() {
        let address = std::env::var("SAFFUI_TEST_PG_TLS")
            .unwrap_or_else(|_| panic!("set SAFFUI_TEST_PG_TLS"));
        let certs = std::path::PathBuf::from(
            std::env::var("SAFFUI_TEST_PG_TLS_CERTS")
                .unwrap_or_else(|_| panic!("set SAFFUI_TEST_PG_TLS_CERTS")),
        );
        let refused = Database::new(
            &address,
            Some("verify-full"),
            certs.join("other.crt").to_str(),
            Bounds::default(),
        )
        .unwrap()
        .pool()
        .unwrap()
        .get()
        .await
        .expect_err("a server signed by another authority was trusted");
        assert_eq!(Unreached::of(&refused), Unreached::Tls);
        let PoolError::Backend(failure) = &refused else {
            panic!("{refused:?}");
        };
        let told = describe_connection_failure(failure);
        assert!(told.contains("certificate verify failed"), "{told}");
    }
}
