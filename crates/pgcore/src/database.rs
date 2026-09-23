use std::net::IpAddr;
use std::time::Duration;

use deadpool_postgres::{Manager, Pool, Runtime, Timeouts};
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
    bounds: Bounds,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Database")
            .field("tls", &self.tls)
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
        config.connect_timeout(bounds.connect);
        Ok(Self {
            config: tls.apply(&config),
            tls,
            bounds,
        })
    }

    /// For work that holds a connection as long as it needs to: the
    /// migrations, the owner's grant, the chain reader, the listener.
    pub fn direct(&self) -> Config {
        self.config.clone()
    }

    pub fn connector(&self) -> &PgConnector {
        &self.tls
    }

    /// The served pool.
    pub fn pool(&self) -> Result<Pool, DatabaseError> {
        Pool::builder(Manager::new(self.pooled(), self.tls.maker()))
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

    fn test_address() -> String {
        std::env::var("SAFFUI_TEST_PG")
            .unwrap_or_else(|_| panic!("these tests need a database: set SAFFUI_TEST_PG"))
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
            .expect("the pool waited past its bound");
        assert!(refused.is_err(), "a full pool handed out a connection");
        assert!(
            asked.elapsed() < Duration::from_secs(2),
            "{:?}",
            asked.elapsed()
        );
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
}
