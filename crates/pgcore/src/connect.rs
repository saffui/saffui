//! The one connection policy. Whether the link is encrypted is written by the
//! operator, never negotiated: left unsaid, a clear link is accepted only
//! when every host is this machine.

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use postgres_openssl::MakeTlsConnector;
use tokio_postgres::config::{Host, SslMode};
use tokio_postgres::{Client, Config, NoTls};

/// How the link to the database is protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsMode {
    /// A clear link, written on purpose.
    Disable,
    /// Encrypted, the server certificate not verified.
    Require,
    /// Encrypted, the certificate chain and the host name verified.
    VerifyFull,
}

impl FromStr for TlsMode {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "disable" => Ok(TlsMode::Disable),
            "require" => Ok(TlsMode::Require),
            "verify-full" => Ok(TlsMode::VerifyFull),
            _ => Err(()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionPolicyError {
    #[error("the database connection string cannot be read")]
    UnreadableConnectionString,
    #[error("the database connection string names no host")]
    NoHost,
    #[error("the TLS mode is a setting of its own: remove sslmode from the connection string")]
    TlsModeInConnectionString,
    #[error(
        "a database host is not this machine: say the TLS mode (disable, require or verify-full)"
    )]
    TlsModeRequired,
    #[error("a CA file is only used by the verify-full TLS mode")]
    CaFileWithoutVerification,
    #[error("the TLS settings of the database link cannot be loaded")]
    TlsSetup,
}

/// A connection the policy has accepted: where to, and how the link is protected.
#[derive(Clone, Debug)]
pub struct ConnectionPlan {
    pub(crate) config: Config,
    pub(crate) tls: LinkProtection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LinkProtection {
    Clear,
    Encrypted,
    Verified { ca_file: Option<PathBuf> },
}

/// Applies the policy to what the operator wrote.
///
/// # Errors
///
/// Returns why the connection is refused before anything is dialled.
pub fn plan_connection(
    connection: &str,
    tls_mode: Option<TlsMode>,
    ca_file: Option<PathBuf>,
) -> Result<ConnectionPlan, ConnectionPolicyError> {
    // Two places to say the mode are two answers: the driver's own default would
    // also fall back to a clear link without a word.
    if connection.contains("sslmode") {
        return Err(ConnectionPolicyError::TlsModeInConnectionString);
    }
    let mut config: Config = connection
        .parse()
        .map_err(|_| ConnectionPolicyError::UnreadableConnectionString)?;
    if config.get_hosts().is_empty() {
        return Err(ConnectionPolicyError::NoHost);
    }
    let tls = match tls_mode {
        Some(TlsMode::Disable) => LinkProtection::Clear,
        Some(TlsMode::Require) => LinkProtection::Encrypted,
        Some(TlsMode::VerifyFull) => LinkProtection::Verified { ca_file: None },
        // The driver dials a `hostaddr` in place of its host.
        None if config.get_hosts().iter().all(is_this_machine)
            && config.get_hostaddrs().iter().all(IpAddr::is_loopback) =>
        {
            LinkProtection::Clear
        }
        None => return Err(ConnectionPolicyError::TlsModeRequired),
    };
    let tls = match (tls, ca_file) {
        (LinkProtection::Verified { .. }, ca_file) => LinkProtection::Verified { ca_file },
        (_, Some(_)) => return Err(ConnectionPolicyError::CaFileWithoutVerification),
        (unverified, None) => unverified,
    };
    config.ssl_mode(if tls == LinkProtection::Clear {
        SslMode::Disable
    } else {
        SslMode::Require
    });
    Ok(ConnectionPlan { config, tls })
}

fn is_this_machine(host: &Host) -> bool {
    match host {
        Host::Tcp(name) => {
            name == "localhost" || name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
        }
        #[cfg(unix)]
        Host::Unix(_) => true,
    }
}

impl ConnectionPlan {
    /// Names the session for whoever reads `pg_stat_activity`.
    #[must_use]
    pub fn named(mut self, application: &str) -> Self {
        self.config.application_name(application);
        self
    }

    /// Adds a server setting to every session of this plan.
    #[must_use]
    pub(crate) fn with_session_setting(mut self, name: &str, value: &str) -> Self {
        let mut options = self.config.get_options().unwrap_or_default().to_owned();
        if !options.is_empty() {
            options.push(' ');
        }
        options.push_str("-c");
        options.push_str(name);
        options.push('=');
        options.push_str(value);
        self.config.options(&options);
        self
    }

    pub(crate) fn build_tls_connector(
        &self,
    ) -> Result<Option<MakeTlsConnector>, ConnectionPolicyError> {
        let ca_file = match &self.tls {
            LinkProtection::Clear => return Ok(None),
            LinkProtection::Encrypted => None,
            LinkProtection::Verified { ca_file } => ca_file.as_ref(),
        };
        let verified = matches!(self.tls, LinkProtection::Verified { .. });

        let mut builder =
            SslConnector::builder(SslMethod::tls()).map_err(|_| ConnectionPolicyError::TlsSetup)?;
        if let Some(ca_file) = ca_file {
            builder
                .set_ca_file(ca_file)
                .map_err(|_| ConnectionPolicyError::TlsSetup)?;
        }
        if !verified {
            builder.set_verify(SslVerifyMode::NONE);
        }
        let mut connector = MakeTlsConnector::new(builder.build());
        if !verified {
            connector.set_callback(|configuration, _domain| {
                configuration.set_verify_hostname(false);
                Ok(())
            });
        }
        Ok(Some(connector))
    }

    /// Opens one connection outside any pool, for what must keep its session:
    /// a session lock is lost the moment a pooler hands the session to another.
    ///
    /// # Errors
    ///
    /// Returns the policy error, or the driver's when the server cannot be reached.
    pub async fn connect_directly(&self) -> Result<Client, DirectConnectionError> {
        let client = match self.build_tls_connector()? {
            None => {
                let (client, connection) = self.config.connect(NoTls).await?;
                tokio::spawn(connection);
                client
            }
            Some(connector) => {
                let (client, connection) = self.config.connect(connector).await?;
                tokio::spawn(connection);
                client
            }
        };
        Ok(client)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DirectConnectionError {
    #[error(transparent)]
    Policy(#[from] ConnectionPolicyError),
    #[error("the database cannot be reached")]
    Unreachable(#[from] tokio_postgres::Error),
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{ConnectionPolicyError, LinkProtection, TlsMode, plan_connection};

    #[test]
    fn a_loopback_host_without_a_mode_gets_a_clear_link() {
        for connection in [
            "host=127.0.0.1 user=saffui_app dbname=saffui",
            "host=localhost user=saffui_app dbname=saffui",
            "postgres://saffui_app@[::1]:5432/saffui",
        ] {
            let plan = plan_connection(connection, None, None).expect("a loopback plan");
            assert_eq!(plan.tls, LinkProtection::Clear, "{connection}");
        }
    }

    #[test]
    fn a_remote_host_without_a_mode_is_refused() {
        let refused = plan_connection("host=db.internal user=saffui_app", None, None);
        assert!(matches!(
            refused,
            Err(ConnectionPolicyError::TlsModeRequired)
        ));
    }

    #[test]
    fn a_remote_address_behind_a_loopback_host_without_a_mode_is_refused() {
        let refused = plan_connection(
            "host=localhost hostaddr=203.0.113.7 user=saffui_app",
            None,
            None,
        );
        assert!(matches!(
            refused,
            Err(ConnectionPolicyError::TlsModeRequired)
        ));
        let plan = plan_connection(
            "host=localhost hostaddr=127.0.0.1 user=saffui_app",
            None,
            None,
        )
        .expect("a loopback plan");
        assert_eq!(plan.tls, LinkProtection::Clear);
    }

    #[test]
    fn one_remote_host_among_loopback_hosts_is_enough_to_refuse() {
        let refused = plan_connection("host=127.0.0.1,db.internal user=saffui_app", None, None);
        assert!(matches!(
            refused,
            Err(ConnectionPolicyError::TlsModeRequired)
        ));
    }

    #[test]
    fn a_clear_link_to_a_remote_host_is_accepted_when_written() {
        let plan = plan_connection(
            "host=db.internal user=saffui_app",
            Some(TlsMode::Disable),
            None,
        )
        .expect("a written choice");
        assert_eq!(plan.tls, LinkProtection::Clear);
    }

    #[test]
    fn the_mode_cannot_be_said_in_the_connection_string() {
        let refused = plan_connection("host=127.0.0.1 sslmode=disable", None, None);
        assert!(matches!(
            refused,
            Err(ConnectionPolicyError::TlsModeInConnectionString)
        ));
    }

    #[test]
    fn a_ca_file_without_verification_is_refused() {
        let refused = plan_connection(
            "host=db.internal user=saffui_app",
            Some(TlsMode::Require),
            Some(PathBuf::from("/etc/ssl/ca.pem")),
        );
        assert!(matches!(
            refused,
            Err(ConnectionPolicyError::CaFileWithoutVerification)
        ));
    }

    #[test]
    fn each_written_mode_is_read() {
        assert_eq!("disable".parse(), Ok(TlsMode::Disable));
        assert_eq!("require".parse(), Ok(TlsMode::Require));
        assert_eq!("verify-full".parse(), Ok(TlsMode::VerifyFull));
        assert_eq!("prefer".parse::<TlsMode>(), Err(()));
    }
}
