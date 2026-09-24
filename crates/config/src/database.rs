use std::time::Duration;

use crate::ConfigError;

const ADDRESS: &str = "DATABASE_URL";
const TLS: &str = "DATABASE_TLS";
const TLS_CA: &str = "DATABASE_TLS_CA";
const POOL_SIZE: &str = "DATABASE_POOL_SIZE";
const POOL_WAIT: &str = "DATABASE_POOL_WAIT_SECONDS";
const IDLE_IN_TRANSACTION: &str = "DATABASE_IDLE_IN_TRANSACTION_SECONDS";
const CONNECT: &str = "DATABASE_CONNECT_SECONDS";

/// How this process reaches its database, as the operator wrote it.
///
/// Read here and settled by the caller, who knows what a mode means for the
/// hosts the address names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Database {
    pub address: String,
    /// `disabled`, `require` or `verify-full`; absent is decided by the host.
    pub tls: Option<String>,
    /// The bundle `verify-full` checks the server's certificate against.
    pub tls_ca: Option<String>,
    pub pool_size: usize,
    pub pool_wait: Duration,
    pub idle_in_transaction: Duration,
    pub connect: Duration,
}

impl Database {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            address: crate::required(ADDRESS)?,
            tls: crate::optional(TLS),
            tls_ca: crate::optional(TLS_CA),
            pool_size: at_least_one(POOL_SIZE, 16)? as usize,
            pool_wait: Duration::from_secs(at_least_one(POOL_WAIT, 5)?),
            idle_in_transaction: Duration::from_secs(at_least_one(IDLE_IN_TRANSACTION, 30)?),
            connect: Duration::from_secs(at_least_one(CONNECT, 10)?),
        })
    }
}

/// Zero is refused rather than read: a pool of none, a wait of none, or a
/// transaction ended the moment it starts are none of them a setting.
fn at_least_one(key: &str, default: u64) -> Result<u64, ConfigError> {
    match crate::parse_or(key, default)? {
        0 => Err(ConfigError::Invalid {
            key: format!("{}{key}", crate::PREFIX),
            expected: "number above zero".to_owned(),
        }),
        set => Ok(set),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{clear, env_guard, set};

    const EVERY: [&str; 7] = [
        ADDRESS,
        TLS,
        TLS_CA,
        POOL_SIZE,
        POOL_WAIT,
        IDLE_IN_TRANSACTION,
        CONNECT,
    ];

    #[test]
    fn the_address_alone_is_enough() {
        let _guard = env_guard();
        clear(&EVERY);
        set(ADDRESS, "host=localhost user=saffui");

        assert_eq!(
            Database::from_env().unwrap(),
            Database {
                address: "host=localhost user=saffui".to_owned(),
                tls: None,
                tls_ca: None,
                pool_size: 16,
                pool_wait: Duration::from_secs(5),
                idle_in_transaction: Duration::from_secs(30),
                connect: Duration::from_secs(10),
            }
        );
        clear(&EVERY);
    }

    #[test]
    fn every_setting_is_read_under_its_name() {
        let _guard = env_guard();
        clear(&EVERY);
        set(ADDRESS, "host=postgres");
        set(TLS, "verify-full");
        set(TLS_CA, "/certs/server.crt");
        set(POOL_SIZE, "4");
        set(POOL_WAIT, "2");
        set(IDLE_IN_TRANSACTION, "60");
        set(CONNECT, "3");

        let read = Database::from_env().unwrap();
        assert_eq!(read.tls.as_deref(), Some("verify-full"));
        assert_eq!(read.tls_ca.as_deref(), Some("/certs/server.crt"));
        assert_eq!(read.pool_size, 4);
        assert_eq!(read.pool_wait, Duration::from_secs(2));
        assert_eq!(read.idle_in_transaction, Duration::from_secs(60));
        assert_eq!(read.connect, Duration::from_secs(3));
        clear(&EVERY);
    }

    /// Zero and the unreadable are refused and named, never read as a default.
    #[test]
    fn a_bound_of_nothing_is_refused() {
        let _guard = env_guard();
        for key in [POOL_SIZE, POOL_WAIT, IDLE_IN_TRANSACTION, CONNECT] {
            for written in ["0", "several"] {
                clear(&EVERY);
                set(ADDRESS, "host=localhost");
                set(key, written);
                let refused = Database::from_env().unwrap_err();
                assert!(
                    refused.to_string().contains(&format!("SAFFUI_{key}")),
                    "{key}={written}: {refused}"
                );
            }
        }
        clear(&EVERY);
        assert!(matches!(
            Database::from_env(),
            Err(ConfigError::Missing { .. })
        ));
    }
}
