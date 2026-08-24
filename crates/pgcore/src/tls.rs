use std::path::PathBuf;

use openssl::error::ErrorStack;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use postgres_openssl::MakeTlsConnector;
use tokio_postgres::Config;
use tokio_postgres::config::SslMode;

/// How a connection is secured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PgTlsMode {
    /// Nothing on the wire. For a unix socket or trusted loopback, and never a
    /// default — an operator asks for it.
    Disabled,
    /// Encrypted, with the server's certificate unverified. Stops someone
    /// listening; stops nobody standing in the middle.
    Require,
    /// Encrypted and verified: the certificate must chain to this bundle and
    /// name the host being connected to.
    VerifyFull { ca_file: PathBuf },
}

impl PgTlsMode {
    /// Read a mode and its bundle from configuration.
    ///
    /// Case and the two spellings of a separator are both accepted, because an
    /// operator writing `verify_full` meant `verify-full` — and a mode that
    /// failed to parse would have to fall back to something, which is the one
    /// thing a TLS setting must never do.
    pub fn from_parts(mode: &str, ca_file: Option<&str>) -> Result<Self, PgTlsError> {
        match mode.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "disabled" | "disable" | "off" | "none" => Ok(Self::Disabled),
            "require" | "required" => Ok(Self::Require),
            "verify-full" | "verify" => {
                let ca_file = ca_file
                    .map(str::trim)
                    .filter(|path| !path.is_empty())
                    .ok_or(PgTlsError::MissingCaFile)?;

                Ok(Self::VerifyFull {
                    ca_file: PathBuf::from(ca_file),
                })
            }
            other => Err(PgTlsError::UnknownMode(other.to_string())),
        }
    }

    /// What the driver negotiates. Verification is the connector's job, not this
    /// one's, so both encrypted modes ask for the same thing here.
    fn ssl_mode(&self) -> SslMode {
        match self {
            Self::Disabled => SslMode::Disable,
            Self::Require | Self::VerifyFull { .. } => SslMode::Require,
        }
    }
}

/// Why a policy could not be built.
#[derive(Debug, thiserror::Error)]
pub enum PgTlsError {
    #[error("unknown TLS mode '{0}' (expected disabled, require or verify-full)")]
    UnknownMode(String),
    #[error("TLS mode 'verify-full' needs a CA bundle path")]
    MissingCaFile,
    #[error("the TLS connector could not be built")]
    Build(#[source] ErrorStack),
    #[error("the CA bundle at {path} could not be loaded")]
    CaFile {
        path: PathBuf,
        #[source]
        source: ErrorStack,
    },
}

/// A built policy, cheap to clone, handed to every connection site.
#[derive(Clone)]
pub struct PgConnector {
    ssl_mode: SslMode,
    maker: MakeTlsConnector,
}

impl std::fmt::Debug for PgConnector {
    /// Names the policy and not the material behind it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgConnector")
            .field("encrypted", &self.is_encrypted())
            .finish_non_exhaustive()
    }
}

impl PgConnector {
    /// Build the policy.
    pub fn build(mode: &PgTlsMode) -> Result<Self, PgTlsError> {
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(PgTlsError::Build)?;

        match mode {
            // Never invoked under `SslMode::Disable`, but built anyway so every
            // site takes the same type.
            PgTlsMode::Disabled => {}
            PgTlsMode::Require => builder.set_verify(SslVerifyMode::NONE),
            PgTlsMode::VerifyFull { ca_file } => {
                builder
                    .set_ca_file(ca_file)
                    .map_err(|source| PgTlsError::CaFile {
                        path: ca_file.clone(),
                        source,
                    })?;
                builder.set_verify(SslVerifyMode::PEER);
            }
        }

        let mut maker = MakeTlsConnector::new(builder.build());
        if matches!(mode, PgTlsMode::Require) {
            // The chain check is off; the hostname check has to go with it, or
            // "encrypt, do not verify" would still refuse a certificate naming
            // another host — half a policy, failing for the wrong reason.
            maker.set_callback(|config, _| {
                config.set_verify_hostname(false);
                Ok(())
            });
        }

        Ok(Self {
            ssl_mode: mode.ssl_mode(),
            maker,
        })
    }

    /// The policy that encrypts nothing, for a unix socket or a test.
    pub fn disabled() -> Self {
        Self::build(&PgTlsMode::Disabled).expect("building a policy with nothing to load")
    }

    /// The maker each connection site takes by value.
    pub fn maker(&self) -> MakeTlsConnector {
        self.maker.clone()
    }

    /// The same policy in the pool's own vocabulary.
    pub fn pool_ssl_mode(&self) -> deadpool_postgres::SslMode {
        match self.ssl_mode {
            SslMode::Disable => deadpool_postgres::SslMode::Disable,
            _ => deadpool_postgres::SslMode::Require,
        }
    }

    /// A connection config with this policy stamped on it.
    pub fn apply(&self, config: &Config) -> Config {
        let mut config = config.clone();
        config.ssl_mode(self.ssl_mode);
        config
    }

    /// Whether anything is encrypted at all.
    pub fn is_encrypted(&self) -> bool {
        !matches!(self.ssl_mode, SslMode::Disable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every spelling an operator might write, and what each means.
    #[test]
    fn a_mode_is_read_however_it_is_written() {
        for written in ["disabled", "DISABLE", " off ", "none"] {
            assert_eq!(
                PgTlsMode::from_parts(written, None).unwrap(),
                PgTlsMode::Disabled,
                "{written}"
            );
        }

        for written in ["require", "REQUIRED", " require "] {
            assert_eq!(
                PgTlsMode::from_parts(written, None).unwrap(),
                PgTlsMode::Require,
                "{written}"
            );
        }

        for written in ["verify-full", "verify_full", "VERIFY-FULL", "verify"] {
            assert_eq!(
                PgTlsMode::from_parts(written, Some("/etc/ca.pem")).unwrap(),
                PgTlsMode::VerifyFull {
                    ca_file: PathBuf::from("/etc/ca.pem")
                },
                "{written}"
            );
        }
    }

    /// A mode nobody defined is refused rather than resolved to something.
    ///
    /// The one setting that must never fall back: every fallback is either
    /// weaker than what was asked for, or stronger and refuses to connect. Both
    /// are worse than saying the word was not understood.
    #[test]
    fn an_unknown_mode_is_refused() {
        for written in ["", "verify-ca", "prefer", "allow", "tls", "yes", "1"] {
            assert!(
                matches!(
                    PgTlsMode::from_parts(written, Some("/etc/ca.pem")),
                    Err(PgTlsError::UnknownMode(_))
                ),
                "{written:?} was read as a mode"
            );
        }
    }

    /// Verification without a bundle is refused: there would be nothing to
    /// verify against, and the mode's whole meaning is that there is.
    #[test]
    fn verification_without_a_bundle_is_refused() {
        for absent in [None, Some(""), Some("   ")] {
            assert!(
                matches!(
                    PgTlsMode::from_parts("verify-full", absent),
                    Err(PgTlsError::MissingCaFile)
                ),
                "{absent:?}"
            );
        }

        // And the other modes do not need one.
        assert!(PgTlsMode::from_parts("require", None).is_ok());
        assert!(PgTlsMode::from_parts("disabled", None).is_ok());
    }

    /// Only the disabled policy leaves the wire in the clear.
    #[test]
    fn everything_but_disabled_encrypts() {
        assert!(
            !PgConnector::build(&PgTlsMode::Disabled)
                .unwrap()
                .is_encrypted()
        );
        assert!(
            PgConnector::build(&PgTlsMode::Require)
                .unwrap()
                .is_encrypted()
        );
        assert!(!PgConnector::disabled().is_encrypted());
    }

    /// The policy reaches the connection config, and reaches the pool's
    /// vocabulary as the same thing.
    #[test]
    fn the_policy_reaches_every_site_the_same_way() {
        let config: Config = "host=localhost user=saffui".parse().unwrap();

        let disabled = PgConnector::disabled();
        assert_eq!(disabled.apply(&config).get_ssl_mode(), SslMode::Disable);
        assert_eq!(
            disabled.pool_ssl_mode(),
            deadpool_postgres::SslMode::Disable
        );

        let required = PgConnector::build(&PgTlsMode::Require).unwrap();
        assert_eq!(required.apply(&config).get_ssl_mode(), SslMode::Require);
        assert_eq!(
            required.pool_ssl_mode(),
            deadpool_postgres::SslMode::Require
        );
    }

    /// Verifying needs a bundle that exists, and says which one when it does
    /// not.
    #[test]
    fn a_bundle_that_is_not_there_names_itself() {
        let missing = PgTlsMode::VerifyFull {
            ca_file: PathBuf::from("/no/such/ca.pem"),
        };

        let error = PgConnector::build(&missing).unwrap_err();

        assert!(matches!(error, PgTlsError::CaFile { .. }));
        assert!(error.to_string().contains("/no/such/ca.pem"));
    }

    /// A real bundle builds a verifying policy.
    #[test]
    fn a_bundle_that_is_there_builds() {
        let bundle = temp_ca();

        let connector = PgConnector::build(&PgTlsMode::VerifyFull {
            ca_file: bundle.0.clone(),
        })
        .expect("a self-signed bundle is still a bundle");

        assert!(connector.is_encrypted());
    }

    /// Nothing about the policy renders beyond whether it encrypts.
    #[test]
    fn the_policy_does_not_render_its_material() {
        let rendered = format!("{:?}", PgConnector::build(&PgTlsMode::Require).unwrap());

        assert!(rendered.contains("encrypted: true"));
        assert!(!rendered.contains("BEGIN"));
    }

    /// A throwaway self-signed certificate, removed when it drops.
    struct TempCa(PathBuf);

    impl Drop for TempCa {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn temp_ca() -> TempCa {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509, X509NameBuilder};

        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "saffui-test-ca").unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();

        let path = std::env::temp_dir().join(format!("saffui_ca_{}.pem", std::process::id()));
        std::fs::write(&path, builder.build().to_pem().unwrap()).unwrap();

        TempCa(path)
    }

    /// Where a TLS-enabled server is, and the bundles to judge it by.
    ///
    /// Absent, these panic naming the variable. A test that returns quietly here
    /// would report that the policy works while never having negotiated
    /// anything.
    fn tls_server() -> (Config, PathBuf, PathBuf) {
        let connection = std::env::var("SAFFUI_TEST_PG_TLS").unwrap_or_else(|_| {
            panic!("these tests need a TLS-enabled server: set SAFFUI_TEST_PG_TLS")
        });
        let certs = PathBuf::from(
            std::env::var("SAFFUI_TEST_PG_TLS_CERTS").unwrap_or_else(|_| {
                panic!(
                    "set SAFFUI_TEST_PG_TLS_CERTS to the directory holding server.crt and other.crt"
                )
            }),
        );

        (
            connection.parse().expect("a connection string"),
            certs.join("server.crt"),
            certs.join("other.crt"),
        )
    }

    async fn connects(config: &Config, connector: &PgConnector) -> bool {
        match connector.apply(config).connect(connector.maker()).await {
            Ok((client, connection)) => {
                let driver = tokio::spawn(async move {
                    let _ = connection.await;
                });
                let ok = client.simple_query("SELECT 1").await.is_ok();
                driver.abort();
                ok
            }
            Err(_) => false,
        }
    }

    /// `require` encrypts and asks no questions about the certificate.
    ///
    /// This is the whole difference from `verify-full`, and the only way to see
    /// it is against a server whose certificate would not survive verification:
    /// a self-signed one. A policy that quietly verified here would refuse to
    /// connect, and a deployment reading "require" would be down for a reason
    /// its configuration does not mention.
    #[tokio::test]
    #[ignore = "needs a TLS-enabled server (SAFFUI_TEST_PG_TLS)"]
    async fn require_encrypts_without_judging_the_certificate() {
        let (config, _, _) = tls_server();
        let connector = PgConnector::build(&PgTlsMode::Require).unwrap();

        assert!(connector.is_encrypted());
        assert!(
            connects(&config, &connector).await,
            "require refused a self-signed certificate, so it is verifying"
        );
    }

    /// `verify-full` accepts a certificate that chains to its bundle.
    #[tokio::test]
    #[ignore = "needs a TLS-enabled server (SAFFUI_TEST_PG_TLS)"]
    async fn verify_full_accepts_what_its_bundle_vouches_for() {
        let (config, server_ca, _) = tls_server();

        let connector = PgConnector::build(&PgTlsMode::VerifyFull { ca_file: server_ca }).unwrap();

        assert!(connects(&config, &connector).await);
    }

    /// And refuses one it does not.
    ///
    /// The assertion the other two exist to frame: without it, a `verify-full`
    /// that verified nothing would pass every test above.
    #[tokio::test]
    #[ignore = "needs a TLS-enabled server (SAFFUI_TEST_PG_TLS)"]
    async fn verify_full_refuses_what_its_bundle_does_not() {
        let (config, _, other_ca) = tls_server();

        let connector = PgConnector::build(&PgTlsMode::VerifyFull { ca_file: other_ca }).unwrap();

        assert!(
            !connects(&config, &connector).await,
            "verify-full accepted a certificate from another authority"
        );
    }
}
