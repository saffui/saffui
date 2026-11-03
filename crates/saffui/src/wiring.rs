//! The composition root: the one file that knows every crate. It fills the
//! application once, by hand.

use std::sync::{Arc, OnceLock};

use crypto::adapters::digest::ProviderDigester;
use crypto::adapters::open_provider;
use crypto::adapters::otp::ProviderOneTimeCodes;
use crypto::adapters::password::BoundedPasswordHasher;
use crypto::adapters::random::ProviderRandom;
use crypto::adapters::seal::EnvelopeSealer;
use crypto::adapters::sign::JoseSigner;
use crypto::adapters::webauthn::WebauthnSecurityKeys;
use deadpool_postgres::Pool;
use pgcore::connect::ConnectionPlan;
use pgcore::migrate::EMBEDDED;
use pgcore::migrate::window::SchemaWindow;
use pgcore::pool::{BuildPoolError, PoolSettings, build_pool};
use pgcore::probe::describe_driver_error;
use pgcore::role::{PrivilegedRole, read_role_facts, refuse_privileged_role};
use saffui_core::app::App;
use saffui_core::login::fairness::HashingShares;
use saffui_core::ports::clock::Clock;
use saffui_core::ports::storage::StorageUnavailable;
use saffui_core::secret::Secret;
use saffui_core::settings::Settings;
use store::PgStorage;
use time::OffsetDateTime;

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

pub(crate) struct Wired {
    pub(crate) app: App,
    /// Whether a security key can be enrolled on the public origin.
    pub(crate) security_keys_served: bool,
    pool: Pool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WiringError {
    #[error("cannot reach the database: {0}")]
    Pool(#[from] BuildPoolError),
    #[error("the cryptographic library failed its self-test")]
    Library,
    #[error("the root key cannot be used")]
    RootKey,
    #[error("the password hasher cannot be set up")]
    Hasher,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StartupRefusal {
    #[error("the database cannot serve: {0}")]
    Storage(#[from] StorageUnavailable),
    #[error("the role of the database link cannot be read")]
    RoleUnreadable,
    #[error(transparent)]
    Role(#[from] PrivilegedRole),
    #[error("the password hasher cannot answer")]
    Hasher,
    #[error(
        "the retention link cannot purge: it must reach the database under the retention role, which bypasses row security, is no superuser, and may only read and remove what expired"
    )]
    RetentionRole,
}

/// Wires the product on its database, under the root key of the deployment.
/// No connection is opened yet.
pub(crate) fn wire_product(
    settings: Settings,
    database: &ConnectionPlan,
    pool: PoolSettings,
    root_key: &Secret,
    password_hashers: usize,
) -> Result<Wired, WiringError> {
    // Before anything draws: a library that fails its own vector draws nothing.
    let provider = open_provider().map_err(|_| WiringError::Library)?;
    let sealer =
        EnvelopeSealer::new(Arc::clone(&provider), root_key).map_err(|_| WiringError::RootKey)?;
    let hasher = BoundedPasswordHasher::new(Arc::clone(&provider), password_hashers)
        .map_err(|_| WiringError::Hasher)?;
    let pool = build_pool(database, pool)?;
    let storage = PgStorage::new(pool.clone(), SchemaWindow::of_exactly(EMBEDDED));
    let security_keys = WebauthnSecurityKeys::for_origin(settings.public_origin.as_str());
    Ok(Wired {
        security_keys_served: security_keys.is_available(),
        app: App {
            settings,
            storage: Arc::new(storage),
            clock: Arc::new(SystemClock),
            random: Arc::new(ProviderRandom::new(Arc::clone(&provider))),
            digester: Arc::new(ProviderDigester::new(Arc::clone(&provider))),
            sealer: Arc::new(sealer),
            hasher: Arc::new(hasher),
            one_time_codes: Arc::new(ProviderOneTimeCodes::new(Arc::clone(&provider))),
            security_keys: Arc::new(security_keys),
            hashing_shares: Arc::new(HashingShares::new(password_hashers)),
            decoy_hash: Arc::new(OnceLock::new()),
            signer: Arc::new(JoseSigner::new(provider)),
        },
        pool,
    })
}

impl Wired {
    /// Refuses to serve from a database this binary cannot read, or under a
    /// role that row security does not bind.
    pub(crate) async fn refuse_unfit_database(&self) -> Result<(), StartupRefusal> {
        self.app.storage.probe().await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| StorageUnavailable::Unreachable)?;
        let facts = read_role_facts(&client).await.map_err(|error| {
            tracing::error!(
                cause = %describe_driver_error(&error),
                "the role of the database link cannot be read"
            );
            StartupRefusal::RoleUnreadable
        })?;
        refuse_privileged_role(&facts)?;
        Ok(())
    }

    /// Makes the hash an unknown name is verified against. Made here and not
    /// at the first unknown name: that request would take twice the time of
    /// the others, and tell that its name is unknown.
    pub(crate) async fn prepare_decoy_hash(&self) -> Result<(), StartupRefusal> {
        self.app
            .read_decoy_hash()
            .await
            .map(|_| ())
            .map_err(|_| StartupRefusal::Hasher)
    }
}
