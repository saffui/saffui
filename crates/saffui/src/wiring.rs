//! The composition root: the one file that knows every crate. It fills the
//! application once, by hand.

use std::sync::{Arc, OnceLock};

use crypto::adapters::digest::ProviderDigester;
use crypto::adapters::open_provider;
use crypto::adapters::otp::ProviderOneTimeCodes;
use crypto::adapters::password::BoundedPasswordHasher;
use crypto::adapters::random::ProviderRandom;
use crypto::adapters::seal::EnvelopeSealer;
use crypto::adapters::sealing_refused::RefusingSealer;
use crypto::adapters::sign::JoseSigner;
use crypto::adapters::webauthn::{KeyService, WebauthnSecurityKeys};
use deadpool_postgres::Pool;
use pgcore::connect::ConnectionPlan;
use pgcore::migrate::EMBEDDED;
use pgcore::migrate::window::SchemaWindow;
use pgcore::pool::{BuildPoolError, PoolSettings, build_pool};
use pgcore::probe::describe_driver_error;
use pgcore::role::{PrivilegedRole, read_role_facts, refuse_privileged_role};
use saffui_core::app::App;
use saffui_core::authz::shares::DecisionShares;
use saffui_core::login::fairness::HashingShares;
use saffui_core::ports::clock::Clock;
use saffui_core::ports::crypto::Sealer;
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

/// What seals the secrets of the deployment.
#[derive(Clone, Copy)]
pub(crate) enum Sealing<'a> {
    UnderRootKey(&'a Secret),
    /// For a command that seals and opens nothing, run without the root key.
    Refused,
}

pub(crate) struct Wired {
    pub(crate) app: App,
    /// Why no security key is served, and who cannot sign in for it, when
    /// none is: what the journal says once the node listens.
    pub(crate) security_keys_refused: Option<&'static str>,
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

/// Wires the product on its database, its secrets sealed as `sealing` says.
/// No connection is opened yet.
pub(crate) fn wire_product(
    settings: Settings,
    database: &ConnectionPlan,
    pool: PoolSettings,
    sealing: Sealing<'_>,
    password_hashers: usize,
) -> Result<Wired, WiringError> {
    // Before anything draws: a library that fails its own vector draws nothing.
    let provider = open_provider().map_err(|_| WiringError::Library)?;
    let sealer: Arc<dyn Sealer> = match sealing {
        Sealing::UnderRootKey(root_key) => Arc::new(
            EnvelopeSealer::new(Arc::clone(&provider), root_key)
                .map_err(|_| WiringError::RootKey)?,
        ),
        Sealing::Refused => Arc::new(RefusingSealer),
    };
    let hasher = BoundedPasswordHasher::new(Arc::clone(&provider), password_hashers)
        .map_err(|_| WiringError::Hasher)?;
    // Cut from the hasher itself: the shares never count other workers than it has.
    let hashing_shares = HashingShares::new(hasher.count_workers());
    let connections = pool.max_size;
    let pool = build_pool(database, pool)?;
    let storage = PgStorage::new(pool.clone(), SchemaWindow::of_exactly(EMBEDDED));
    let security_keys = WebauthnSecurityKeys::for_origin(settings.public_origin.as_str());
    let security_keys_refused = describe_unserved_keys(security_keys.describe_service());
    Ok(Wired {
        security_keys_refused,
        app: App {
            settings,
            storage: Arc::new(storage),
            clock: Arc::new(SystemClock),
            random: Arc::new(ProviderRandom::new(Arc::clone(&provider))),
            digester: Arc::new(ProviderDigester::new(Arc::clone(&provider))),
            sealer,
            hasher: Arc::new(hasher),
            one_time_codes: Arc::new(ProviderOneTimeCodes::new(Arc::clone(&provider))),
            security_keys: Arc::new(security_keys),
            hashing_shares: Arc::new(hashing_shares),
            decision_shares: Arc::new(DecisionShares::for_pool(connections)),
            key_shares: Arc::default(),
            decoy_hash: Arc::new(OnceLock::new()),
            signer: Arc::new(JoseSigner::new(provider)),
        },
        pool,
    })
}

/// What an operator is told when no security key is served.
fn describe_unserved_keys(service: KeyService) -> Option<&'static str> {
    match service {
        KeyService::Served => None,
        KeyService::FipsStrictBuild => Some(
            "this build is fips-strict and the challenges of a security key come from the rand crate: no security key is served, and a person who holds only a key cannot sign in",
        ),
        KeyService::OriginIsAnAddress => Some(
            "the public origin is named by an address: no security key is served, and a person who holds only a key cannot sign in",
        ),
    }
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

#[cfg(test)]
mod tests {
    use crypto::adapters::webauthn::{KeyService, WebauthnSecurityKeys};
    use pgcore::connect::plan_connection;
    use pgcore::pool::PoolSettings;
    use saffui_core::ids::mint_id;
    use saffui_core::settings::{PublicOrigin, Settings};
    use saffui_core::tenancy::RealmId;

    use super::{Sealing, describe_unserved_keys, wire_product};

    const WHO_CANNOT: &str = "a person who holds only a key cannot sign in";

    #[test]
    fn a_node_whose_origin_is_an_address_says_so_and_who_cannot_sign_in() {
        let keys = WebauthnSecurityKeys::for_origin("http://127.0.0.1:8080");

        let told = describe_unserved_keys(keys.describe_service()).expect("a warning");

        assert!(told.contains(WHO_CANNOT), "{told}");
    }

    #[test]
    fn each_reason_no_key_is_served_is_named_and_a_fips_strict_build_claims_no_more() {
        let address = describe_unserved_keys(KeyService::OriginIsAnAddress).expect("a warning");
        assert!(address.contains("named by an address"), "{address}");

        let fips = describe_unserved_keys(KeyService::FipsStrictBuild).expect("a warning");
        assert!(
            fips.contains("fips-strict") && fips.contains("rand crate"),
            "{fips}"
        );
        assert!(fips.contains(WHO_CANNOT), "{fips}");
        assert!(!fips.contains("validated module"), "{fips}");

        assert_eq!(describe_unserved_keys(KeyService::Served), None);
    }

    #[test]
    fn a_node_wired_with_one_hasher_refuses_a_second_share_to_another_realm() {
        let plan = plan_connection("host=127.0.0.1 user=saffui dbname=saffui", None, None)
            .expect("a loopback plan");
        // No connection is opened: the pool dials on its first borrow.
        let wired = wire_product(
            Settings::reached_directly(
                PublicOrigin::parse("https://id.example.test").expect("an origin"),
            ),
            &plan,
            PoolSettings::default(),
            Sealing::Refused,
            1,
        )
        .expect("a product");
        let app = &wired.app;
        let realm = || RealmId::from_uuid(mint_id(app).expect("an identifier"));

        let held = app.hashing_shares.take(realm(), None).expect("a share");
        assert!(
            app.hashing_shares.take(realm(), None).is_none(),
            "one hasher, one share for the node, whatever realm asks"
        );
        drop(held);
    }
}
