use std::sync::{Arc, OnceLock};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use time::OffsetDateTime;

use crate::authz::shares::DecisionShares;
use crate::error::{ErrorCode, Failure};
use crate::keys::shares::KeyMakingShares;
use crate::login::fairness::HashingShares;
use crate::ports::clock::Clock;
use crate::ports::crypto::{Digester, OneTimeCodes, PasswordHasher, Sealer, SecurityKeys, Signer};
use crate::ports::random::Random;
use crate::ports::storage::Storage;
use crate::secret::Secret;
use crate::settings::Settings;

/// Everything a use case can reach. The binary fills it once.
#[derive(Clone)]
pub struct App {
    pub settings: Settings,
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub random: Arc<dyn Random>,
    pub digester: Arc<dyn Digester>,
    pub sealer: Arc<dyn Sealer>,
    pub signer: Arc<dyn Signer>,
    pub hasher: Arc<dyn PasswordHasher>,
    pub one_time_codes: Arc<dyn OneTimeCodes>,
    pub security_keys: Arc<dyn SecurityKeys>,
    /// What each realm may take of the hashers at once.
    pub hashing_shares: Arc<HashingShares>,
    /// What each tenant, and the node, may have answered by the point of
    /// decision at once.
    pub decision_shares: Arc<DecisionShares>,
    /// The key each tenant is making: one at a time.
    pub key_shares: Arc<KeyMakingShares>,
    /// A hash nobody's password matches, made once per process. Start it empty.
    pub decoy_hash: Arc<OnceLock<String>>,
}

impl App {
    /// The time, at the precision the storage keeps: an instant read back is
    /// equal to the one that was written.
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        let now = self.clock.now();
        now.replace_nanosecond(now.nanosecond() / 1_000 * 1_000)
            .unwrap_or(now)
    }

    /// The hash an unknown name is verified against, so that it costs what a
    /// known name costs. It is the hash of bytes nobody was told.
    ///
    /// # Errors
    ///
    /// Returns the failure of the random source or of the hasher.
    pub async fn read_decoy_hash(&self) -> Result<String, Failure> {
        if let Some(hash) = self.decoy_hash.get() {
            return Ok(hash.clone());
        }
        let mut unknown = vec![0_u8; 32];
        self.random
            .fill(&mut unknown)
            .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
        // Written as text: a password is text, and a hasher may refuse anything else.
        let unknown = Secret::new(URL_SAFE_NO_PAD.encode(&unknown).into_bytes());
        // Made before the node serves (the binary prepares it at start): no caller
        // holds a share for it.
        let hash = self
            .hasher
            .hash_password(unknown, Box::new(()))
            .await
            .map_err(crate::directory::create::translate_hashing_failure)?;
        // Two requests may both compute it: either result serves.
        Ok(self.decoy_hash.get_or_init(|| hash).clone())
    }
}
