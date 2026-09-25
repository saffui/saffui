use std::sync::Arc;

use crypto::envelope::Envelope;
use crypto::provider::{CryptoError, CryptoProvider};

/// What it takes to open a realm's sealed keys.
///
/// One value rather than two fields, because neither half is any use alone and
/// a caller holding one would have to go looking for the other.
///
/// Shared rather than copied. `Envelope` is deliberately not `Clone`: a derived
/// one would duplicate deployment key material every time a worker was built,
/// and there is no reason for a second copy to exist.
#[derive(Clone)]
pub struct Sealing {
    /// What carries a message out, when this deployment has said how. Absent
    /// refuses to send rather than choosing a way nobody asked for.
    pub sender: Option<std::sync::Arc<dyn auth::messaging::Deliver>>,
    /// What carries a text out, under the same rule.
    pub texter: Option<std::sync::Arc<dyn auth::messaging::Texter>>,
    pub provider: Arc<dyn CryptoProvider>,
    pub envelope: Arc<Envelope>,
    /// What every door counts a typed name under, derived from the envelope
    /// once for the process rather than once a request.
    pub names: Arc<auth::login::throttle::NameKey>,
}

impl Sealing {
    /// Built over `envelope`, and deriving the key names are counted under from
    /// it here, so the two cannot come from different deployments.
    pub fn new(
        sender: Option<Arc<dyn auth::messaging::Deliver>>,
        texter: Option<Arc<dyn auth::messaging::Texter>>,
        provider: Arc<dyn CryptoProvider>,
        envelope: Envelope,
    ) -> Result<Sealing, CryptoError> {
        let names = Arc::new(auth::login::throttle::NameKey::derive(&envelope)?);
        Ok(Sealing {
            sender,
            texter,
            provider,
            envelope: Arc::new(envelope),
            names,
        })
    }
}
