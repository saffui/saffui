use serde::{Deserialize, Serialize};

pub mod apple_secret;
pub mod federated_identity;
pub mod link;
pub mod login_state;
pub mod oidc_config;
pub mod presets;

/// A value that must not be rendered until it is used.
///
/// The PKCE verifier and the nonce are secret until redemption, the raw state
/// for the life of the login, and an upstream token for as long as it is kept.
/// They all reach a log the same way: a struct holding one gets formatted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerSecret(String);

impl BrokerSecret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Read it. Named so every place one is read is greppable.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BrokerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrokerSecret(<redacted>)")
    }
}
