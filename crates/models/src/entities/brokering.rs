use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Who a local user is at an upstream provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedIdentityModel {
    pub realm_id: String,
    pub user_id: String,
    pub provider_alias: String,
    pub external_user_id: String,
    pub external_username: String,
    pub created_at: DateTime<Utc>,
}

/// One brokered login in flight: what left for the upstream, kept so what
/// comes back can be tied to it and spent exactly once. The verifier and the
/// nonce live here and never reach the browser.
#[derive(Debug, Clone)]
pub struct BrokerLoginState {
    pub state_hash: String,
    pub provider_alias: String,
    pub auth_session: String,
    pub code_verifier: String,
    pub nonce: String,
    pub expires_at: DateTime<Utc>,
}
