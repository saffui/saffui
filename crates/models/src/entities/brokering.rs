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

/// A rule turning what an upstream provider asserted into something local.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpMapperModel {
    pub mapper_id: String,
    pub realm_id: String,
    pub provider_alias: String,
    pub name: String,
    pub mapper_type: String,
    pub configs: Option<crate::entities::attributes::AttributesMap>,
    pub metadata: crate::auditable::AuditableModel,
}

/// The create and update payload for one rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpMapperMutationModel {
    pub name: String,
    pub mapper_type: String,
    #[serde(default)]
    pub configs: Option<crate::entities::attributes::AttributesMap>,
}

impl IdpMapperMutationModel {
    pub fn into_model(
        self,
        mapper_id: String,
        realm_id: String,
        provider_alias: String,
        metadata: crate::auditable::AuditableModel,
    ) -> IdpMapperModel {
        IdpMapperModel {
            mapper_id,
            realm_id,
            provider_alias,
            name: self.name,
            mapper_type: self.mapper_type,
            configs: self.configs,
            metadata,
        }
    }
}

/// The directory a realm federates its users from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserFederationModel {
    pub realm_id: String,
    pub enabled: Option<bool>,
    pub configs: Option<crate::entities::attributes::AttributesMap>,
    pub metadata: crate::auditable::AuditableModel,
}

/// The write payload for the one directory a realm holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserFederationMutationModel {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub configs: Option<crate::entities::attributes::AttributesMap>,
}
