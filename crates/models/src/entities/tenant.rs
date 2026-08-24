use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::str_enum::str_enum;

str_enum! {
    #[postgres(name = "tenant_state")]
    /// Whether a tenant may be reached at all.
    pub enum TenantState {
        Active => "active",
        Suspended => "suspended",
        Archived => "archived",
    }
}

/// Per-tenant ceilings an operator may set. Every field `None` — the default —
/// means unlimited.
///
/// These bound what one tenant can make the deployment do, not what it is
/// entitled to: a runaway import in one tenant is the reason they exist.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantLimits {
    pub max_realms: Option<i64>,
    pub max_users_per_realm: Option<i64>,
    pub max_orgs_per_realm: Option<i64>,
    pub max_sessions: Option<i64>,
}

/// A registered tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantModel {
    pub tenant_id: String,
    pub display_name: String,
    pub state: TenantState,
    /// `None` = unlimited.
    pub limits: Option<TenantLimits>,
    /// Residency pin, e.g. `eu-west`.
    pub region: Option<String>,
    pub created_by: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_by: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
    pub version: i32,
}

impl TenantModel {
    pub fn is_active(&self) -> bool {
        self.state == TenantState::Active
    }

    /// A tenant with no limits skips the quota checks rather than comparing
    /// against a zero that would refuse everything.
    pub fn is_unlimited(&self) -> bool {
        self.limits.is_none()
    }
}

/// The create payload. The model's defaults and the database's `created_at`
/// fill the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCreateModel {
    pub tenant_id: String,
    pub display_name: String,
    pub region: Option<String>,
    pub limits: Option<TenantLimits>,
    pub created_by: Option<String>,
}

impl From<TenantCreateModel> for TenantModel {
    fn from(create: TenantCreateModel) -> Self {
        TenantModel {
            tenant_id: create.tenant_id,
            display_name: create.display_name,
            state: TenantState::Active,
            limits: create.limits,
            region: create.region,
            created_by: create.created_by,
            created_at: None, // written by the column default
            updated_by: None,
            updated_at: None,
            version: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;
    use std::str::FromStr;

    fn create() -> TenantCreateModel {
        TenantCreateModel {
            tenant_id: "acme".into(),
            display_name: "Acme".into(),
            region: None,
            limits: None,
            created_by: Some("root".into()),
        }
    }

    #[test]
    fn the_states_agree_with_their_own_spelling() {
        // The count is stated here so that adding a state fails a test rather
        // than quietly widening what the round trip covers.
        assert_eq!(TenantState::ALL.len(), 3);
        assert_round_trips(TenantState::ALL);
    }

    /// A value nobody named does not become the first variant, which would read
    /// a suspended tenant as reachable.
    #[test]
    fn an_unknown_state_is_refused() {
        assert!(TenantState::from_str("activ").is_err());
        assert!(TenantState::from_str("Active").is_err());
        assert!(TenantState::from_str("").is_err());
    }

    #[test]
    fn create_defaults_to_an_active_unlimited_tenant() {
        let tenant: TenantModel = create().into();
        assert!(tenant.is_active());
        assert!(tenant.is_unlimited());
        assert_eq!(tenant.version, 1);
    }

    #[test]
    fn explicit_limits_and_region_are_kept() {
        let tenant: TenantModel = TenantCreateModel {
            region: Some("eu-west".into()),
            limits: Some(TenantLimits {
                max_realms: Some(100),
                ..Default::default()
            }),
            ..create()
        }
        .into();
        assert_eq!(tenant.region.as_deref(), Some("eu-west"));
        assert!(!tenant.is_unlimited());
        assert_eq!(tenant.limits.unwrap().max_realms, Some(100));
    }

    /// Only `Active` is reachable — a state added later is refused until it is
    /// decided, rather than inheriting whatever `is_active` last matched.
    #[test]
    fn only_the_active_state_is_reachable() {
        for state in TenantState::ALL {
            let tenant = TenantModel {
                state: *state,
                ..create().into()
            };
            assert_eq!(tenant.is_active(), *state == TenantState::Active);
        }
    }
}
