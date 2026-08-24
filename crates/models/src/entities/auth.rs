use serde::{Deserialize, Serialize};

use crate::auditable::AuditableModel;
use crate::entities::attributes::AttributesMap;
use crate::entities::user::RequiredAction;
use crate::str_enum::str_enum;

/// A required action as a realm registers it: which action, who implements it,
/// and whether it is imposed on new users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredActionModel {
    pub action_id: String,
    pub realm_id: String,
    /// The provider that shows the screen.
    pub provider_id: String,
    pub action: RequiredAction,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
    /// Whether a new user gets it without anyone adding it.
    pub default_action: Option<bool>,
    /// Whether it is asked once and then cleared, rather than standing.
    pub on_time_action: Option<bool>,
    pub priority: Option<i32>,
    pub metadata: AuditableModel,
}

/// The create and update payload for a required action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredActionMutationModel {
    pub provider_id: String,
    pub action: RequiredAction,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
    pub default_action: Option<bool>,
    pub on_time_action: Option<bool>,
    pub priority: Option<i32>,
}

impl RequiredActionMutationModel {
    pub fn into_model(
        self,
        action_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> RequiredActionModel {
        RequiredActionModel {
            action_id,
            realm_id,
            provider_id: self.provider_id,
            action: self.action,
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            enabled: self.enabled,
            default_action: self.default_action,
            on_time_action: self.on_time_action,
            priority: self.priority,
            metadata,
        }
    }
}

/// A named authentication flow: an ordered set of steps a login runs through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFlowModel {
    pub flow_id: String,
    pub realm_id: String,
    pub alias: String,
    pub provider_id: String,
    pub description: String,
    /// Whether a login can start here, as opposed to it being a sub-flow that
    /// only runs when something else calls it.
    pub top_level: Option<bool>,
    /// Whether the realm was created with it. Built-in flows are the ones an
    /// admin can break by deleting.
    pub built_in: Option<bool>,
    pub metadata: AuditableModel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFlowMutationModel {
    pub alias: String,
    pub provider_id: String,
    pub description: String,
    pub top_level: Option<bool>,
    pub built_in: Option<bool>,
}

impl AuthenticationFlowMutationModel {
    pub fn into_model(
        self,
        flow_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> AuthenticationFlowModel {
        AuthenticationFlowModel {
            flow_id,
            realm_id,
            alias: self.alias,
            provider_id: self.provider_id,
            description: self.description,
            top_level: self.top_level,
            built_in: self.built_in,
            metadata,
        }
    }
}

str_enum! {
    #[postgres(name = "authenticator_requirement")]
    /// How much a step counts towards the flow succeeding.
    ///
    /// There is no conditional requirement. A step that runs only sometimes has
    /// something it is conditional on, and a requirement has nowhere to put it:
    /// the value would name a state whose data lives nowhere, which is the one
    /// shape this schema refuses everywhere else. A step that decides whether
    /// the rest of its flow runs is an ordinary step whose authenticator is that
    /// decision.
    pub enum AuthenticatorRequirement {
        /// Must succeed. The flow fails without it.
        Required => "required",
        /// One of a set, any of which satisfies the flow.
        Alternative => "alternative",
        /// Never runs.
        Disabled => "disabled",
    }
}

impl AuthenticatorRequirement {
    /// Whether the step runs at all.
    ///
    /// The one derived reading worth a name, because "not disabled" is a
    /// question the engine asks about every step before it asks anything else.
    /// The rest is a match on the value, which the compiler checks and a
    /// predicate per variant does not.
    pub fn is_enabled(self) -> bool {
        self != Self::Disabled
    }
}

/// What a step actually runs.
///
/// One arm per kind, because what each needs is disjoint: an authenticator has
/// a name and may have settings, a nested flow has the identifier of the flow
/// to run and no settings of its own. A shape carrying a flag beside all three
/// gives every step two fields that mean nothing for it, and leaves the pairing
/// to whoever writes the row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecutionStep {
    /// A single authenticator, with the settings it reads when it runs.
    Authenticator {
        authenticator: String,
        config_id: Option<String>,
    },
    /// Another flow, run as one step of this one.
    SubFlow { flow_id: String },
}

impl ExecutionStep {
    /// The flow this step runs, if it runs a flow.
    pub fn sub_flow(&self) -> Option<&str> {
        match self {
            Self::SubFlow { flow_id } => Some(flow_id),
            Self::Authenticator { .. } => None,
        }
    }
}

/// One step of a flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExecutionModel {
    pub execution_id: String,
    pub realm_id: String,
    pub alias: String,
    /// The flow this step belongs to.
    pub flow_id: String,
    /// Lower runs first, and no two steps of one flow share a position.
    pub priority: i32,
    pub step: ExecutionStep,
    pub requirement: AuthenticatorRequirement,
    pub metadata: AuditableModel,
}

impl AuthenticationExecutionModel {
    pub fn is_enabled(&self) -> bool {
        self.requirement.is_enabled()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExecutionMutationModel {
    pub alias: String,
    pub flow_id: String,
    pub priority: i32,
    pub step: ExecutionStep,
    pub requirement: AuthenticatorRequirement,
}

impl AuthenticationExecutionMutationModel {
    pub fn into_model(
        self,
        execution_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> AuthenticationExecutionModel {
        AuthenticationExecutionModel {
            execution_id,
            realm_id,
            alias: self.alias,
            flow_id: self.flow_id,
            priority: self.priority,
            step: self.step,
            requirement: self.requirement,
            metadata,
        }
    }
}

/// Settings an authenticator reads when it runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorConfigModel {
    pub config_id: String,
    pub realm_id: String,
    pub alias: String,
    pub configs: Option<AttributesMap>,
    pub metadata: AuditableModel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorConfigMutationModel {
    pub alias: String,
    pub configs: Option<AttributesMap>,
}

impl AuthenticatorConfigMutationModel {
    pub fn into_model(
        self,
        config_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> AuthenticatorConfigModel {
        AuthenticatorConfigModel {
            config_id,
            realm_id,
            alias: self.alias,
            configs: self.configs,
            metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;

    fn metadata() -> AuditableModel {
        AuditableModel::from_creator("acme".into(), "root".into())
    }

    #[test]
    fn the_requirements_agree_with_their_own_spelling() {
        assert_eq!(AuthenticatorRequirement::ALL.len(), 3);
        assert_eq!(AuthenticatorRequirement::Required.as_str(), "required");
        assert_eq!(
            AuthenticatorRequirement::Alternative.as_str(),
            "alternative"
        );
        assert_eq!(AuthenticatorRequirement::Disabled.as_str(), "disabled");
        assert_round_trips(AuthenticatorRequirement::ALL);
    }

    /// Exactly one requirement stops a step from running, and the other three
    /// all run. A predicate that named the wrong side would skip a required
    /// step or run a disabled one.
    #[test]
    fn only_the_disabled_requirement_stops_a_step_running() {
        for requirement in AuthenticatorRequirement::ALL {
            assert_eq!(
                requirement.is_enabled(),
                *requirement != AuthenticatorRequirement::Disabled,
                "{requirement}"
            );
        }
        assert_eq!(
            AuthenticatorRequirement::ALL
                .iter()
                .filter(|r| !r.is_enabled())
                .count(),
            1
        );
    }

    /// Every mutation payload takes its identifiers and its audit record from
    /// the caller, so none of them can name the realm it lands in.
    #[test]
    fn a_mutation_takes_its_identifiers_from_the_caller() {
        let action = RequiredActionMutationModel {
            provider_id: "verify-email-provider".into(),
            action: RequiredAction::VerifyEmail,
            name: "Verify Email".into(),
            display_name: "Verify Email".into(),
            description: String::new(),
            enabled: Some(true),
            default_action: Some(true),
            on_time_action: Some(true),
            priority: Some(10),
        }
        .into_model("action-1".into(), "realm-1".into(), metadata());
        assert_eq!(action.action_id, "action-1");
        assert_eq!(action.realm_id, "realm-1");
        assert_eq!(action.action, RequiredAction::VerifyEmail);
        assert_eq!(action.metadata.tenant, "acme");

        let flow = AuthenticationFlowMutationModel {
            alias: "browser".into(),
            provider_id: "basic-flow".into(),
            description: String::new(),
            top_level: Some(true),
            built_in: Some(true),
        }
        .into_model("flow-1".into(), "realm-1".into(), metadata());
        assert_eq!(flow.flow_id, "flow-1");
        assert_eq!(flow.realm_id, "realm-1");
        assert_eq!(flow.alias, "browser");

        let config = AuthenticatorConfigMutationModel {
            alias: "otp-config".into(),
            configs: None,
        }
        .into_model("config-1".into(), "realm-1".into(), metadata());
        assert_eq!(config.config_id, "config-1");
        assert_eq!(config.realm_id, "realm-1");
        assert_eq!(config.alias, "otp-config");
    }

    /// A step that runs a flow answers with the flow it runs, and one that runs
    /// an authenticator answers with nothing. Whoever walks the tree asks this
    /// one question, and an arm that answered wrongly would either descend into
    /// an authenticator or stop at a nested flow.
    #[test]
    fn only_a_nested_step_names_a_flow_to_run() {
        let nested = ExecutionStep::SubFlow {
            flow_id: "flow-2".into(),
        };
        assert_eq!(nested.sub_flow(), Some("flow-2"));

        let leaf = ExecutionStep::Authenticator {
            authenticator: "auth-otp".into(),
            config_id: None,
        };
        assert_eq!(leaf.sub_flow(), None);
    }

    /// The two kinds are told apart on the wire by a tag, not by which fields
    /// happen to be present.
    #[test]
    fn a_step_names_its_kind_on_the_wire() {
        let nested = serde_json::to_value(ExecutionStep::SubFlow {
            flow_id: "flow-2".into(),
        })
        .unwrap();
        assert_eq!(nested["kind"], "sub_flow");
        assert_eq!(nested["flow_id"], "flow-2");
        assert!(nested.get("authenticator").is_none());

        let leaf = serde_json::to_value(ExecutionStep::Authenticator {
            authenticator: "auth-otp".into(),
            config_id: None,
        })
        .unwrap();
        assert_eq!(leaf["kind"], "authenticator");
        assert_eq!(
            serde_json::from_value::<ExecutionStep>(leaf).unwrap(),
            ExecutionStep::Authenticator {
                authenticator: "auth-otp".into(),
                config_id: None,
            }
        );
    }

    /// A step keeps the flow it names and the requirement it was given, and
    /// reads its own enablement from that requirement.
    #[test]
    fn a_step_keeps_its_flow_and_reads_its_requirement() {
        let execution = AuthenticationExecutionMutationModel {
            alias: "otp".into(),
            flow_id: "flow-1".into(),
            priority: 20,
            step: ExecutionStep::Authenticator {
                authenticator: "auth-otp".into(),
                config_id: Some("config-1".into()),
            },
            requirement: AuthenticatorRequirement::Alternative,
        }
        .into_model("exec-1".into(), "realm-1".into(), metadata());

        assert_eq!(execution.execution_id, "exec-1");
        assert_eq!(execution.realm_id, "realm-1");
        assert_eq!(execution.flow_id, "flow-1");
        assert_eq!(execution.priority, 20);
        assert!(execution.is_enabled());
        assert_eq!(
            execution.step.sub_flow(),
            None,
            "a step running an authenticator answered with a flow to run"
        );

        let disabled = AuthenticationExecutionModel {
            requirement: AuthenticatorRequirement::Disabled,
            ..execution
        };
        assert!(!disabled.is_enabled());
    }
}
