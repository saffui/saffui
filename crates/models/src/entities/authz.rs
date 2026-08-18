//! Who may do what: the capability vocabulary, roles, groups, and the identity
//! providers a realm federates to.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::auditable::AuditableModel;
use crate::entities::attributes::AttributesMap;
use crate::str_enum::str_enum;

str_enum! {
    /// Every capability the admin plane recognises.
    ///
    /// One list, shared by the two halves that have to agree about it: whatever
    /// derives a capability from a request, and whatever decides if the caller
    /// holds it. Two vocabularies means one side deriving a name the other never
    /// heard of, which is a silent denial, or the other accepting whatever it is
    /// sent, which is no vocabulary at all.
    ///
    /// Closed, and a type rather than a string, because this is what a role
    /// grants. A capability nobody declared cannot be stored on a role, so
    /// deny-by-default holds without anything having to check a list first.
    ///
    /// The shape is `family:verb`, with the verb last. A few operations stand
    /// alone because they are not comparable to a verb on a family: importing a
    /// realm writes an entire realm, exporting one reads every user in it, and
    /// rotating a signing key changes what tokens the realm can issue. Granting
    /// "may administer this realm" must not quietly grant those.
    pub enum AdminAction {
        RealmRead => "realm:read",
        RealmWrite => "realm:write",
        RealmCreate => "realm:create",
        RealmList => "realm:list",
        RealmImport => "realm:import",
        RealmExport => "realm:export",
        RealmKeysRead => "realm:keys:read",
        RealmKeysWrite => "realm:keys:write",
        UserRead => "user:read",
        UserWrite => "user:write",
        RoleRead => "role:read",
        RoleWrite => "role:write",
        GroupRead => "group:read",
        GroupWrite => "group:write",
        ClientRead => "client:read",
        ClientWrite => "client:write",
        IdpRead => "idp:read",
        IdpWrite => "idp:write",
        UmaRead => "uma:read",
        UmaWrite => "uma:write",
        AuthFlowRead => "auth-flow:read",
        AuthFlowWrite => "auth-flow:write",
        RequiredActionRead => "required-action:read",
        RequiredActionWrite => "required-action:write",
        AuthzDecisionRead => "authz-decision:read",
        AuthzDecisionWrite => "authz-decision:write",
        RebacRead => "rebac:read",
        RebacWrite => "rebac:write",
        ThemeRead => "theme:read",
        ThemeWrite => "theme:write",
        ConsentRead => "consent:read",
        ConsentFullRead => "consent:full:read",
        OrgRead => "org:read",
        OrgWrite => "org:write",
        FeatureRead => "feature:read",
    }
}

impl AdminAction {
    /// Everything before the last colon.
    ///
    /// Read back from the spelling rather than kept in a second table, so a
    /// capability added to the one table cannot be missing from here.
    pub fn family(self) -> &'static str {
        self.as_str()
            .rsplit_once(':')
            .expect("every capability names a family and a verb")
            .0
    }

    /// The verb: what the capability does to its family.
    pub fn verb(self) -> &'static str {
        self.as_str()
            .rsplit_once(':')
            .expect("every capability names a family and a verb")
            .1
    }

    /// Whether an organization-bound principal may hold this.
    ///
    /// Read from the family rather than from a prefix test on a raw string. A
    /// prefix test answers for anything shaped like a capability, including
    /// strings nobody declared, so it is not a gate on its own.
    pub fn is_org_scoped(self) -> bool {
        self.family() == "org"
    }
}

/// A named grant. Realm roles apply everywhere in the realm, client roles only
/// where their client is the audience.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleModel {
    pub role_id: String,
    pub realm_id: String,
    pub name: String,
    pub description: String,
    pub display_name: String,
    /// The client that owns it, or none when the realm does. Named rather than
    /// flagged, so entitlements are not rebuilt by matching role names.
    pub client_id: Option<String>,
    /// Admin plane capabilities this role grants, typed so an undeclared one
    /// cannot be written. None and an empty list both grant nothing.
    pub admin_permissions: Option<Vec<AdminAction>>,
    pub metadata: AuditableModel,
}

impl RoleModel {
    /// Whether a client owns it, which is the same question as whether one is
    /// named. Derived rather than stored beside the name, so the two cannot
    /// disagree.
    pub fn is_client_role(&self) -> bool {
        self.client_id.is_some()
    }
}

/// The create and update payload for a role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleMutationModel {
    pub name: String,
    pub description: String,
    pub display_name: String,
    pub client_id: Option<String>,
    pub admin_permissions: Option<Vec<AdminAction>>,
}

impl RoleMutationModel {
    pub fn into_model(
        self,
        role_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> RoleModel {
        RoleModel {
            role_id,
            realm_id,
            name: self.name,
            description: self.description,
            display_name: self.display_name,
            client_id: self.client_id,
            admin_permissions: self.admin_permissions,
            metadata,
        }
    }
}

/// A set of users that can be granted roles together.
///
/// The roles attached to it are not a field. A group is read wherever a user's
/// grants are assembled, and a join per group is paid there; whoever needs the
/// attachment reads the attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupModel {
    pub group_id: String,
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    /// Whether new users join it without anyone adding them.
    pub is_default: bool,
    pub metadata: AuditableModel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMutationModel {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub is_default: bool,
}

impl GroupMutationModel {
    /// Build a group. The identifier comes from the caller, like every other
    /// one here: a model that minted its own would be the only place in the
    /// crate that generates randomness, and the caller is where an identifier
    /// has to be reserved anyway.
    pub fn into_model(
        self,
        group_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> GroupModel {
        GroupModel {
            group_id,
            realm_id,
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            is_default: self.is_default,
            metadata,
        }
    }
}

/// An external identity provider a realm accepts logins from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProviderModel {
    pub internal_id: String,
    pub realm_id: String,
    /// The provider's own identifier, as it appears in a login URL.
    pub provider_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
    /// Whether an email address this provider asserts is taken as verified.
    pub trust_email: Option<bool>,
    pub configs: Option<AttributesMap>,
    pub metadata: AuditableModel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProviderMutationModel {
    pub provider_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
    pub trust_email: Option<bool>,
    pub configs: Option<AttributesMap>,
}

impl IdentityProviderMutationModel {
    pub fn into_model(
        self,
        internal_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> IdentityProviderModel {
        IdentityProviderModel {
            internal_id,
            realm_id,
            provider_id: self.provider_id,
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            enabled: self.enabled,
            trust_email: self.trust_email,
            configs: self.configs,
            metadata,
        }
    }
}

// Resource servers, and the policies that guard what they hold.

str_enum! {
    #[postgres(name = "policyenforcementmodeenum")]
    /// What a resource server does with a decision.
    pub enum PolicyEnforcementMode {
        /// Refuse what the policies do not permit.
        Enforcing => "enforcing",
        /// Record the decision and let the request through. For rolling a
        /// policy out before it is trusted to deny.
        Permissive => "permissive",
        /// Evaluate nothing.
        Disabled => "disabled",
    }
}

str_enum! {
    #[postgres(name = "decisionstrategyenum")]
    /// How several policies combine into one answer.
    pub enum DecisionStrategy {
        /// One permit is enough.
        Affirmative => "affirmative",
        /// Every policy must permit.
        Unanimous => "unanimous",
        /// More permits than denies.
        Consensus => "consensus",
    }
}

str_enum! {
    #[postgres(name = "decisionlogicenum")]
    /// Whether a policy grants on a match or on the absence of one.
    pub enum DecisionLogic {
        Positive => "positive",
        /// Inverted: grant when the policy does not match.
        Negative => "negative",
    }
}

str_enum! {
    #[postgres(name = "policytypeenum")]
    /// What a policy decides on.
    pub enum PolicyType {
        Role => "role",
        Group => "group",
        User => "user",
        Client => "client",
        ClientScope => "client-scope",
        Time => "time",
        Regex => "regex",
        Script => "script",
        Aggregated => "aggregated",
        ScopePermission => "scope-permission",
        ResourcePermission => "resource-permission",
    }
}

/// A protected application and the settings its decisions are made under.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceServerModel {
    pub server_id: String,
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enforcement_mode: PolicyEnforcementMode,
    pub decision_strategy: DecisionStrategy,
    pub remote_resource_management: Option<bool>,
    pub user_managed_access_enabled: Option<bool>,
    pub configs: Option<AttributesMap>,
    pub metadata: AuditableModel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceServerMutationModel {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enforcement_mode: PolicyEnforcementMode,
    pub decision_strategy: DecisionStrategy,
    pub remote_resource_management: Option<bool>,
    pub user_managed_access_enabled: Option<bool>,
    pub configs: Option<AttributesMap>,
}

impl ResourceServerMutationModel {
    pub fn into_model(
        self,
        server_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> ResourceServerModel {
        ResourceServerModel {
            server_id,
            realm_id,
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            enforcement_mode: self.enforcement_mode,
            decision_strategy: self.decision_strategy,
            remote_resource_management: self.remote_resource_management,
            user_managed_access_enabled: self.user_managed_access_enabled,
            configs: self.configs,
            metadata,
        }
    }
}

/// Something a resource server protects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceModel {
    pub resource_id: String,
    pub server_id: String,
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub resource_uris: Vec<String>,
    pub resource_type: String,
    pub resource_owner: String,
    pub user_managed_access_enabled: Option<bool>,
    pub configs: Option<AttributesMap>,
    /// The verbs meaningful on this resource. None is not loaded, empty is declares
    /// none, and neither may read as the other.
    pub scopes: Option<Vec<String>>,
    pub metadata: AuditableModel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMutationModel {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub resource_uris: Vec<String>,
    pub resource_type: String,
    pub resource_owner: String,
    pub user_managed_access_enabled: Option<bool>,
    pub configs: Option<AttributesMap>,
}

impl ResourceMutationModel {
    pub fn into_model(
        self,
        resource_id: String,
        server_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> ResourceModel {
        ResourceModel {
            resource_id,
            server_id,
            realm_id,
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            resource_uris: self.resource_uris,
            resource_type: self.resource_type,
            resource_owner: self.resource_owner,
            user_managed_access_enabled: self.user_managed_access_enabled,
            configs: self.configs,
            // A payload never carries scope bindings. They are attached through
            // their own operation, so creating a resource cannot quietly widen
            // what is meaningful on it.
            scopes: None,
            metadata,
        }
    }
}

/// A verb that is meaningful on a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeModel {
    pub scope_id: String,
    pub server_id: String,
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub metadata: AuditableModel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeMutationModel {
    pub name: String,
    pub display_name: String,
    pub description: String,
}

impl ScopeMutationModel {
    pub fn into_model(
        self,
        scope_id: String,
        server_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> ScopeModel {
        ScopeModel {
            scope_id,
            server_id,
            realm_id,
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            metadata,
        }
    }
}

/// When a time policy grants.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    pub not_before: Option<u64>,
    pub not_on_or_after: Option<u64>,
    pub year: Option<u64>,
    pub year_end: Option<u64>,
    pub month: Option<u64>,
    pub month_end: Option<u64>,
    pub day_of_month: Option<u64>,
    pub day_of_month_end: Option<u64>,
    pub hour: Option<u64>,
    pub hour_end: Option<u64>,
    pub minute: Option<u64>,
    pub minute_end: Option<u64>,
}

/// What a policy actually decides on.
///
/// One arm per kind, carrying exactly that kind's payload. The shape this
/// replaces was a single record with a field per kind, all optional, so a regex
/// policy carried eleven fields that meant nothing for it and a reader had to
/// know which one to look at from a separate discriminant that could disagree
/// with them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "policy_type")]
pub enum PolicyRule {
    #[serde(rename = "role")]
    Role { roles: Vec<String> },
    #[serde(rename = "group")]
    Group {
        group_claim: String,
        groups: Vec<String>,
    },
    #[serde(rename = "user")]
    User { users: Vec<String> },
    #[serde(rename = "client")]
    Client { clients: Vec<String> },
    #[serde(rename = "client-scope")]
    ClientScope { client_scopes: Vec<String> },
    #[serde(rename = "time")]
    Time(TimeWindow),
    #[serde(rename = "regex")]
    Regex {
        target_claim: String,
        target_regex: String,
    },
    #[serde(rename = "script")]
    Script { script: String },
    /// Decides from the policies it aggregates, which are the common `policies`
    /// list, so it carries nothing of its own.
    #[serde(rename = "aggregated")]
    Aggregated,
    #[serde(rename = "scope-permission")]
    ScopePermission { resource_type: String },
    #[serde(rename = "resource-permission")]
    ResourcePermission { resource_type: String },
}

impl PolicyRule {
    /// The kind, read from the rule rather than stored beside it.
    pub fn policy_type(&self) -> PolicyType {
        match self {
            Self::Role { .. } => PolicyType::Role,
            Self::Group { .. } => PolicyType::Group,
            Self::User { .. } => PolicyType::User,
            Self::Client { .. } => PolicyType::Client,
            Self::ClientScope { .. } => PolicyType::ClientScope,
            Self::Time(_) => PolicyType::Time,
            Self::Regex { .. } => PolicyType::Regex,
            Self::Script { .. } => PolicyType::Script,
            Self::Aggregated => PolicyType::Aggregated,
            Self::ScopePermission { .. } => PolicyType::ScopePermission,
            Self::ResourcePermission { .. } => PolicyType::ResourcePermission,
        }
    }
}

/// What every policy carries, whatever it decides on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyTerms {
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategy,
    pub logic: DecisionLogic,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    /// Policies this one is built from, by identifier.
    pub policies: Vec<String>,
    /// Resources it applies to, by identifier.
    pub resources: Vec<String>,
    /// Scopes it applies to, by identifier.
    pub scopes: Vec<String>,
    #[serde(flatten)]
    pub rule: PolicyRule,
}

impl PolicyTerms {
    pub fn policy_type(&self) -> PolicyType {
        self.rule.policy_type()
    }
}

/// A stored policy.
///
/// Comparing two is comparing their [`PolicyTerms`], which is derived and covers
/// the rule. The hand-written comparison this replaces sat on the whole model,
/// looked at the identifiers and the name, and deliberately at none of the
/// payload, so two policies matching different regular expressions compared
/// equal and anything asking whether one had changed answered no.
///
/// The audit record is not part of that question: the same rule written by two
/// admins is the same rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyModel {
    pub policy_id: String,
    pub server_id: String,
    pub realm_id: String,
    #[serde(flatten)]
    pub terms: PolicyTerms,
    pub metadata: AuditableModel,
}

impl PolicyModel {
    pub fn policy_type(&self) -> PolicyType {
        self.terms.policy_type()
    }
}

impl PolicyTerms {
    /// Build a stored policy from the terms, with identifiers from the caller.
    pub fn into_model(
        self,
        policy_id: String,
        server_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> PolicyModel {
        PolicyModel {
            policy_id,
            server_id,
            realm_id,
            terms: self,
            metadata,
        }
    }
}

str_enum! {
    /// What a decision point answered.
    pub enum Decision {
        Permit => "permit",
        Deny => "deny",
    }
}

/// One recorded decision.
///
/// The flat columns are what a query filters on; `detail` is the request as it
/// was made, so a decision can be replayed against the policies as they stand
/// now and the two answers compared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzDecisionRecord {
    pub decision_id: String,
    pub tenant: String,
    pub realm_id: String,
    pub subject_type: String,
    pub subject_id: String,
    pub resource_kind: String,
    pub resource_ref: Option<String>,
    pub action: String,
    pub decision: Decision,
    /// The replay payload.
    pub detail: serde_json::Value,
    pub duration_us: i64,
    pub trace_id: Option<String>,
    /// Epoch milliseconds. `None` on a record not yet persisted, since the
    /// column default stamps it.
    pub occurred_at_millis: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;
    use std::str::FromStr;

    fn metadata() -> AuditableModel {
        AuditableModel::from_creator("acme".into(), "root".into())
    }

    #[test]
    fn the_vocabulary_agrees_with_its_own_spelling() {
        assert_eq!(AdminAction::ALL.len(), 35);
        assert_round_trips(AdminAction::ALL);
    }

    /// Every capability names a family and a verb, with the verb last. A reader
    /// of an audit line should be able to tell what was exercised without
    /// consulting a table.
    #[test]
    fn every_capability_names_a_family_and_a_verb() {
        for action in AdminAction::ALL {
            assert!(!action.family().is_empty(), "{action} has no family");
            assert!(
                matches!(
                    action.verb(),
                    "read" | "write" | "create" | "list" | "import" | "export"
                ),
                "{action} ends in an unexpected verb"
            );
        }

        assert_eq!(AdminAction::RealmKeysWrite.family(), "realm:keys");
        assert_eq!(AdminAction::RealmKeysWrite.verb(), "write");
        assert_eq!(AdminAction::ConsentFullRead.family(), "consent:full");
        assert_eq!(AdminAction::AuthFlowRead.family(), "auth-flow");
    }

    /// The dangerous operations are capabilities of their own, so granting a
    /// realm write cannot carry them by implication.
    #[test]
    fn the_powerful_operations_stand_alone() {
        for standalone in [
            AdminAction::RealmImport,
            AdminAction::RealmExport,
            AdminAction::RealmKeysWrite,
        ] {
            assert_ne!(standalone, AdminAction::RealmWrite);
            assert_ne!(standalone.as_str(), AdminAction::RealmWrite.as_str());
        }

        assert_ne!(
            AdminAction::ConsentFullRead,
            AdminAction::ConsentRead,
            "the whole receipt is not the list"
        );
    }

    /// A capability nobody declared cannot be named. This is what keeps a role
    /// from granting something the plane has never heard of.
    #[test]
    fn an_undeclared_capability_cannot_be_named() {
        for undeclared in [
            "admin:access",
            "user:delete",
            "",
            "realm:*",
            "REALM:READ",
            "user:read ",
        ] {
            assert!(
                AdminAction::from_str(undeclared).is_err(),
                "{undeclared:?} must not parse"
            );
        }
    }

    /// Exactly the organization capabilities answer to an organization bound
    /// principal, and nothing realm wide does.
    #[test]
    fn only_organization_capabilities_are_organization_scoped() {
        let scoped: Vec<&AdminAction> = AdminAction::ALL
            .iter()
            .filter(|action| action.is_org_scoped())
            .collect();
        assert_eq!(
            scoped,
            vec![&AdminAction::OrgRead, &AdminAction::OrgWrite],
            "the organization set is exactly these two"
        );

        for realm_wide in [
            AdminAction::UserRead,
            AdminAction::RealmWrite,
            AdminAction::ClientWrite,
            AdminAction::RealmExport,
        ] {
            assert!(!realm_wide.is_org_scoped(), "{realm_wide}");
        }
    }

    /// A role's grant is typed, so an undeclared capability does not survive the
    /// wire and cannot reach the decision that reads it.
    #[test]
    fn a_role_cannot_carry_an_undeclared_capability() {
        let role = RoleMutationModel {
            name: "auditor".into(),
            description: "Reads the ledger".into(),
            display_name: "Auditor".into(),
            client_id: None,
            admin_permissions: Some(vec![AdminAction::ConsentRead, AdminAction::UserRead]),
        }
        .into_model("role-1".into(), "realm-1".into(), metadata());

        assert_eq!(role.role_id, "role-1");
        assert_eq!(role.realm_id, "realm-1");
        assert_eq!(role.metadata.tenant, "acme");
        assert_eq!(
            role.admin_permissions,
            Some(vec![AdminAction::ConsentRead, AdminAction::UserRead])
        );

        let encoded = serde_json::to_string(&role).unwrap();
        assert!(encoded.contains("consent:read"), "{encoded}");

        let smuggled = encoded.replace("consent:read", "realm:*");
        assert!(
            serde_json::from_str::<RoleModel>(&smuggled).is_err(),
            "a capability nobody declared must not decode onto a role"
        );
    }

    /// Granting nothing is what an absent list means, and it is the same answer
    /// as an empty one.
    #[test]
    fn a_role_with_no_capabilities_grants_nothing() {
        let role = RoleMutationModel {
            name: "member".into(),
            description: String::new(),
            display_name: "Member".into(),
            client_id: None,
            admin_permissions: None,
        }
        .into_model("role-2".into(), "realm-1".into(), metadata());
        assert_eq!(role.admin_permissions, None);

        let empty = RoleModel {
            admin_permissions: Some(Vec::new()),
            ..role
        };
        assert_eq!(
            empty.admin_permissions.as_deref().unwrap_or_default().len(),
            0
        );
    }

    /// A group takes its identifier from the caller like everything else, rather
    /// than minting one.
    #[test]
    fn a_group_takes_its_identifier_from_the_caller() {
        let group = GroupMutationModel {
            name: "engineering".into(),
            display_name: "Engineering".into(),
            description: String::new(),
            is_default: false,
        }
        .into_model("group-1".into(), "realm-1".into(), metadata());

        assert_eq!(group.group_id, "group-1");
        assert_eq!(group.realm_id, "realm-1");
        assert!(!group.is_default);
        assert_eq!(group.metadata.tenant, "acme");
    }

    fn terms(rule: PolicyRule) -> PolicyTerms {
        PolicyTerms {
            name: "business-hours".into(),
            description: String::new(),
            decision: DecisionStrategy::Unanimous,
            logic: DecisionLogic::Positive,
            policy_owner: "ada".into(),
            configs: None,
            policies: Vec::new(),
            resources: vec!["resource-1".into()],
            scopes: vec!["scope-1".into()],
            rule,
        }
    }

    #[test]
    fn the_authorization_catalogues_agree_with_their_own_spelling() {
        assert_eq!(PolicyEnforcementMode::ALL.len(), 3);
        assert_eq!(DecisionStrategy::ALL.len(), 3);
        assert_eq!(DecisionLogic::ALL.len(), 2);
        assert_eq!(PolicyType::ALL.len(), 11);
        assert_eq!(Decision::ALL.len(), 2);
        assert_round_trips(PolicyEnforcementMode::ALL);
        assert_round_trips(DecisionStrategy::ALL);
        assert_round_trips(DecisionLogic::ALL);
        assert_round_trips(PolicyType::ALL);
        assert_round_trips(Decision::ALL);
    }

    /// Every rule names its kind, every kind is named by a rule, and the tag on
    /// the wire is the kind's own spelling. Two tables hold that literal, so a
    /// rename in one is a failure here rather than a policy that decodes as
    /// another kind.
    #[test]
    fn every_rule_names_its_kind_and_the_wire_agrees() {
        let rules = [
            PolicyRule::Role { roles: Vec::new() },
            PolicyRule::Group {
                group_claim: "groups".into(),
                groups: Vec::new(),
            },
            PolicyRule::User { users: Vec::new() },
            PolicyRule::Client {
                clients: Vec::new(),
            },
            PolicyRule::ClientScope {
                client_scopes: Vec::new(),
            },
            PolicyRule::Time(TimeWindow::default()),
            PolicyRule::Regex {
                target_claim: "email".into(),
                target_regex: ".*".into(),
            },
            PolicyRule::Script {
                script: "return true".into(),
            },
            PolicyRule::Aggregated,
            PolicyRule::ScopePermission {
                resource_type: "urn:app".into(),
            },
            PolicyRule::ResourcePermission {
                resource_type: "urn:app".into(),
            },
        ];

        assert_eq!(
            rules.len(),
            PolicyType::ALL.len(),
            "every kind has a rule that produces it"
        );

        let mut seen: Vec<PolicyType> = Vec::new();
        for rule in &rules {
            let kind = rule.policy_type();
            assert!(!seen.contains(&kind), "{kind} is produced by two rules");
            seen.push(kind);

            let encoded = serde_json::to_value(rule).unwrap();
            assert_eq!(
                encoded.get("policy_type").and_then(|v| v.as_str()),
                Some(kind.as_str()),
                "the tag and the kind disagree for {kind}"
            );
            assert_eq!(
                &serde_json::from_value::<PolicyRule>(encoded).unwrap(),
                rule
            );
        }
    }

    /// A rule carries only its own payload, so a stored policy of one kind
    /// cannot come back holding another kind's.
    #[test]
    fn a_rule_carries_nothing_that_belongs_to_another_kind() {
        let regex = serde_json::to_value(&PolicyRule::Regex {
            target_claim: "email".into(),
            target_regex: "@example[.]test$".into(),
        })
        .unwrap();
        assert!(regex.get("groups").is_none());
        assert!(regex.get("script").is_none());
        assert!(regex.get("roles").is_none());

        assert!(
            serde_json::from_str::<PolicyRule>(r#"{"policy_type":"regex","target_claim":"email"}"#)
                .is_err(),
            "half a regex rule is not a rule"
        );
        assert!(serde_json::from_str::<PolicyRule>(r#"{"policy_type":"nonexistent"}"#).is_err());
    }

    /// A policy is one flat document. The rule's tag sits beside the common
    /// terms rather than under a wrapper, so a stored policy names its kind
    /// where a reader of the row looks for it.
    #[test]
    fn a_policy_is_one_flat_document() {
        let policy = terms(PolicyRule::Regex {
            target_claim: "email".into(),
            target_regex: "@example[.]test$".into(),
        });

        let encoded = serde_json::to_value(&policy).unwrap();
        assert_eq!(
            encoded.get("policy_type").and_then(|v| v.as_str()),
            Some("regex"),
            "the kind is at the top level: {encoded}"
        );
        assert_eq!(
            encoded.get("target_regex").and_then(|v| v.as_str()),
            Some("@example[.]test$")
        );
        assert!(
            encoded.get("rule").is_none(),
            "the rule is not wrapped: {encoded}"
        );
        assert_eq!(
            encoded.get("name").and_then(|v| v.as_str()),
            Some("business-hours")
        );

        assert_eq!(
            serde_json::from_value::<PolicyTerms>(encoded).unwrap(),
            policy
        );
    }

    /// Two policies differ when their rules differ. The comparison this replaces
    /// looked at none of the payload, so a changed regular expression read as no
    /// change at all.
    #[test]
    fn two_policies_differ_when_their_rules_differ() {
        let one = terms(PolicyRule::Regex {
            target_claim: "email".into(),
            target_regex: "@example[.]test$".into(),
        });
        let other = terms(PolicyRule::Regex {
            target_claim: "email".into(),
            target_regex: ".*".into(),
        });

        assert_ne!(one, other, "a different expression is a different policy");
        assert_eq!(one, one.clone());

        let another_kind = terms(PolicyRule::Aggregated);
        assert_ne!(one, another_kind);
    }

    /// A policy takes its identifiers from the caller, and its kind is read from
    /// the rule rather than carried alongside it.
    #[test]
    fn a_policy_reads_its_kind_from_its_rule() {
        let policy = terms(PolicyRule::Time(TimeWindow {
            hour: Some(9),
            hour_end: Some(18),
            ..TimeWindow::default()
        }))
        .into_model(
            "policy-1".into(),
            "server-1".into(),
            "realm-1".into(),
            metadata(),
        );

        assert_eq!(policy.policy_id, "policy-1");
        assert_eq!(policy.server_id, "server-1");
        assert_eq!(policy.realm_id, "realm-1");
        assert_eq!(policy.policy_type(), PolicyType::Time);
        assert_eq!(policy.metadata.tenant, "acme");
    }

    /// A resource declaring no scopes is a different answer from one whose
    /// scopes were not loaded, and a payload never attaches any.
    #[test]
    fn a_resources_scopes_distinguish_absent_from_empty() {
        let resource = ResourceMutationModel {
            name: "invoice".into(),
            display_name: "Invoice".into(),
            description: String::new(),
            resource_uris: vec!["/invoices/*".into()],
            resource_type: "urn:app:invoice".into(),
            resource_owner: "app".into(),
            user_managed_access_enabled: Some(false),
            configs: None,
        }
        .into_model(
            "resource-1".into(),
            "server-1".into(),
            "realm-1".into(),
            metadata(),
        );

        assert_eq!(resource.resource_id, "resource-1");
        assert_eq!(resource.server_id, "server-1");
        assert_eq!(
            resource.scopes, None,
            "creating a resource does not widen what is meaningful on it"
        );

        let declares_none = ResourceModel {
            scopes: Some(Vec::new()),
            ..resource
        };
        assert_ne!(declares_none.scopes, None);
        assert_eq!(declares_none.scopes.as_deref(), Some(&[][..]));
    }

    /// A resource server takes its identifiers from the caller and keeps the
    /// mode it was given, since permissive and enforcing are the difference
    /// between recording a denial and applying one.
    #[test]
    fn a_resource_server_keeps_the_mode_it_was_given() {
        for mode in PolicyEnforcementMode::ALL {
            let server = ResourceServerMutationModel {
                name: "app".into(),
                display_name: "App".into(),
                description: String::new(),
                enforcement_mode: *mode,
                decision_strategy: DecisionStrategy::Affirmative,
                remote_resource_management: None,
                user_managed_access_enabled: None,
                configs: None,
            }
            .into_model("server-1".into(), "realm-1".into(), metadata());

            assert_eq!(server.server_id, "server-1");
            assert_eq!(server.realm_id, "realm-1");
            assert_eq!(server.enforcement_mode, *mode);
        }
    }

    /// A recorded decision names one of two answers, and a stored value that is
    /// neither does not decode.
    #[test]
    fn a_recorded_decision_is_one_of_two_answers() {
        assert_eq!(Decision::Permit.as_str(), "permit");
        assert_eq!(Decision::Deny.as_str(), "deny");
        assert!(serde_json::from_str::<Decision>("\"maybe\"").is_err());
        assert!(serde_json::from_str::<Decision>("\"Permit\"").is_err());
    }

    /// A provider keeps the identifier a login URL names it by, and takes the
    /// internal one from the caller.
    #[test]
    fn a_provider_keeps_its_public_identifier() {
        let provider = IdentityProviderMutationModel {
            provider_id: "google".into(),
            name: "google".into(),
            display_name: "Google".into(),
            description: String::new(),
            enabled: Some(true),
            trust_email: Some(false),
            configs: None,
        }
        .into_model("idp-1".into(), "realm-1".into(), metadata());

        assert_eq!(provider.internal_id, "idp-1");
        assert_eq!(provider.realm_id, "realm-1");
        assert_eq!(provider.provider_id, "google");
        assert_eq!(
            provider.trust_email,
            Some(false),
            "trusting an asserted address is opt in"
        );
    }
}
