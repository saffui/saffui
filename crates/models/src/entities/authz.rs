//! Who may do what: the capability vocabulary, roles, groups, and the identity
//! providers a realm federates to.

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
    pub is_client_role: bool,
    /// Admin plane capabilities this role grants.
    ///
    /// Typed, so a capability nobody declared cannot be written down. `None` and
    /// an empty list both grant nothing: the admin plane is deny by default, and
    /// a role that administers a deployment holds its grant by name rather than
    /// through this list.
    pub admin_permissions: Option<Vec<AdminAction>>,
    pub metadata: AuditableModel,
}

/// The create and update payload for a role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleMutationModel {
    pub name: String,
    pub description: String,
    pub display_name: String,
    pub is_client_role: bool,
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
            is_client_role: self.is_client_role,
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
            is_client_role: false,
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
            is_client_role: false,
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
