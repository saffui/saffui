use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::auditable::AuditableModel;
use crate::entities::attributes::AttributesMap;
use crate::str_enum::str_enum;

/// A verified (or pending) email domain that drives home-realm discovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationDomain {
    pub name: String,
    pub verified: bool,
}

str_enum! {
    #[postgres(name = "org_membership")]
    /// How a user came to belong to an organization.
    pub enum OrgMembershipType {
        /// Provisioned by an org-linked identity provider on broker login.
        Managed => "managed",
        /// Invited, or self-registered.
        Unmanaged => "unmanaged",
    }
}

/// An organization within a realm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationModel {
    pub org_id: String,
    pub realm_id: String,
    /// Slug, unique within the realm.
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: bool,
    /// Home-realm-discovery keys. Empty on a plain load, populated when domains
    /// are asked for.
    pub domains: Vec<OrganizationDomain>,
    /// Post-login landing for the organization's login link.
    pub redirect_url: Option<String>,
    pub attributes: Option<AttributesMap>,
    pub metadata: AuditableModel,
}

/// An explicit M:N membership. A user may belong to several organizations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationMemberModel {
    pub realm_id: String,
    pub org_id: String,
    pub user_id: String,
    pub membership_type: OrgMembershipType,
    /// Organization-scoped role ids granted to the member.
    pub roles: Vec<String>,
    pub joined_at: Option<DateTime<Utc>>,
    pub metadata: AuditableModel,
}

/// The create and update payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationMutationModel {
    pub name: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    /// On unless said otherwise: an organization created over the plane is
    /// created to be used.
    #[serde(default = "enabled_unless_said")]
    pub enabled: bool,
    #[serde(default)]
    pub redirect_url: Option<String>,
    #[serde(default)]
    pub attributes: Option<AttributesMap>,
}

fn enabled_unless_said() -> bool {
    true
}

impl OrganizationMutationModel {
    /// Build a full model for a new organization. The caller supplies the ids
    /// and the metadata, because both come from the request context rather than
    /// from the payload — an organization that could name its own tenant would
    /// be one a caller could plant in someone else's.
    pub fn into_model(
        self,
        org_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> OrganizationModel {
        OrganizationModel {
            org_id,
            realm_id,
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            enabled: self.enabled,
            domains: Vec::new(),
            redirect_url: self.redirect_url,
            attributes: self.attributes,
            metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mutation() -> OrganizationMutationModel {
        OrganizationMutationModel {
            name: "customer-x".into(),
            display_name: "Customer X".into(),
            description: String::new(),
            enabled: true,
            redirect_url: Some("https://x.example".into()),
            attributes: None,
        }
    }

    #[test]
    fn mutation_builds_a_model_with_the_ids_and_metadata_it_was_given() {
        let org = mutation().into_model(
            "org-1".into(),
            "realm-1".into(),
            AuditableModel::from_creator("acme".into(), "root".into()),
        );

        assert_eq!(org.org_id, "org-1");
        assert_eq!(org.realm_id, "realm-1");
        assert_eq!(org.name, "customer-x");
        assert_eq!(org.redirect_url.as_deref(), Some("https://x.example"));
        assert!(org.enabled);
        assert_eq!(org.metadata.tenant, "acme");
    }

    /// Domains are a separate table, so a newly built organization has none —
    /// carrying one from the payload would be an unverified domain claiming
    /// home-realm discovery for a mail domain the caller does not own.
    #[test]
    fn a_new_organization_claims_no_domains() {
        let org = mutation().into_model(
            "org-1".into(),
            "realm-1".into(),
            AuditableModel::unassigned(),
        );
        assert!(org.domains.is_empty());
    }

    /// The membership type is a database enum, so its label, its wire spelling
    /// and `as_str` all come from one literal.
    #[test]
    fn the_membership_types_agree_with_their_own_spelling() {
        assert_eq!(OrgMembershipType::ALL.len(), 2);
        assert_eq!(OrgMembershipType::Managed.as_str(), "managed");
        assert_eq!(OrgMembershipType::Unmanaged.as_str(), "unmanaged");
        crate::str_enum::assert_round_trips(OrgMembershipType::ALL);
    }
}
