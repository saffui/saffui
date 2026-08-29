use serde::{Deserialize, Serialize};

use crate::entities::auth::{
    AuthenticationExecutionModel, AuthenticationFlowModel, RequiredActionModel,
};
use crate::entities::authz::{
    GroupModel, PolicyModel, ResourceModel, ResourceServerModel, RoleModel, ScopeModel,
};
use crate::entities::client::{ClientModel, ClientScopeModel, ProtocolMapperModel};
use crate::entities::organization::{OrganizationMemberModel, OrganizationModel};
use crate::entities::realm::RealmModel;
use crate::entities::user::UserModel;

/// The one document format this build writes and reads.
pub const EXPORT_FORMAT: u32 = 1;

/// A realm as a document: its configuration and its people, with every
/// identifier verbatim, so an import is the same realm and not a copy of it.
///
/// Nothing secret travels. Client secrets are hashed or sealed beside the
/// client rather than on it, signing keys and mail credentials are sealed to
/// the deployment's own envelope, and a sealed value opened nowhere else is
/// noise. An imported realm re-provisions its keys and is handed its secrets
/// again; the sections say what is carried so a reader never has to infer
/// what is missing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedRealm {
    /// Refused on read when it names a format this build does not write.
    pub format_version: u32,
    /// When the document was produced, seconds since the epoch.
    pub exported_at: i64,
    /// What this document carries, named so absence is stated rather than
    /// inferred.
    pub sections: Vec<String>,

    pub realm: RealmModel,
    pub required_actions: Vec<RequiredActionModel>,
    pub flows: Vec<AuthenticationFlowModel>,
    pub executions: Vec<AuthenticationExecutionModel>,
    pub roles: Vec<ExportedRole>,
    pub groups: Vec<ExportedGroup>,
    pub organizations: Vec<ExportedOrganization>,
    pub client_scopes: Vec<ExportedClientScope>,
    pub protocol_mappers: Vec<ProtocolMapperModel>,
    pub clients: Vec<ExportedClient>,
    pub users: Vec<UserModel>,
    pub authorization: Vec<ExportedResourceServer>,
}

/// A role and who holds it directly. The joins ride with their owner, which
/// is how the store hands them back and the order an import writes them in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedRole {
    pub role: RoleModel,
    pub held_by_users: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedGroup {
    pub group: GroupModel,
    pub members: Vec<String>,
    pub grants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedOrganization {
    pub organization: OrganizationModel,
    pub members: Vec<OrganizationMemberModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedClientScope {
    pub scope: ClientScopeModel,
    pub mappers: Vec<String>,
    pub grants: Vec<String>,
}

/// A client and what is attached to it, by identifier: the scopes and
/// mappers themselves are listed once at the top of the document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedClient {
    pub client: ClientModel,
    /// Each held scope and whether it is optional.
    pub scopes: Vec<(String, bool)>,
    pub mappers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedResourceServer {
    pub server: ResourceServerModel,
    pub resources: Vec<ResourceModel>,
    pub scopes: Vec<ScopeModel>,
    /// In an order where a policy's conditions precede it, so a replay can
    /// write them front to back.
    pub policies: Vec<PolicyModel>,
}
