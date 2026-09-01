use actix_web::Route;
use actix_web::http::Method;
use actix_web::web;
use models::entities::authz::AdminAction;

use crate::api::rest::endpoints::admin::{
    authorization, claim_sources, client_scopes, clients, directory, features, federation, flows,
    idps, iga, keys, mail, negotiation, portability, protocol_mappers, realm_keys, realms, rebac,
    sessions, users,
};
use crate::api::rest::endpoints::scim;

/// One route: the verb, the path, what it costs, and what answers it.
///
/// The four together, once. Written apart, the mount and the table of costs are
/// two lists that agree until one of them is edited, and the one that gets
/// edited is the mount: a handler arrives, nothing charges it, and the guard
/// refuses a route that looks like it should work.
#[derive(Clone)]
pub struct AdminRoute {
    pub method: Method,
    /// The registered pattern, not the request path: `/admin/realms/{realm}`
    /// rather than `/admin/realms/main`, so the lookup is an equality.
    pub pattern: &'static str,
    pub action: AdminAction,
    /// What actix mounts, once something answers it. A builder rather than a
    /// value, since registering consumes a route and this table is read twice.
    ///
    /// `None` declares what the plane will carry before it carries it: the cost
    /// is settled here first, so a handler arriving later cannot arrive without
    /// one, and until then the route is simply not there.
    pub handler: Option<fn() -> Route>,
}

impl std::fmt::Debug for AdminRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} ({:?})", self.method, self.pattern, self.action)
    }
}

/// Every admin route.
pub fn routes() -> Vec<AdminRoute> {
    vec![
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms",
            action: AdminAction::RealmList,
            handler: Some(|| web::get().to(realms::list)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms",
            action: AdminAction::RealmCreate,
            handler: None,
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/import",
            action: AdminAction::RealmImport,
            handler: Some(|| web::post().to(portability::import)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/features",
            action: AdminAction::FeatureRead,
            handler: Some(|| web::get().to(features::list)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/export",
            action: AdminAction::RealmExport,
            handler: Some(|| web::get().to(portability::export)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}",
            action: AdminAction::RealmRead,
            handler: Some(|| web::get().to(realms::get)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}",
            action: AdminAction::RealmWrite,
            handler: None,
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/mail",
            action: AdminAction::RealmRead,
            handler: Some(|| web::get().to(mail::read)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/mail",
            action: AdminAction::RealmWrite,
            handler: Some(|| web::put().to(mail::write)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/mail",
            action: AdminAction::RealmWrite,
            handler: Some(|| web::delete().to(mail::forget)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/theme",
            action: AdminAction::RealmRead,
            handler: Some(|| web::get().to(realms::theme)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/theme",
            action: AdminAction::RealmWrite,
            handler: Some(|| web::put().to(realms::set_theme)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/theme",
            action: AdminAction::RealmWrite,
            handler: Some(|| web::delete().to(realms::clear_theme)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/keys",
            action: AdminAction::RealmKeysRead,
            handler: Some(|| web::get().to(realm_keys::list)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/keys",
            action: AdminAction::RealmKeysWrite,
            handler: Some(|| web::post().to(realm_keys::rotate)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/keys/{kid}",
            action: AdminAction::RealmKeysWrite,
            handler: Some(|| web::delete().to(realm_keys::disable)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/clients",
            action: AdminAction::ClientRead,
            handler: Some(|| web::get().to(clients::list)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/clients",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::post().to(clients::create)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/clients/{client}",
            action: AdminAction::ClientRead,
            handler: Some(|| web::get().to(clients::get)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/clients/{client}",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::put().to(clients::update)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/clients/{client}",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::delete().to(clients::remove)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/clients/{client}/secret",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::post().to(clients::rotate_secret)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/client-scopes",
            action: AdminAction::ClientRead,
            handler: Some(|| web::get().to(client_scopes::list)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/client-scopes",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::post().to(client_scopes::create)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/client-scopes/{scope}",
            action: AdminAction::ClientRead,
            handler: Some(|| web::get().to(client_scopes::get)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/client-scopes/{scope}",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::put().to(client_scopes::update)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/client-scopes/{scope}",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::delete().to(client_scopes::delete)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/clients/{client}/scopes",
            action: AdminAction::ClientRead,
            handler: Some(|| web::get().to(client_scopes::of_client)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/clients/{client}/scopes/{scope}",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::put().to(client_scopes::attach)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/clients/{client}/scopes/{scope}",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::delete().to(client_scopes::detach)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/protocol-mappers",
            action: AdminAction::ClientRead,
            handler: Some(|| web::get().to(protocol_mappers::list)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/protocol-mappers",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::post().to(protocol_mappers::create)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/protocol-mappers/{mapper}",
            action: AdminAction::ClientRead,
            handler: Some(|| web::get().to(protocol_mappers::get)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/protocol-mappers/{mapper}",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::put().to(protocol_mappers::update)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/protocol-mappers/{mapper}",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::delete().to(protocol_mappers::delete)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/client-scopes/{scope}/mappers",
            action: AdminAction::ClientRead,
            handler: Some(|| web::get().to(protocol_mappers::of_scope)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/client-scopes/{scope}/mappers/{mapper}",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::put().to(protocol_mappers::attach_to_scope)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/client-scopes/{scope}/mappers/{mapper}",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::delete().to(protocol_mappers::detach_from_scope)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/clients/{client}/mappers",
            action: AdminAction::ClientRead,
            handler: Some(|| web::get().to(protocol_mappers::of_client)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/clients/{client}/mappers/{mapper}",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::put().to(protocol_mappers::attach_to_client)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/clients/{client}/mappers/{mapper}",
            action: AdminAction::ClientWrite,
            handler: Some(|| web::delete().to(protocol_mappers::detach_from_client)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/auth/flows",
            action: AdminAction::AuthFlowRead,
            handler: Some(|| web::get().to(flows::list)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/auth/flows",
            action: AdminAction::AuthFlowWrite,
            handler: Some(|| web::post().to(flows::create)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/auth/flows/{flow}",
            action: AdminAction::AuthFlowRead,
            handler: Some(|| web::get().to(flows::get)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/auth/flows/{flow}",
            action: AdminAction::AuthFlowWrite,
            handler: Some(|| web::delete().to(flows::delete)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/auth/flows/{flow}/executions",
            action: AdminAction::AuthFlowWrite,
            handler: Some(|| web::post().to(flows::add_execution)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/auth/flows/{flow}/order",
            action: AdminAction::AuthFlowWrite,
            handler: Some(|| web::put().to(flows::reorder)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/auth/executions/{execution}/requirement",
            action: AdminAction::AuthFlowWrite,
            handler: Some(|| web::put().to(flows::set_requirement)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/auth/executions/{execution}",
            action: AdminAction::AuthFlowWrite,
            handler: Some(|| web::delete().to(flows::remove_execution)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/auth/required-actions",
            action: AdminAction::RequiredActionRead,
            handler: Some(|| web::get().to(flows::list_actions)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/auth/required-actions",
            action: AdminAction::RequiredActionWrite,
            handler: Some(|| web::post().to(flows::register_action)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/auth/required-actions/{action}",
            action: AdminAction::RequiredActionWrite,
            handler: Some(|| web::put().to(flows::rework_action)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/auth/required-actions/{action}",
            action: AdminAction::RequiredActionWrite,
            handler: Some(|| web::delete().to(flows::unregister_action)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/users/{user}/required-actions/{action}",
            action: AdminAction::RequiredActionWrite,
            handler: Some(|| web::put().to(flows::require_of_user)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/users/{user}/required-actions/{action}",
            action: AdminAction::RequiredActionWrite,
            handler: Some(|| web::delete().to(flows::release_user)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/users/{user}/claim-sources",
            action: AdminAction::UserRead,
            handler: Some(|| web::get().to(claim_sources::list)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/users/{user}/claim-sources",
            action: AdminAction::UserWrite,
            handler: Some(|| web::post().to(claim_sources::add)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/users/{user}/claim-sources/{source}",
            action: AdminAction::UserWrite,
            handler: Some(|| web::delete().to(claim_sources::remove)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/identity-providers",
            action: AdminAction::IdpRead,
            handler: Some(|| web::get().to(idps::list)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/identity-providers",
            action: AdminAction::IdpWrite,
            handler: Some(|| web::post().to(idps::create)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/identity-providers/{alias}",
            action: AdminAction::IdpRead,
            handler: Some(|| web::get().to(idps::get)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/identity-providers/{alias}",
            action: AdminAction::IdpWrite,
            handler: Some(|| web::put().to(idps::update)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/identity-providers/{alias}",
            action: AdminAction::IdpWrite,
            handler: Some(|| web::delete().to(idps::delete)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/identity-providers/{alias}/mappers",
            action: AdminAction::IdpRead,
            handler: Some(|| web::get().to(idps::list_mappers)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/identity-providers/{alias}/mappers",
            action: AdminAction::IdpWrite,
            handler: Some(|| web::post().to(idps::add_mapper)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/identity-providers/{alias}/mappers/{mapper}",
            action: AdminAction::IdpRead,
            handler: Some(|| web::get().to(idps::get_mapper)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/identity-providers/{alias}/mappers/{mapper}",
            action: AdminAction::IdpWrite,
            handler: Some(|| web::put().to(idps::rework_mapper)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/identity-providers/{alias}/mappers/{mapper}",
            action: AdminAction::IdpWrite,
            handler: Some(|| web::delete().to(idps::remove_mapper)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/users/{user}/federated-identities",
            action: AdminAction::UserRead,
            handler: Some(|| web::get().to(idps::identities_of_user)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/federations",
            action: AdminAction::IdpRead,
            handler: Some(|| web::get().to(federation::list)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/federations/{alias}",
            action: AdminAction::IdpRead,
            handler: Some(|| web::get().to(federation::get)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/federations/{alias}",
            action: AdminAction::IdpWrite,
            handler: Some(|| web::put().to(federation::put)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/federations/{alias}",
            action: AdminAction::IdpWrite,
            handler: Some(|| web::delete().to(federation::delete)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/federations/{alias}/import",
            action: AdminAction::IdpWrite,
            handler: Some(|| web::post().to(federation::import)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/iga/rules",
            action: AdminAction::IgaRead,
            handler: Some(|| web::get().to(iga::rules)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/iga/rules/{rule}",
            action: AdminAction::IgaWrite,
            handler: Some(|| web::put().to(iga::put_rule)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/iga/rules/{rule}",
            action: AdminAction::IgaWrite,
            handler: Some(|| web::delete().to(iga::delete_rule)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/iga/grants",
            action: AdminAction::IgaWrite,
            handler: Some(|| web::post().to(iga::put_grant)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/iga/grants/{user}",
            action: AdminAction::IgaRead,
            handler: Some(|| web::get().to(iga::grants_of)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/iga/grants/{user}/{role}",
            action: AdminAction::IgaWrite,
            handler: Some(|| web::delete().to(iga::delete_grant)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/iga/converge",
            action: AdminAction::IgaWrite,
            handler: Some(|| web::post().to(iga::converge)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/realms/{realm}/scim/v2/Users",
            action: AdminAction::ScimRead,
            handler: Some(|| web::get().to(scim::users::list)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/realms/{realm}/scim/v2/Users",
            action: AdminAction::ScimWrite,
            handler: Some(|| web::post().to(scim::users::create)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/realms/{realm}/scim/v2/Users/{id}",
            action: AdminAction::ScimRead,
            handler: Some(|| web::get().to(scim::users::get)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/realms/{realm}/scim/v2/Users/{id}",
            action: AdminAction::ScimWrite,
            handler: Some(|| web::put().to(scim::users::replace)),
        },
        AdminRoute {
            method: Method::PATCH,
            pattern: "/realms/{realm}/scim/v2/Users/{id}",
            action: AdminAction::ScimWrite,
            handler: Some(|| web::patch().to(scim::users::patch)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/realms/{realm}/scim/v2/Users/{id}",
            action: AdminAction::ScimWrite,
            handler: Some(|| web::delete().to(scim::users::delete)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/realms/{realm}/scim/v2/Groups",
            action: AdminAction::ScimRead,
            handler: Some(|| web::get().to(scim::groups::list)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/realms/{realm}/scim/v2/Groups",
            action: AdminAction::ScimWrite,
            handler: Some(|| web::post().to(scim::groups::create)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/realms/{realm}/scim/v2/Groups/{id}",
            action: AdminAction::ScimRead,
            handler: Some(|| web::get().to(scim::groups::get)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/realms/{realm}/scim/v2/Groups/{id}",
            action: AdminAction::ScimWrite,
            handler: Some(|| web::put().to(scim::groups::replace)),
        },
        AdminRoute {
            method: Method::PATCH,
            pattern: "/realms/{realm}/scim/v2/Groups/{id}",
            action: AdminAction::ScimWrite,
            handler: Some(|| web::patch().to(scim::groups::patch)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/realms/{realm}/scim/v2/Groups/{id}",
            action: AdminAction::ScimWrite,
            handler: Some(|| web::delete().to(scim::groups::delete)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/realms/{realm}/scim/v2/ServiceProviderConfig",
            action: AdminAction::ScimRead,
            handler: Some(|| web::get().to(scim::discovery::service_provider_config)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/realms/{realm}/scim/v2/Schemas",
            action: AdminAction::ScimRead,
            handler: Some(|| web::get().to(scim::discovery::schemas)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/realms/{realm}/scim/v2/ResourceTypes",
            action: AdminAction::ScimRead,
            handler: Some(|| web::get().to(scim::discovery::resource_types)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/spnego",
            action: AdminAction::IdpRead,
            handler: Some(|| web::get().to(negotiation::get)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/spnego",
            action: AdminAction::IdpWrite,
            handler: Some(|| web::put().to(negotiation::put)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/spnego",
            action: AdminAction::IdpWrite,
            handler: Some(|| web::delete().to(negotiation::delete)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/authz/servers/{client}",
            action: AdminAction::UmaWrite,
            handler: Some(|| web::post().to(authorization::protect)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/authz/servers/{client}",
            action: AdminAction::UmaRead,
            handler: Some(|| web::get().to(authorization::server)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/authz/servers/{client}",
            action: AdminAction::UmaWrite,
            handler: Some(|| web::put().to(authorization::set_mode)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/authz/servers/{client}",
            action: AdminAction::UmaWrite,
            handler: Some(|| web::delete().to(authorization::unprotect)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/authz/servers/{client}/resources",
            action: AdminAction::UmaRead,
            handler: Some(|| web::get().to(authorization::resources)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/authz/servers/{client}/resources",
            action: AdminAction::UmaWrite,
            handler: Some(|| web::post().to(authorization::add_resource)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/authz/servers/{client}/resources/{resource}",
            action: AdminAction::UmaWrite,
            handler: Some(|| web::delete().to(authorization::remove_resource)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/authz/servers/{client}/scopes",
            action: AdminAction::UmaRead,
            handler: Some(|| web::get().to(authorization::scopes)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/authz/servers/{client}/scopes",
            action: AdminAction::UmaWrite,
            handler: Some(|| web::post().to(authorization::add_scope)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/authz/servers/{client}/scopes/{scope}",
            action: AdminAction::UmaWrite,
            handler: Some(|| web::delete().to(authorization::remove_scope)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/authz/servers/{client}/policies",
            action: AdminAction::UmaRead,
            handler: Some(|| web::get().to(authorization::policies)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/authz/servers/{client}/policies",
            action: AdminAction::UmaWrite,
            handler: Some(|| web::post().to(authorization::add_policy)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/authz/servers/{client}/policies/{policy}",
            action: AdminAction::UmaWrite,
            handler: Some(|| web::put().to(authorization::rework_policy)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/authz/servers/{client}/policies/{policy}",
            action: AdminAction::UmaWrite,
            handler: Some(|| web::delete().to(authorization::remove_policy)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/authz/decisions",
            action: AdminAction::AuthzDecisionRead,
            handler: Some(|| web::get().to(authorization::decisions)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/authz/decisions/disagreements",
            action: AdminAction::AuthzDecisionRead,
            handler: Some(|| web::get().to(authorization::disagreements)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/authz/decisions",
            action: AdminAction::AuthzDecisionWrite,
            handler: Some(|| web::delete().to(authorization::prune_decisions)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/rebac/schema",
            action: AdminAction::RebacRead,
            handler: Some(|| web::get().to(rebac::schema)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/rebac/schema",
            action: AdminAction::RebacWrite,
            handler: Some(|| web::put().to(rebac::publish)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/rebac/relations",
            action: AdminAction::RebacRead,
            handler: Some(|| web::get().to(rebac::subjects)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/rebac/relations",
            action: AdminAction::RebacWrite,
            handler: Some(|| web::post().to(rebac::relate)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/rebac/relations",
            action: AdminAction::RebacWrite,
            handler: Some(|| web::delete().to(rebac::unrelate)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/roles",
            action: AdminAction::RoleRead,
            handler: Some(|| web::get().to(directory::list_roles)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/roles",
            action: AdminAction::RoleWrite,
            handler: Some(|| web::post().to(directory::create_role)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/roles/{role}",
            action: AdminAction::RoleRead,
            handler: Some(|| web::get().to(directory::get_role)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/roles/{role}",
            action: AdminAction::RoleWrite,
            handler: Some(|| web::put().to(directory::update_role)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/roles/{role}",
            action: AdminAction::RoleWrite,
            handler: Some(|| web::delete().to(directory::delete_role)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/groups",
            action: AdminAction::GroupRead,
            handler: Some(|| web::get().to(directory::list_groups)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/groups",
            action: AdminAction::GroupWrite,
            handler: Some(|| web::post().to(directory::create_group)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/groups/{group}",
            action: AdminAction::GroupRead,
            handler: Some(|| web::get().to(directory::get_group)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/groups/{group}",
            action: AdminAction::GroupWrite,
            handler: Some(|| web::put().to(directory::update_group)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/groups/{group}",
            action: AdminAction::GroupWrite,
            handler: Some(|| web::delete().to(directory::delete_group)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/organizations",
            action: AdminAction::OrgRead,
            handler: Some(|| web::get().to(directory::list_organizations)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/organizations",
            action: AdminAction::OrgWrite,
            handler: Some(|| web::post().to(directory::create_organization)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/organizations/{organization}",
            action: AdminAction::OrgRead,
            handler: Some(|| web::get().to(directory::get_organization)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/organizations/{organization}",
            action: AdminAction::OrgWrite,
            handler: Some(|| web::put().to(directory::update_organization)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/organizations/{organization}",
            action: AdminAction::OrgWrite,
            handler: Some(|| web::delete().to(directory::delete_organization)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/roles/{role}/holders",
            action: AdminAction::RoleRead,
            handler: Some(|| web::get().to(directory::role_holders)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/roles/{role}/holders/{user}",
            action: AdminAction::RoleWrite,
            handler: Some(|| web::put().to(directory::grant_role_to_user)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/roles/{role}/holders/{user}",
            action: AdminAction::RoleWrite,
            handler: Some(|| web::delete().to(directory::revoke_role_from_user)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/groups/{group}/membership",
            action: AdminAction::GroupRead,
            handler: Some(|| web::get().to(directory::group_membership)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/groups/{group}/members/{user}",
            action: AdminAction::GroupWrite,
            handler: Some(|| web::put().to(directory::add_user_to_group)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/groups/{group}/members/{user}",
            action: AdminAction::GroupWrite,
            handler: Some(|| web::delete().to(directory::remove_user_from_group)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/groups/{group}/roles/{role}",
            action: AdminAction::RoleWrite,
            handler: Some(|| web::put().to(directory::grant_role_to_group)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/groups/{group}/roles/{role}",
            action: AdminAction::RoleWrite,
            handler: Some(|| web::delete().to(directory::revoke_role_from_group)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/organizations/{organization}/members",
            action: AdminAction::OrgRead,
            handler: Some(|| web::get().to(directory::organization_members)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/organizations/{organization}/members/{user}",
            action: AdminAction::OrgWrite,
            handler: Some(|| web::put().to(directory::add_organization_member)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/organizations/{organization}/members/{user}",
            action: AdminAction::OrgWrite,
            handler: Some(|| web::delete().to(directory::remove_organization_member)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/organizations/{organization}/theme",
            action: AdminAction::OrgRead,
            handler: Some(|| web::get().to(directory::get_organization_theme)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/organizations/{organization}/theme",
            action: AdminAction::OrgWrite,
            handler: Some(|| web::put().to(directory::set_organization_theme)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/organizations/{organization}/theme",
            action: AdminAction::OrgWrite,
            handler: Some(|| web::delete().to(directory::clear_organization_theme)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/users",
            action: AdminAction::UserRead,
            handler: Some(|| web::get().to(users::list)),
        },
        AdminRoute {
            method: Method::POST,
            pattern: "/admin/realms/{realm}/users",
            action: AdminAction::UserWrite,
            handler: Some(|| web::post().to(users::create)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/users/{user}",
            action: AdminAction::UserRead,
            handler: Some(|| web::get().to(users::get)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/users/{user}",
            action: AdminAction::UserWrite,
            handler: Some(|| web::put().to(users::update)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/users/{user}",
            action: AdminAction::UserWrite,
            handler: Some(|| web::delete().to(users::remove)),
        },
        AdminRoute {
            method: Method::PUT,
            pattern: "/admin/realms/{realm}/users/{user}/password",
            action: AdminAction::UserWrite,
            handler: Some(|| web::put().to(users::set_password)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/users/{user}/consents",
            action: AdminAction::UserRead,
            handler: Some(|| web::get().to(users::consents)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/users/{user}/consents/{client}",
            action: AdminAction::UserWrite,
            handler: Some(|| web::delete().to(users::withdraw_consent)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/users/{user}/messages",
            action: AdminAction::UserRead,
            handler: Some(|| web::get().to(users::messages)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/users/{user}/lockout",
            action: AdminAction::UserRead,
            handler: Some(|| web::get().to(users::lockout)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/users/{user}/lockout",
            action: AdminAction::UserWrite,
            handler: Some(|| web::delete().to(users::lift_lockout)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/users/{user}/keys",
            action: AdminAction::UserRead,
            handler: Some(|| web::get().to(keys::list)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/users/{user}/keys/{credential}",
            action: AdminAction::UserWrite,
            handler: Some(|| web::delete().to(keys::revoke)),
        },
        AdminRoute {
            method: Method::GET,
            pattern: "/admin/realms/{realm}/users/{user}/sessions",
            action: AdminAction::UserRead,
            handler: Some(|| web::get().to(sessions::list)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/users/{user}/sessions/{session}",
            action: AdminAction::UserWrite,
            handler: Some(|| web::delete().to(sessions::close)),
        },
        AdminRoute {
            method: Method::DELETE,
            pattern: "/admin/realms/{realm}/users/{user}/sessions/{session}/grants/{client}",
            action: AdminAction::UserWrite,
            handler: Some(|| web::delete().to(sessions::revoke)),
        },
    ]
}

/// What this route requires, or nothing if it is not declared.
///
/// The method is part of the question. A table that answered by path alone
/// would charge a read what a write costs, or the reverse, which is worse.
pub fn required(method: &Method, pattern: &str) -> Option<AdminAction> {
    routes()
        .into_iter()
        .find(|route| route.method == method && route.pattern == pattern)
        .map(|route| route.action)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One entry per method and path. A duplicate means two answers to one
    /// question, and which one applies would depend on the order of this list.
    #[test]
    fn no_route_is_declared_twice() {
        let mut seen = std::collections::HashSet::new();
        for route in routes() {
            assert!(
                seen.insert((route.method.clone(), route.pattern)),
                "{} {} is declared twice",
                route.method,
                route.pattern
            );
        }
    }

    /// The method is part of the answer, which is the whole reason this is a
    /// table and not a path prefix.
    #[test]
    fn two_methods_on_one_path_cost_differently() {
        assert_eq!(
            required(&Method::GET, "/admin/realms/{realm}"),
            Some(AdminAction::RealmRead)
        );
        assert_eq!(
            required(&Method::PUT, "/admin/realms/{realm}"),
            Some(AdminAction::RealmWrite)
        );
    }

    /// A route nobody declared is refused rather than guessed at.
    #[test]
    fn an_undeclared_route_requires_nothing_and_is_therefore_refused() {
        assert_eq!(required(&Method::DELETE, "/admin/realms/{realm}"), None);
        assert_eq!(required(&Method::GET, "/admin/whatever"), None);
    }

    /// A pattern, never a path. Looking up a concrete path would silently miss.
    #[test]
    fn the_lookup_is_on_the_pattern_and_not_the_path() {
        assert_eq!(required(&Method::GET, "/admin/realms/main"), None);
    }
}
