use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::authz::{PolicyModel, StoredPolicy};
use models::entities::export::{
    EXPORT_FORMAT, ExportedClient, ExportedClientScope, ExportedGroup, ExportedOrganization,
    ExportedRealm, ExportedResourceServer, ExportedRole,
};
use models::paging::Window;
use store::providers::{
    auth_flows, authz_policies, authz_surface, client_scopes, clients, organizations, realms,
    roles, users,
};
use store::query::list_query::ListQuery;

/// Why a realm could not be carried out or written back.
#[derive(Debug, thiserror::Error)]
pub enum Unportable {
    #[error("no such realm")]
    NotFound,
    #[error("a realm with this name already exists")]
    AlreadyExists,
    /// A quarantined policy row would leave a silent hole in the document,
    /// which a reader has no way to see. Deleting or repairing it first is
    /// the honest path.
    #[error("policy {0} cannot be read, so the document would be missing it")]
    Quarantined(String),
    /// The document names conditions in an order no replay can satisfy, which
    /// this build never writes.
    #[error("the policies of {0} do not resolve in document order")]
    Tangled(String),
    #[error("{0}")]
    Invalid(String),
    #[error("the store could not be read or written")]
    Backend,
}

/// Every page of a paged listing, drained inside the one transaction.
macro_rules! drained {
    ($fetch:expr) => {{
        let mut all = Vec::new();
        let mut first: i64 = 0;
        loop {
            let query = ListQuery::new(Window {
                first,
                max: 500,
                clamped: false,
            });
            let page = $fetch(&query).await.map_err(|_| Unportable::Backend)?;
            let got = page.items.len() as i64;
            all.extend(page.items);
            if got < 500 {
                break;
            }
            first += got;
        }
        all
    }};
}

/// The realm as a document, read whole inside one transaction so no section
/// can come from a different state than another.
pub async fn export_realm(
    transaction: &Transaction<'_>,
    realm_id: &str,
    now: DateTime<Utc>,
) -> Result<ExportedRealm, Unportable> {
    let realm = realms::load(transaction, realm_id)
        .await
        .map_err(|_| Unportable::Backend)?
        .ok_or(Unportable::NotFound)?;

    let required_actions = auth_flows::list_actions(transaction)
        .await
        .map_err(|_| Unportable::Backend)?;
    let flows = auth_flows::list_flows(transaction)
        .await
        .map_err(|_| Unportable::Backend)?;
    let mut executions = Vec::new();
    for flow in &flows {
        executions.extend(
            auth_flows::executions_of(transaction, &flow.flow_id)
                .await
                .map_err(|_| Unportable::Backend)?,
        );
    }

    let mut exported_roles = Vec::new();
    for role in drained!(|query| roles::list(transaction, query, false)) {
        // The second half of the answer is the groups holding it, which the
        // groups section already carries as its own grants.
        let (held_by_users, _) = roles::holders_of(transaction, &role.role_id)
            .await
            .map_err(|_| Unportable::Backend)?;
        exported_roles.push(ExportedRole {
            role,
            held_by_users,
        });
    }

    let mut groups = Vec::new();
    for group in drained!(|query| roles::list_groups(transaction, query, false)) {
        let (members, grants) = roles::group_membership(transaction, &group.group_id)
            .await
            .map_err(|_| Unportable::Backend)?;
        groups.push(ExportedGroup {
            group,
            members,
            grants,
        });
    }

    let mut exported_orgs = Vec::new();
    for organization in drained!(|query| organizations::list(transaction, query, false)) {
        let members = organizations::members(transaction, &organization.org_id)
            .await
            .map_err(|_| Unportable::Backend)?;
        exported_orgs.push(ExportedOrganization {
            organization,
            members,
        });
    }

    let mut exported_scopes = Vec::new();
    for scope in client_scopes::list_scopes(transaction)
        .await
        .map_err(|_| Unportable::Backend)?
    {
        let mappers = client_scopes::mappers_of_scope(transaction, &scope.client_scope_id)
            .await
            .map_err(|_| Unportable::Backend)?
            .into_iter()
            .map(|mapper| mapper.mapper_id)
            .collect();
        let grants = client_scopes::roles_of_scope(transaction, &scope.client_scope_id)
            .await
            .map_err(|_| Unportable::Backend)?;
        exported_scopes.push(ExportedClientScope {
            scope,
            mappers,
            grants,
        });
    }
    let protocol_mappers = client_scopes::list_mappers(transaction)
        .await
        .map_err(|_| Unportable::Backend)?;

    let mut exported_clients = Vec::new();
    for client in drained!(|query| clients::list(transaction, query, false)) {
        let scopes = client_scopes::scopes_of_client(transaction, &client.client_id)
            .await
            .map_err(|_| Unportable::Backend)?
            .into_iter()
            .map(|(scope, optional)| (scope.client_scope_id, optional))
            .collect();
        let mappers = client_scopes::mappers_of_client(transaction, &client.client_id)
            .await
            .map_err(|_| Unportable::Backend)?
            .into_iter()
            .map(|mapper| mapper.mapper_id)
            .collect();
        exported_clients.push(ExportedClient {
            client,
            scopes,
            mappers,
        });
    }

    let users = drained!(|query| users::list(transaction, query, false));

    let mut authorization = Vec::new();
    for server in authz_surface::list_servers(transaction)
        .await
        .map_err(|_| Unportable::Backend)?
    {
        let resources = authz_surface::resources_of_server(transaction, &server.server_id)
            .await
            .map_err(|_| Unportable::Backend)?;
        let scopes = authz_surface::scopes_of_server(transaction, &server.server_id)
            .await
            .map_err(|_| Unportable::Backend)?;
        let mut policies = Vec::new();
        for stored in authz_policies::list_for_server(transaction, &server.server_id)
            .await
            .map_err(|_| Unportable::Backend)?
        {
            match stored {
                StoredPolicy::Read(policy) => policies.push(policy),
                StoredPolicy::Unreadable { policy_id } => {
                    return Err(Unportable::Quarantined(policy_id));
                }
            }
        }
        let policies = conditions_first(&server.server_id, policies)?;
        authorization.push(ExportedResourceServer {
            server,
            resources,
            scopes,
            policies,
        });
    }

    Ok(ExportedRealm {
        format_version: EXPORT_FORMAT,
        exported_at: now.timestamp(),
        sections: [
            "realm",
            "required_actions",
            "flows",
            "executions",
            "roles",
            "groups",
            "organizations",
            "client_scopes",
            "protocol_mappers",
            "clients",
            "users",
            "authorization",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        realm,
        required_actions,
        flows,
        executions,
        roles: exported_roles,
        groups,
        organizations: exported_orgs,
        client_scopes: exported_scopes,
        protocol_mappers,
        clients: exported_clients,
        users,
        authorization,
    })
}

/// Order policies so every condition precedes what reads it, which is the
/// order a replay writes them in and the order the store will accept.
fn conditions_first(
    server_id: &str,
    mut pending: Vec<PolicyModel>,
) -> Result<Vec<PolicyModel>, Unportable> {
    let mut ordered: Vec<PolicyModel> = Vec::with_capacity(pending.len());
    while !pending.is_empty() {
        let placed_before = ordered.len();
        let mut still = Vec::new();
        for policy in pending {
            let satisfied = policy
                .terms
                .policies
                .iter()
                .all(|condition| ordered.iter().any(|placed| &placed.policy_id == condition));
            if satisfied {
                ordered.push(policy);
            } else {
                still.push(policy);
            }
        }
        if ordered.len() == placed_before {
            return Err(Unportable::Tangled(server_id.to_owned()));
        }
        pending = still;
    }
    Ok(ordered)
}

/// Point every row of the document at the realm it is being written into.
///
/// The realm in the document is where it came from; the transaction is
/// scoped to where it is going, and a row naming another realm would be
/// refused or, worse, quietly rescoped by the session settings. The tenant
/// is rewritten for the same reason: it is the importer's, never the
/// document's.
fn retarget(doc: &mut ExportedRealm, tenant: &str, realm_id: &str) {
    let name = realm_id.to_owned();
    doc.realm.realm_id = name.clone();
    doc.realm.name = name.clone();

    macro_rules! repoint {
        ($($row:expr),+ $(,)?) => {
            $(
                $row.realm_id = name.clone();
                $row.metadata.tenant = tenant.to_owned();
            )+
        };
    }
    repoint!(doc.realm);
    for action in &mut doc.required_actions {
        repoint!(action);
    }
    for flow in &mut doc.flows {
        repoint!(flow);
    }
    for execution in &mut doc.executions {
        repoint!(execution);
    }
    for role in &mut doc.roles {
        repoint!(role.role);
    }
    for group in &mut doc.groups {
        repoint!(group.group);
    }
    for organization in &mut doc.organizations {
        repoint!(organization.organization);
        for member in &mut organization.members {
            repoint!(member);
        }
    }
    for scope in &mut doc.client_scopes {
        repoint!(scope.scope);
    }
    for mapper in &mut doc.protocol_mappers {
        repoint!(mapper);
    }
    for client in &mut doc.clients {
        repoint!(client.client);
    }
    for user in &mut doc.users {
        repoint!(user);
    }
    for server in &mut doc.authorization {
        repoint!(server.server);
        for resource in &mut server.resources {
            repoint!(resource);
        }
        for scope in &mut server.scopes {
            repoint!(scope);
        }
        for policy in &mut server.policies {
            repoint!(policy);
        }
    }
}

/// Write the document back as rows, in dependency order, inside the one
/// transaction the caller opened for the target realm. Nothing commits
/// here: a realm is wholly present or wholly absent.
pub async fn import_realm(
    transaction: &Transaction<'_>,
    tenant: &str,
    realm_id: &str,
    mut doc: ExportedRealm,
) -> Result<(), Unportable> {
    if doc.format_version != EXPORT_FORMAT {
        return Err(Unportable::Invalid(format!(
            "this build reads format {EXPORT_FORMAT} and the document says {}",
            doc.format_version
        )));
    }
    if realms::load(transaction, realm_id)
        .await
        .map_err(|_| Unportable::Backend)?
        .is_some()
    {
        return Err(Unportable::AlreadyExists);
    }
    retarget(&mut doc, tenant, realm_id);

    realms::create(transaction, &doc.realm)
        .await
        .map_err(|_| Unportable::Backend)?;
    for action in &doc.required_actions {
        auth_flows::register_action(transaction, action)
            .await
            .map_err(|_| Unportable::Backend)?;
    }
    for flow in &doc.flows {
        auth_flows::create_flow(transaction, flow)
            .await
            .map_err(|_| Unportable::Backend)?;
    }
    for execution in &doc.executions {
        auth_flows::create_execution(transaction, execution)
            .await
            .map_err(|_| Unportable::Backend)?;
    }

    for exported in &doc.roles {
        roles::create(transaction, &exported.role)
            .await
            .map_err(|_| Unportable::Backend)?;
    }
    for exported in &doc.groups {
        roles::create_group(transaction, &exported.group)
            .await
            .map_err(|_| Unportable::Backend)?;
        for role_id in &exported.grants {
            roles::grant_to_group(transaction, &exported.group.group_id, role_id)
                .await
                .map_err(|_| Unportable::Backend)?;
        }
    }
    for exported in &doc.organizations {
        organizations::create(transaction, &exported.organization)
            .await
            .map_err(|_| Unportable::Backend)?;
    }

    for exported in &doc.client_scopes {
        client_scopes::create_scope(transaction, &exported.scope)
            .await
            .map_err(|_| Unportable::Backend)?;
    }
    for mapper in &doc.protocol_mappers {
        client_scopes::create_mapper(transaction, mapper)
            .await
            .map_err(|_| Unportable::Backend)?;
    }
    for exported in &doc.client_scopes {
        for mapper_id in &exported.mappers {
            client_scopes::attach_mapper_to_scope(
                transaction,
                &exported.scope.client_scope_id,
                mapper_id,
            )
            .await
            .map_err(|_| Unportable::Backend)?;
        }
        for role_id in &exported.grants {
            client_scopes::attach_role_to_scope(
                transaction,
                &exported.scope.client_scope_id,
                role_id,
            )
            .await
            .map_err(|_| Unportable::Backend)?;
        }
    }

    for exported in &doc.clients {
        clients::create(transaction, &exported.client)
            .await
            .map_err(|_| Unportable::Backend)?;
        clients::update(transaction, &exported.client)
            .await
            .map_err(|_| Unportable::Backend)?;
        for (scope_id, optional) in &exported.scopes {
            client_scopes::attach_scope(
                transaction,
                &exported.client.client_id,
                scope_id,
                *optional,
            )
            .await
            .map_err(|_| Unportable::Backend)?;
        }
        for mapper_id in &exported.mappers {
            client_scopes::attach_mapper_to_client(
                transaction,
                &exported.client.client_id,
                mapper_id,
            )
            .await
            .map_err(|_| Unportable::Backend)?;
        }
    }

    for user in &doc.users {
        users::create(transaction, user)
            .await
            .map_err(|_| Unportable::Backend)?;
    }
    for exported in &doc.roles {
        for user_id in &exported.held_by_users {
            roles::grant_to_user(transaction, user_id, &exported.role.role_id)
                .await
                .map_err(|_| Unportable::Backend)?;
        }
    }
    for exported in &doc.groups {
        for user_id in &exported.members {
            roles::add_to_group(transaction, user_id, &exported.group.group_id)
                .await
                .map_err(|_| Unportable::Backend)?;
        }
    }
    for exported in &doc.organizations {
        for member in &exported.members {
            organizations::add_member(transaction, member)
                .await
                .map_err(|_| Unportable::Backend)?;
        }
    }

    for exported in &doc.authorization {
        authz_surface::create_server(transaction, &exported.server)
            .await
            .map_err(|_| Unportable::Backend)?;
        for resource in &exported.resources {
            authz_surface::create_resource(transaction, resource)
                .await
                .map_err(|_| Unportable::Backend)?;
        }
        for scope in &exported.scopes {
            authz_surface::create_scope(transaction, scope)
                .await
                .map_err(|_| Unportable::Backend)?;
        }
        for policy in &exported.policies {
            authz_policies::create(transaction, policy)
                .await
                .map_err(|why| Unportable::Invalid(why.to_string()))?;
        }
    }
    Ok(())
}
