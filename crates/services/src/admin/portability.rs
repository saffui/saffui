use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::authz::{PolicyModel, StoredPolicy};
use models::entities::export::{
    EXPORT_FORMAT, ExportedClient, ExportedClientScope, ExportedGroup, ExportedOrganization,
    ExportedResourceServer, ExportedRole,
};
use models::entities::export::{
    ExportedRealm, ImportCollision, ImportCollisionPolicy, PartialImportReport,
};
use models::paging::Window;
use std::collections::HashSet;
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
    #[error("partial import refused: {0}")]
    Partial(String),
}

const MAX_PARTIAL_ITEMS: usize = 10_000;
const MAX_PARTIAL_COLLISIONS: usize = 100;

#[derive(Default)]
struct Existing {
    ids: HashSet<String>,
    names: HashSet<String>,
}

struct PartialPlan {
    report: PartialImportReport,
    roles: Existing,
    groups: Existing,
    client_scopes: Existing,
    protocol_mappers: Existing,
    clients: Existing,
    organizations: Existing,
    flows: Existing,
    executions: Existing,
    required_actions: Existing,
    resource_servers: Existing,
    resources: Existing,
    authorization_scopes: Existing,
    policies: Existing,
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

#[derive(Clone, Copy)]
enum PartialAction {
    New,
    Overwrite,
    Skip,
}

async fn existing(
    transaction: &Transaction<'_>,
    table: &str,
    id_column: &str,
    name_column: &str,
    ids: &[String],
    names: &[String],
) -> Result<Existing, Unportable> {
    if ids.is_empty() && names.is_empty() {
        return Ok(Existing::default());
    }
    let statement = format!(
        "SELECT {id_column}, {name_column} FROM {table} \
         WHERE {id_column} = ANY($1) OR {name_column} = ANY($2)"
    );
    let rows = transaction
        .query(statement.as_str(), &[&ids, &names])
        .await
        .map_err(|_| Unportable::Backend)?;
    Ok(Existing {
        ids: rows.iter().map(|row| row.get(id_column)).collect(),
        names: rows.iter().map(|row| row.get(name_column)).collect(),
    })
}

fn validate_count(label: &str, count: usize) -> Result<(), Unportable> {
    if count > MAX_PARTIAL_ITEMS {
        return Err(Unportable::Partial(format!(
            "{label} carries {count} items; the limit is {MAX_PARTIAL_ITEMS}"
        )));
    }
    Ok(())
}

fn choose(
    report: &mut PartialImportReport,
    section: &str,
    identifier: &str,
    name: &str,
    state: &Existing,
    policy: ImportCollisionPolicy,
) -> Result<PartialAction, Unportable> {
    let Some(reason) = state
        .ids
        .contains(identifier)
        .then_some("identifier")
        .or_else(|| state.names.contains(name).then_some("name"))
    else {
        return Ok(PartialAction::New);
    };

    report.collision_count += 1;
    if report.collisions.len() < MAX_PARTIAL_COLLISIONS {
        report.collisions.push(ImportCollision {
            section: section.to_owned(),
            identifier: identifier.to_owned(),
            reason: reason.to_owned(),
        });
    } else {
        report.collisions_truncated = true;
    }

    match action(state, identifier, name, policy)? {
        PartialAction::New => unreachable!(),
        PartialAction::Overwrite => Ok(PartialAction::Overwrite),
        PartialAction::Skip => Ok(PartialAction::Skip),
    }
}

fn action(
    state: &Existing,
    identifier: &str,
    name: &str,
    policy: ImportCollisionPolicy,
) -> Result<PartialAction, Unportable> {
    let Some(reason) = state
        .ids
        .contains(identifier)
        .then_some("identifier")
        .or_else(|| state.names.contains(name).then_some("name"))
    else {
        return Ok(PartialAction::New);
    };
    match policy {
        ImportCollisionPolicy::Skip => Ok(PartialAction::Skip),
        ImportCollisionPolicy::Fail => Ok(PartialAction::Skip),
        ImportCollisionPolicy::Overwrite if reason == "identifier" => Ok(PartialAction::Overwrite),
        ImportCollisionPolicy::Overwrite => Err(Unportable::Partial(format!(
            "object {identifier} collides by name but not by identifier"
        ))),
    }
}

fn ensure_no_users(document: &ExportedRealm) -> Result<(), Unportable> {
    if !document.users.is_empty() || document.sections.iter().any(|section| section == "users") {
        return Err(Unportable::Partial(
            "accounts, credentials and sessions cannot be imported partially".to_owned(),
        ));
    }
    for client in &document.clients {
        if client.client.secret.is_some() || client.client.registration_token.is_some() {
            return Err(Unportable::Partial(
                "client credentials cannot be imported".to_owned(),
            ));
        }
    }
    Ok(())
}

async fn partial_plan(
    transaction: &Transaction<'_>,
    target: &str,
    document: &ExportedRealm,
    policy: ImportCollisionPolicy,
) -> Result<PartialPlan, Unportable> {
    if document.format_version != EXPORT_FORMAT {
        return Err(Unportable::Invalid(format!(
            "this build reads format {EXPORT_FORMAT} and the document says {}",
            document.format_version
        )));
    }
    ensure_no_users(document)?;
    validate_count("roles", document.roles.len())?;
    validate_count(
        "role composites",
        document
            .roles
            .iter()
            .map(|role| role.composites.len())
            .sum(),
    )?;
    validate_count("groups", document.groups.len())?;
    validate_count("client scopes", document.client_scopes.len())?;
    validate_count("protocol mappers", document.protocol_mappers.len())?;
    validate_count("clients", document.clients.len())?;
    validate_count("organizations", document.organizations.len())?;
    validate_count("flows", document.flows.len())?;
    validate_count("executions", document.executions.len())?;
    validate_count("required actions", document.required_actions.len())?;

    let resources: Vec<_> = document
        .authorization
        .iter()
        .flat_map(|server| server.resources.iter())
        .collect();
    let authorization_scopes: Vec<_> = document
        .authorization
        .iter()
        .flat_map(|server| server.scopes.iter())
        .collect();
    let policies: Vec<_> = document
        .authorization
        .iter()
        .flat_map(|server| server.policies.iter())
        .collect();
    validate_count("resource servers", document.authorization.len())?;
    validate_count("resources", resources.len())?;
    validate_count("authorization scopes", authorization_scopes.len())?;
    validate_count("policies", policies.len())?;

    let role_ids: Vec<_> = document
        .roles
        .iter()
        .map(|held| held.role.role_id.clone())
        .collect();
    let role_names: Vec<_> = document
        .roles
        .iter()
        .map(|held| held.role.name.clone())
        .collect();
    let group_ids: Vec<_> = document
        .groups
        .iter()
        .map(|held| held.group.group_id.clone())
        .collect();
    let group_names: Vec<_> = document
        .groups
        .iter()
        .map(|held| held.group.name.clone())
        .collect();
    let scope_ids: Vec<_> = document
        .client_scopes
        .iter()
        .map(|held| held.scope.client_scope_id.clone())
        .collect();
    let scope_names: Vec<_> = document
        .client_scopes
        .iter()
        .map(|held| held.scope.name.clone())
        .collect();
    let mapper_ids: Vec<_> = document
        .protocol_mappers
        .iter()
        .map(|held| held.mapper_id.clone())
        .collect();
    let mapper_names: Vec<_> = document
        .protocol_mappers
        .iter()
        .map(|held| held.name.clone())
        .collect();
    let client_ids: Vec<_> = document
        .clients
        .iter()
        .map(|held| held.client.client_id.clone())
        .collect();
    let client_names: Vec<_> = document
        .clients
        .iter()
        .map(|held| held.client.name.clone())
        .collect();
    let org_ids: Vec<_> = document
        .organizations
        .iter()
        .map(|held| held.organization.org_id.clone())
        .collect();
    let org_names: Vec<_> = document
        .organizations
        .iter()
        .map(|held| held.organization.name.clone())
        .collect();
    let flow_ids: Vec<_> = document
        .flows
        .iter()
        .map(|held| held.flow_id.clone())
        .collect();
    let flow_names: Vec<_> = document
        .flows
        .iter()
        .map(|held| held.alias.clone())
        .collect();
    let execution_ids: Vec<_> = document
        .executions
        .iter()
        .map(|held| held.execution_id.clone())
        .collect();
    let execution_names: Vec<_> = document
        .executions
        .iter()
        .map(|held| held.alias.clone())
        .collect();
    let action_ids: Vec<_> = document
        .required_actions
        .iter()
        .map(|held| held.action_id.clone())
        .collect();
    let action_names: Vec<_> = document
        .required_actions
        .iter()
        .map(|held| held.action.to_string())
        .collect();
    let server_ids: Vec<_> = document
        .authorization
        .iter()
        .map(|held| held.server.server_id.clone())
        .collect();
    let resource_ids: Vec<_> = resources
        .iter()
        .map(|held| held.resource_id.clone())
        .collect();
    let resource_names: Vec<_> = resources.iter().map(|held| held.name.clone()).collect();
    let authz_scope_ids: Vec<_> = authorization_scopes
        .iter()
        .map(|held| held.scope_id.clone())
        .collect();
    let authz_scope_names: Vec<_> = authorization_scopes
        .iter()
        .map(|held| held.name.clone())
        .collect();
    let policy_ids: Vec<_> = policies.iter().map(|held| held.policy_id.clone()).collect();
    let policy_names: Vec<_> = policies
        .iter()
        .map(|held| held.terms.name.clone())
        .collect();

    let roles = existing(
        transaction,
        "roles",
        "role_id",
        "name",
        &role_ids,
        &role_names,
    )
    .await?;
    let groups = existing(
        transaction,
        "groups",
        "group_id",
        "name",
        &group_ids,
        &group_names,
    )
    .await?;
    let client_scopes = existing(
        transaction,
        "client_scopes",
        "client_scope_id",
        "name",
        &scope_ids,
        &scope_names,
    )
    .await?;
    let protocol_mappers = existing(
        transaction,
        "protocol_mappers",
        "mapper_id",
        "name",
        &mapper_ids,
        &mapper_names,
    )
    .await?;
    let clients = existing(
        transaction,
        "clients",
        "client_id",
        "name",
        &client_ids,
        &client_names,
    )
    .await?;
    let organizations = existing(
        transaction,
        "organizations",
        "org_id",
        "name",
        &org_ids,
        &org_names,
    )
    .await?;
    let flows = existing(
        transaction,
        "authentication_flows",
        "flow_id",
        "alias",
        &flow_ids,
        &flow_names,
    )
    .await?;
    let executions = existing(
        transaction,
        "authentication_executions",
        "execution_id",
        "alias",
        &execution_ids,
        &execution_names,
    )
    .await?;
    let required_actions = existing(
        transaction,
        "required_actions",
        "action_id",
        "action",
        &action_ids,
        &action_names,
    )
    .await?;
    let resource_servers = existing(
        transaction,
        "resource_servers",
        "server_id",
        "server_id",
        &server_ids,
        &server_ids,
    )
    .await?;
    let resources = existing(
        transaction,
        "resources",
        "resource_id",
        "name",
        &resource_ids,
        &resource_names,
    )
    .await?;
    let authorization_scopes = existing(
        transaction,
        "scopes",
        "scope_id",
        "name",
        &authz_scope_ids,
        &authz_scope_names,
    )
    .await?;
    let policies = existing(
        transaction,
        "policies",
        "policy_id",
        "name",
        &policy_ids,
        &policy_names,
    )
    .await?;

    let mut report = PartialImportReport {
        realm_id: target.to_owned(),
        ..PartialImportReport::default()
    };

    for held in &document.roles {
        match choose(
            &mut report,
            "roles",
            &held.role.role_id,
            &held.role.name,
            &roles,
            policy,
        )? {
            PartialAction::New => report.new.roles += 1,
            PartialAction::Overwrite => report.overwritten.roles += 1,
            PartialAction::Skip => report.skipped.roles += 1,
        }
    }
    for held in &document.groups {
        match choose(
            &mut report,
            "groups",
            &held.group.group_id,
            &held.group.name,
            &groups,
            policy,
        )? {
            PartialAction::New => report.new.groups += 1,
            PartialAction::Overwrite => report.overwritten.groups += 1,
            PartialAction::Skip => report.skipped.groups += 1,
        }
    }
    for held in &document.client_scopes {
        match choose(
            &mut report,
            "client-scopes",
            &held.scope.client_scope_id,
            &held.scope.name,
            &client_scopes,
            policy,
        )? {
            PartialAction::New => report.new.client_scopes += 1,
            PartialAction::Overwrite => report.overwritten.client_scopes += 1,
            PartialAction::Skip => report.skipped.client_scopes += 1,
        }
    }
    for held in &document.protocol_mappers {
        match choose(
            &mut report,
            "protocol-mappers",
            &held.mapper_id,
            &held.name,
            &protocol_mappers,
            policy,
        )? {
            PartialAction::New => report.new.protocol_mappers += 1,
            PartialAction::Overwrite => report.overwritten.protocol_mappers += 1,
            PartialAction::Skip => report.skipped.protocol_mappers += 1,
        }
    }
    for held in &document.clients {
        match choose(
            &mut report,
            "clients",
            &held.client.client_id,
            &held.client.name,
            &clients,
            policy,
        )? {
            PartialAction::New => report.new.clients += 1,
            PartialAction::Overwrite => report.overwritten.clients += 1,
            PartialAction::Skip => report.skipped.clients += 1,
        }
    }
    for held in &document.organizations {
        match choose(
            &mut report,
            "organizations",
            &held.organization.org_id,
            &held.organization.name,
            &organizations,
            policy,
        )? {
            PartialAction::New => report.new.organizations += 1,
            PartialAction::Overwrite => report.overwritten.organizations += 1,
            PartialAction::Skip => report.skipped.organizations += 1,
        }
    }
    for held in &document.flows {
        match choose(
            &mut report,
            "flows",
            &held.flow_id,
            &held.alias,
            &flows,
            policy,
        )? {
            PartialAction::New => report.new.flows += 1,
            PartialAction::Overwrite => report.overwritten.flows += 1,
            PartialAction::Skip => report.skipped.flows += 1,
        }
    }
    for held in &document.required_actions {
        let name = held.action.to_string();
        match choose(
            &mut report,
            "required-actions",
            &held.action_id,
            &name,
            &required_actions,
            policy,
        )? {
            PartialAction::New => report.new.required_actions += 1,
            PartialAction::Overwrite => report.overwritten.required_actions += 1,
            PartialAction::Skip => report.skipped.required_actions += 1,
        }
    }
    for held in &document.executions {
        match choose(
            &mut report,
            "executions",
            &held.execution_id,
            &held.alias,
            &executions,
            policy,
        )? {
            PartialAction::New => report.new.executions += 1,
            PartialAction::Overwrite => report.overwritten.executions += 1,
            PartialAction::Skip => report.skipped.executions += 1,
        }
    }
    for held in &document.authorization {
        match choose(
            &mut report,
            "resource-servers",
            &held.server.server_id,
            &held.server.server_id,
            &resource_servers,
            policy,
        )? {
            PartialAction::New => report.new.resource_servers += 1,
            PartialAction::Overwrite => report.overwritten.resource_servers += 1,
            PartialAction::Skip => report.skipped.resource_servers += 1,
        }
        for resource in &held.resources {
            match choose(
                &mut report,
                "resources",
                &resource.resource_id,
                &resource.name,
                &resources,
                policy,
            )? {
                PartialAction::New => report.new.resources += 1,
                PartialAction::Overwrite => report.overwritten.resources += 1,
                PartialAction::Skip => report.skipped.resources += 1,
            }
        }
        for scope in &held.scopes {
            match choose(
                &mut report,
                "authorization-scopes",
                &scope.scope_id,
                &scope.name,
                &authorization_scopes,
                policy,
            )? {
                PartialAction::New => report.new.authorization_scopes += 1,
                PartialAction::Overwrite => report.overwritten.authorization_scopes += 1,
                PartialAction::Skip => report.skipped.authorization_scopes += 1,
            }
        }
        for policy_model in &held.policies {
            match choose(
                &mut report,
                "policies",
                &policy_model.policy_id,
                &policy_model.terms.name,
                &policies,
                policy,
            )? {
                PartialAction::New => report.new.policies += 1,
                PartialAction::Overwrite => report.overwritten.policies += 1,
                PartialAction::Skip => report.skipped.policies += 1,
            }
        }
    }

    Ok(PartialPlan {
        report,
        roles,
        groups,
        client_scopes,
        protocol_mappers,
        clients,
        organizations,
        flows,
        executions,
        required_actions,
        resource_servers,
        resources,
        authorization_scopes,
        policies,
    })
}

/// Check a configuration document without writing the target realm.
pub async fn preview_partial_import(
    transaction: &Transaction<'_>,
    target: &str,
    document: &ExportedRealm,
    policy: ImportCollisionPolicy,
) -> Result<PartialImportReport, Unportable> {
    Ok(partial_plan(transaction, target, document, policy)
        .await?
        .report)
}

/// Merge a configuration document atomically into an existing realm.
pub async fn import_partial_realm(
    transaction: &Transaction<'_>,
    tenant: &str,
    target: &str,
    mut document: ExportedRealm,
    policy: ImportCollisionPolicy,
) -> Result<PartialImportReport, Unportable> {
    retarget(&mut document, tenant, target);
    let plan = partial_plan(transaction, target, &document, policy).await?;
    if policy == ImportCollisionPolicy::Fail && plan.report.collision_count > 0 {
        return Err(Unportable::Partial(format!(
            "{} collision(s) found; nothing was imported",
            plan.report.collision_count
        )));
    }
    // One change to many people: the role graph and the realm are held in the
    // order a composite edit holds them, and whoever the import reaches is
    // weighed once it has written.
    roles::lock_role_composites(transaction)
        .await
        .map_err(|_| Unportable::Backend)?;
    store::providers::sod::hold_realm(transaction)
        .await
        .map_err(|_| Unportable::Backend)?;
    let mut reached_groups: Vec<String> = Vec::new();
    let mut composite_edges: Vec<(String, String)> = Vec::new();

    for exported in &document.roles {
        match action(
            &plan.roles,
            &exported.role.role_id,
            &exported.role.name,
            policy,
        )? {
            PartialAction::New => roles::create(transaction, &exported.role).await,
            PartialAction::Overwrite => {
                roles::update(transaction, &exported.role).await.map(|_| ())
            }
            PartialAction::Skip => Ok(()),
        }
        .map_err(|_| Unportable::Backend)?;
    }

    for exported in &document.roles {
        if matches!(
            action(
                &plan.roles,
                &exported.role.role_id,
                &exported.role.name,
                policy,
            )?,
            PartialAction::Skip
        ) {
            continue;
        }
        for child_role_id in &exported.composites {
            add_composite_checked(transaction, &exported.role.role_id, child_role_id).await?;
            composite_edges.push((exported.role.role_id.clone(), child_role_id.clone()));
        }
    }

    let mut pending = document.groups.iter().collect::<Vec<_>>();
    let mut created_groups = HashSet::new();
    while !pending.is_empty() {
        let before = pending.len();
        let mut next = Vec::new();
        for exported in pending {
            let parent_ready = exported
                .group
                .parent_id
                .as_deref()
                .map(|parent| plan.groups.ids.contains(parent) || created_groups.contains(parent))
                .unwrap_or(true);
            if !parent_ready {
                next.push(exported);
                continue;
            }
            let group_action = action(
                &plan.groups,
                &exported.group.group_id,
                &exported.group.name,
                policy,
            )?;
            match group_action {
                PartialAction::New => roles::create_group(transaction, &exported.group).await,
                PartialAction::Overwrite => roles::update_group(transaction, &exported.group)
                    .await
                    .map(|_| ()),
                PartialAction::Skip => Ok(()),
            }
            .map_err(|_| Unportable::Backend)?;
            created_groups.insert(exported.group.group_id.clone());
            if !matches!(group_action, PartialAction::Skip) {
                reached_groups.push(exported.group.group_id.clone());
                for role_id in &exported.grants {
                    roles::grant_to_group(transaction, &exported.group.group_id, role_id)
                        .await
                        .map_err(|_| Unportable::Backend)?;
                }
            }
        }
        if next.len() == before {
            return Err(Unportable::Partial(
                "group parents do not resolve in document order".to_owned(),
            ));
        }
        pending = next;
    }

    for exported in &document.client_scopes {
        match action(
            &plan.client_scopes,
            &exported.scope.client_scope_id,
            &exported.scope.name,
            policy,
        )? {
            PartialAction::New => client_scopes::create_scope(transaction, &exported.scope).await,
            PartialAction::Overwrite => client_scopes::update_scope(transaction, &exported.scope)
                .await
                .map(|_| ()),
            PartialAction::Skip => Ok(()),
        }
        .map_err(|_| Unportable::Backend)?;
    }
    for mapper in &document.protocol_mappers {
        match action(
            &plan.protocol_mappers,
            &mapper.mapper_id,
            &mapper.name,
            policy,
        )? {
            PartialAction::New => client_scopes::create_mapper(transaction, mapper).await,
            PartialAction::Overwrite => client_scopes::update_mapper(transaction, mapper)
                .await
                .map(|_| ()),
            PartialAction::Skip => Ok(()),
        }
        .map_err(|_| Unportable::Backend)?;
    }
    for exported in &document.clients {
        match action(
            &plan.clients,
            &exported.client.client_id,
            &exported.client.name,
            policy,
        )? {
            PartialAction::New => clients::create(transaction, &exported.client).await,
            PartialAction::Overwrite => clients::update(transaction, &exported.client)
                .await
                .map(|_| ()),
            PartialAction::Skip => Ok(()),
        }
        .map_err(|_| Unportable::Backend)?;
    }
    for exported in &document.organizations {
        match action(
            &plan.organizations,
            &exported.organization.org_id,
            &exported.organization.name,
            policy,
        )? {
            PartialAction::New => organizations::create(transaction, &exported.organization).await,
            PartialAction::Overwrite => organizations::update(transaction, &exported.organization)
                .await
                .map(|_| ()),
            PartialAction::Skip => Ok(()),
        }
        .map_err(|_| Unportable::Backend)?;
    }
    for action_model in &document.required_actions {
        let name = action_model.action.to_string();
        match action(
            &plan.required_actions,
            &action_model.action_id,
            &name,
            policy,
        )? {
            PartialAction::New => auth_flows::register_action(transaction, action_model).await,
            PartialAction::Overwrite => auth_flows::update_action(transaction, action_model)
                .await
                .map(|_| ()),
            PartialAction::Skip => Ok(()),
        }
        .map_err(|_| Unportable::Backend)?;
    }
    for flow in &document.flows {
        match action(&plan.flows, &flow.flow_id, &flow.alias, policy)? {
            PartialAction::New => auth_flows::create_flow(transaction, flow).await,
            PartialAction::Overwrite => {
                auth_flows::update_flow(transaction, flow).await.map(|_| ())
            }
            PartialAction::Skip => Ok(()),
        }
        .map_err(|_| Unportable::Backend)?;
    }
    transaction
        .execute("SET CONSTRAINTS one_step_per_position DEFERRED", &[])
        .await
        .map_err(|_| Unportable::Backend)?;
    for execution in &document.executions {
        match action(
            &plan.executions,
            &execution.execution_id,
            &execution.alias,
            policy,
        )? {
            PartialAction::New => auth_flows::create_execution(transaction, execution).await,
            PartialAction::Overwrite => auth_flows::update_execution(transaction, execution)
                .await
                .map(|_| ()),
            PartialAction::Skip => Ok(()),
        }
        .map_err(|_| Unportable::Backend)?;
    }

    for exported in &document.client_scopes {
        let scope_action = action(
            &plan.client_scopes,
            &exported.scope.client_scope_id,
            &exported.scope.name,
            policy,
        )?;
        if !matches!(scope_action, PartialAction::Skip) {
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
    }
    for exported in &document.clients {
        let client_action = action(
            &plan.clients,
            &exported.client.client_id,
            &exported.client.name,
            policy,
        )?;
        if !matches!(client_action, PartialAction::Skip) {
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
    }

    for exported in &document.authorization {
        let server_action = action(
            &plan.resource_servers,
            &exported.server.server_id,
            &exported.server.server_id,
            policy,
        )?;
        match server_action {
            PartialAction::New => authz_surface::create_server(transaction, &exported.server).await,
            PartialAction::Overwrite => {
                authz_surface::set_server_mode(transaction, &exported.server)
                    .await
                    .map(|_| ())
            }
            PartialAction::Skip => Ok(()),
        }
        .map_err(|_| Unportable::Backend)?;
        if matches!(server_action, PartialAction::Skip) {
            continue;
        }
        for resource in &exported.resources {
            match action(
                &plan.resources,
                &resource.resource_id,
                &resource.name,
                policy,
            )? {
                PartialAction::New => authz_surface::create_resource(transaction, resource).await,
                PartialAction::Overwrite => authz_surface::update_resource(transaction, resource)
                    .await
                    .map(|_| ()),
                PartialAction::Skip => Ok(()),
            }
            .map_err(|_| Unportable::Backend)?;
        }
        for scope in &exported.scopes {
            match action(
                &plan.authorization_scopes,
                &scope.scope_id,
                &scope.name,
                policy,
            )? {
                PartialAction::New => authz_surface::create_scope(transaction, scope).await,
                PartialAction::Overwrite => authz_surface::update_scope(transaction, scope)
                    .await
                    .map(|_| ()),
                PartialAction::Skip => Ok(()),
            }
            .map_err(|_| Unportable::Backend)?;
        }
        for policy_model in conditions_first(&exported.server.server_id, exported.policies.clone())?
        {
            match action(
                &plan.policies,
                &policy_model.policy_id,
                &policy_model.terms.name,
                policy,
            )? {
                PartialAction::New => authz_policies::create(transaction, &policy_model)
                    .await
                    .map_err(|why| Unportable::Invalid(why.to_string())),
                PartialAction::Overwrite => authz_policies::update(transaction, &policy_model)
                    .await
                    .map(|_| ())
                    .map_err(|why| Unportable::Invalid(why.to_string())),
                PartialAction::Skip => Ok(()),
            }?;
        }
    }

    weigh_import(transaction, &reached_groups, &composite_edges).await?;
    Ok(plan.report)
}

/// Weigh everyone a partial import reached: the people standing in a group it
/// wrote, who hold what the group and those above it carry, and the holders of
/// a role it placed another under. A breach refuses the whole import.
async fn weigh_import(
    transaction: &Transaction<'_>,
    reached_groups: &[String],
    composite_edges: &[(String, String)],
) -> Result<(), Unportable> {
    let mut people: Vec<String> = Vec::new();
    let mut arriving: Vec<String> = Vec::new();
    for group_id in reached_groups {
        people.extend(
            roles::members_at_or_below(transaction, group_id)
                .await
                .map_err(|_| Unportable::Backend)?,
        );
        arriving.extend(
            roles::roles_carried_at_or_above(transaction, group_id)
                .await
                .map_err(|_| Unportable::Backend)?,
        );
    }
    for (parent, child) in composite_edges {
        people.extend(
            roles::holders_of_role(transaction, parent)
                .await
                .map_err(|_| Unportable::Backend)?,
        );
        arriving.push(child.clone());
    }
    people.sort_unstable();
    people.dedup();
    let arriving = roles::roles_reached_from(transaction, &arriving)
        .await
        .map_err(|_| Unportable::Backend)?;
    match crate::sod::weigh_everyone(transaction, &people, &arriving).await {
        Ok(()) => Ok(()),
        Err(crate::sod::Toxic::Refused(said)) => Err(Unportable::Invalid(format!(
            "the import would break a separation of duties: {said}"
        ))),
        Err(crate::sod::Toxic::Backend) => Err(Unportable::Backend),
    }
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
        let composites = roles::composite_children(transaction, &role.role_id)
            .await
            .map_err(|_| Unportable::Backend)?
            .into_iter()
            .map(|child| child.role_id)
            .collect();
        exported_roles.push(ExportedRole {
            role,
            held_by_users,
            composites,
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

async fn add_composite_checked(
    transaction: &Transaction<'_>,
    parent_role_id: &str,
    child_role_id: &str,
) -> Result<(), Unportable> {
    roles::lock_role_composites(transaction)
        .await
        .map_err(|_| Unportable::Backend)?;
    if parent_role_id == child_role_id
        || roles::composite_reaches(transaction, child_role_id, parent_role_id)
            .await
            .map_err(|_| Unportable::Backend)?
    {
        return Err(Unportable::Invalid(
            "role composites contain a cycle".to_owned(),
        ));
    }
    roles::add_composite(transaction, parent_role_id, child_role_id)
        .await
        .map_err(|_| Unportable::Backend)
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
        .map_err(|why| match why {
            store::error::StoreError::AlreadyExists => Unportable::AlreadyExists,
            _ => Unportable::Backend,
        })?;
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
    for exported in &doc.roles {
        for child_role_id in &exported.composites {
            add_composite_checked(transaction, &exported.role.role_id, child_role_id).await?;
        }
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
