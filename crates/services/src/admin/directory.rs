use crypto::provider::CryptoProvider;
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::authz::{GroupModel, GroupMutationModel, RoleModel, RoleMutationModel};
use models::entities::organization::{OrganizationModel, OrganizationMutationModel};
use models::paging::Page;
use store::providers::{organizations, roles};
use store::query::list_query::ListQuery;

/// Why a role, group or organization could not be written.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum Unwritable {
    #[error("one with this name already exists")]
    AlreadyExists,
    #[error("no such one")]
    NotFound,
    /// Deletion refused while something still holds it. The joins cascade, so
    /// deleting anyway would strip an entitlement from every holder silently
    /// rather than the deletion being told no.
    #[error("still granted, so not deleted")]
    StillHeld,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("the store could not be written")]
    Backend,
}

/// A name callers will spell in URLs and grants: short, printable, no spaces.
fn check_name(name: &str) -> Result<(), Unwritable> {
    let shaped = !name.is_empty()
        && name.len() <= 255
        && !name.chars().any(char::is_whitespace)
        && !name.chars().any(char::is_control);
    shaped.then_some(()).ok_or(Unwritable::Invalid(
        "a name has no spaces and no control characters",
    ))
}

/// A drawn identifier, so a rename never changes what grants point at.
fn draw(provider: &dyn CryptoProvider, prefix: &str) -> Result<String, Unwritable> {
    let mut bytes = [0_u8; 16];
    provider
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Unwritable::Backend)?;
    Ok(format!("{prefix}-{}", BASE64URL_NOPAD.encode(&bytes)))
}

pub async fn create_role(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    asked: RoleMutationModel,
) -> Result<RoleModel, Unwritable> {
    check_name(&asked.name)?;
    if roles::load_by_name(transaction, &asked.name)
        .await
        .map_err(|_| Unwritable::Backend)?
        .is_some()
    {
        return Err(Unwritable::AlreadyExists);
    }
    let role = asked.into_model(
        draw(provider, "role")?,
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    roles::create(transaction, &role)
        .await
        .map_err(|_| Unwritable::Backend)?;
    Ok(role)
}

pub async fn list_roles(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> Result<Page<RoleModel>, Unwritable> {
    roles::list(transaction, query, with_total)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn get_role(
    transaction: &Transaction<'_>,
    role_id: &str,
) -> Result<RoleModel, Unwritable> {
    roles::load(transaction, role_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)
}

/// Rewrite what a role says about itself. Renaming keeps the identity, so
/// everything granted keeps meaning what it meant; the new name still has to
/// be free.
pub async fn update_role(
    transaction: &Transaction<'_>,
    role_id: &str,
    by: &str,
    asked: RoleMutationModel,
) -> Result<RoleModel, Unwritable> {
    check_name(&asked.name)?;
    let mut role = get_role(transaction, role_id).await?;
    if role.name != asked.name
        && roles::load_by_name(transaction, &asked.name)
            .await
            .map_err(|_| Unwritable::Backend)?
            .is_some()
    {
        return Err(Unwritable::AlreadyExists);
    }
    // The owner is set at creation and not editable: moving a role between a
    // client and the realm would change what its grants mean.
    role.name = asked.name;
    role.display_name = asked.display_name;
    role.description = asked.description;
    role.admin_actions = asked.admin_actions;
    role.metadata.updated_by = Some(by.to_owned());
    roles::update(transaction, &role)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(role)
        .ok_or(Unwritable::NotFound)
}

pub async fn delete_role(transaction: &Transaction<'_>, role_id: &str) -> Result<(), Unwritable> {
    get_role(transaction, role_id).await?;
    if roles::role_still_held(transaction, role_id)
        .await
        .map_err(|_| Unwritable::Backend)?
    {
        return Err(Unwritable::StillHeld);
    }
    roles::delete(transaction, role_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

pub async fn create_group(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    asked: GroupMutationModel,
) -> Result<GroupModel, Unwritable> {
    check_name(&asked.name)?;
    if roles::load_group_by_name(transaction, &asked.name)
        .await
        .map_err(|_| Unwritable::Backend)?
        .is_some()
    {
        return Err(Unwritable::AlreadyExists);
    }
    let group = asked.into_model(
        draw(provider, "group")?,
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    roles::create_group(transaction, &group)
        .await
        .map_err(|_| Unwritable::Backend)?;
    Ok(group)
}

pub async fn list_groups(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> Result<Page<GroupModel>, Unwritable> {
    roles::list_groups(transaction, query, with_total)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn get_group(
    transaction: &Transaction<'_>,
    group_id: &str,
) -> Result<GroupModel, Unwritable> {
    roles::load_group(transaction, group_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)
}

pub async fn update_group(
    transaction: &Transaction<'_>,
    group_id: &str,
    by: &str,
    asked: GroupMutationModel,
) -> Result<GroupModel, Unwritable> {
    check_name(&asked.name)?;
    let mut group = get_group(transaction, group_id).await?;
    if group.name != asked.name
        && roles::load_group_by_name(transaction, &asked.name)
            .await
            .map_err(|_| Unwritable::Backend)?
            .is_some()
    {
        return Err(Unwritable::AlreadyExists);
    }
    group.name = asked.name;
    group.display_name = asked.display_name;
    group.description = asked.description;
    group.is_default = asked.is_default;
    group.metadata.updated_by = Some(by.to_owned());
    roles::update_group(transaction, &group)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(group)
        .ok_or(Unwritable::NotFound)
}

pub async fn delete_group(transaction: &Transaction<'_>, group_id: &str) -> Result<(), Unwritable> {
    get_group(transaction, group_id).await?;
    if roles::group_still_held(transaction, group_id)
        .await
        .map_err(|_| Unwritable::Backend)?
    {
        return Err(Unwritable::StillHeld);
    }
    roles::delete_group(transaction, group_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

pub async fn create_organization(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    asked: OrganizationMutationModel,
) -> Result<OrganizationModel, Unwritable> {
    check_name(&asked.name)?;
    if organizations::load_by_name(transaction, &asked.name)
        .await
        .map_err(|_| Unwritable::Backend)?
        .is_some()
    {
        return Err(Unwritable::AlreadyExists);
    }
    let org = asked.into_model(
        draw(provider, "org")?,
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    organizations::create(transaction, &org)
        .await
        .map_err(|_| Unwritable::Backend)?;
    Ok(org)
}

pub async fn list_organizations(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> Result<Page<OrganizationModel>, Unwritable> {
    organizations::list(transaction, query, with_total)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn get_organization(
    transaction: &Transaction<'_>,
    org_id: &str,
) -> Result<OrganizationModel, Unwritable> {
    organizations::load(transaction, org_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)
}

pub async fn update_organization(
    transaction: &Transaction<'_>,
    org_id: &str,
    by: &str,
    asked: OrganizationMutationModel,
) -> Result<OrganizationModel, Unwritable> {
    check_name(&asked.name)?;
    let mut org = get_organization(transaction, org_id).await?;
    if org.name != asked.name
        && organizations::load_by_name(transaction, &asked.name)
            .await
            .map_err(|_| Unwritable::Backend)?
            .is_some()
    {
        return Err(Unwritable::AlreadyExists);
    }
    org.name = asked.name;
    org.display_name = asked.display_name;
    org.description = asked.description;
    org.enabled = asked.enabled;
    org.redirect_url = asked.redirect_url;
    org.attributes = asked.attributes;
    org.metadata.updated_by = Some(by.to_owned());
    organizations::update(transaction, &org)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(org)
        .ok_or(Unwritable::NotFound)
}

/// Deleting an organization is deliberately unguarded by membership: the rows
/// confining policies to it cascade, and a policy confined to a gone
/// organization is muted rather than widened, which the evaluator already
/// holds. Members lose a label, not an entitlement.
pub async fn delete_organization(
    transaction: &Transaction<'_>,
    org_id: &str,
) -> Result<(), Unwritable> {
    get_organization(transaction, org_id).await?;
    organizations::delete(transaction, org_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}
