use crypto::provider::CryptoProvider;
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::authz::{
    DecisionStrategy, PolicyEnforcementMode, PolicyModel, PolicyTerms, ResourceModel,
    ResourceMutationModel, ResourceServerModel, ScopeModel, ScopeMutationModel, StoredPolicy,
};
use store::error::StoreError;
use store::providers::{authz_policies, authz_surface, clients};

/// Why the authorization surface could not be written.
///
/// Unlike the directory, whose store flattens every refusal, this store speaks:
/// cycles, unusable windows, unread bindings and empty policies are all named
/// before the first write. The manager's job is to carry those words out, not
/// to restate them.
#[derive(Debug, thiserror::Error)]
pub enum Unwritable {
    #[error("no such client to protect")]
    NoSuchClient,
    #[error("this client is already a protected application")]
    AlreadyProtected,
    #[error("no such one")]
    NotFound,
    /// A deletion refused because something still reads what it names.
    #[error("{0}")]
    StillRead(String),
    /// The store's own sentence for a write it refused.
    #[error("{0}")]
    Refused(String),
    #[error("the store could not be written")]
    Backend,
}

/// The store's refusals, sorted by what a caller can do about them.
fn carried(why: StoreError) -> Unwritable {
    match why {
        StoreError::NotFound { .. } => Unwritable::NotFound,
        StoreError::PolicyIsACondition { .. } => Unwritable::StillRead(why.to_string()),
        StoreError::UnboundMember { .. }
        | StoreError::EmptyPolicy { .. }
        | StoreError::UnconditionalPermission
        | StoreError::UnappliedPermission
        | StoreError::UnreadBinding { .. }
        | StoreError::UnusableWindow { .. }
        | StoreError::BadPattern(_)
        | StoreError::PolicyKindChanged
        | StoreError::PolicyCycle { .. } => Unwritable::Refused(why.to_string()),
        _ => Unwritable::Backend,
    }
}

fn draw(provider: &dyn CryptoProvider, prefix: &str) -> Result<String, Unwritable> {
    let mut bytes = [0_u8; 16];
    provider
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Unwritable::Backend)?;
    Ok(format!("{prefix}-{}", BASE64URL_NOPAD.encode(&bytes)))
}

/// Declare a client a protected application. The identity is the client's own,
/// which is what the schema holds by key: a server that is not a client is not
/// a server.
pub async fn protect(
    transaction: &Transaction<'_>,
    tenant: &str,
    realm_id: &str,
    by: &str,
    client_id: &str,
    enforcement_mode: PolicyEnforcementMode,
    decision_strategy: DecisionStrategy,
) -> Result<ResourceServerModel, Unwritable> {
    clients::load(transaction, client_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NoSuchClient)?;
    if authz_surface::load_server(transaction, client_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .is_some()
    {
        return Err(Unwritable::AlreadyProtected);
    }
    let server = ResourceServerModel {
        server_id: client_id.to_owned(),
        realm_id: realm_id.to_owned(),
        enforcement_mode,
        decision_strategy,
        remote_resource_management: false,
        user_managed_access: false,
        metadata: AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    };
    authz_surface::create_server(transaction, &server)
        .await
        .map_err(carried)?;
    Ok(server)
}

pub async fn server(
    transaction: &Transaction<'_>,
    server_id: &str,
) -> Result<ResourceServerModel, Unwritable> {
    authz_surface::load_server(transaction, server_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)
}

pub async fn set_mode(
    transaction: &Transaction<'_>,
    server_id: &str,
    by: &str,
    enforcement_mode: PolicyEnforcementMode,
    decision_strategy: DecisionStrategy,
) -> Result<ResourceServerModel, Unwritable> {
    let mut held = server(transaction, server_id).await?;
    held.enforcement_mode = enforcement_mode;
    held.decision_strategy = decision_strategy;
    held.metadata.updated_by = Some(by.to_owned());
    authz_surface::set_server_mode(transaction, &held)
        .await
        .map_err(carried)?
        .then_some(held)
        .ok_or(Unwritable::NotFound)
}

/// Take the surface down: bindings first, then the rows. The condition edge
/// does not cascade, so a server deleted around its policies would leave
/// conditions read by nothing.
pub async fn unprotect(transaction: &Transaction<'_>, server_id: &str) -> Result<(), Unwritable> {
    server(transaction, server_id).await?;
    authz_policies::unbind_server(transaction, server_id)
        .await
        .map_err(carried)?;
    authz_surface::delete_server(transaction, server_id)
        .await
        .map_err(carried)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

pub async fn add_resource(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    server_id: &str,
    asked: ResourceMutationModel,
) -> Result<ResourceModel, Unwritable> {
    server(transaction, server_id).await?;
    let resource = asked.into_model(
        draw(provider, "resource")?,
        server_id.to_owned(),
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    authz_surface::create_resource(transaction, &resource)
        .await
        .map_err(carried)?;
    Ok(resource)
}

pub async fn resources(
    transaction: &Transaction<'_>,
    server_id: &str,
) -> Result<Vec<ResourceModel>, Unwritable> {
    server(transaction, server_id).await?;
    authz_surface::resources_of_server(transaction, server_id)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn remove_resource(
    transaction: &Transaction<'_>,
    resource_id: &str,
) -> Result<(), Unwritable> {
    authz_surface::delete_resource(transaction, resource_id)
        .await
        .map_err(carried)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

pub async fn add_scope(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    server_id: &str,
    asked: ScopeMutationModel,
) -> Result<ScopeModel, Unwritable> {
    server(transaction, server_id).await?;
    let scope = asked.into_model(
        draw(provider, "scope")?,
        server_id.to_owned(),
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    authz_surface::create_scope(transaction, &scope)
        .await
        .map_err(carried)?;
    Ok(scope)
}

pub async fn scopes(
    transaction: &Transaction<'_>,
    server_id: &str,
) -> Result<Vec<ScopeModel>, Unwritable> {
    server(transaction, server_id).await?;
    authz_surface::scopes_of_server(transaction, server_id)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn remove_scope(transaction: &Transaction<'_>, scope_id: &str) -> Result<(), Unwritable> {
    authz_surface::delete_scope(transaction, scope_id)
        .await
        .map_err(carried)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

/// Write a policy under everything the store refuses at the door: an empty
/// one, an unconditional permission, an unread binding, a cycle. The terms are
/// the wire shape; the identities come from here.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one policy"
)]
pub async fn add_policy(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    server_id: &str,
    org_id: Option<String>,
    terms: PolicyTerms,
) -> Result<PolicyModel, Unwritable> {
    server(transaction, server_id).await?;
    let policy = terms.into_model(
        draw(provider, "policy")?,
        server_id.to_owned(),
        realm_id.to_owned(),
        org_id,
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    authz_policies::create(transaction, &policy)
        .await
        .map_err(carried)?;
    Ok(policy)
}

/// Every policy of the server, the unreadable ones named rather than dropped.
pub async fn policies(
    transaction: &Transaction<'_>,
    server_id: &str,
) -> Result<Vec<StoredPolicy>, Unwritable> {
    server(transaction, server_id).await?;
    authz_policies::list_for_server(transaction, server_id)
        .await
        .map_err(|_| Unwritable::Backend)
}

/// Rewrite a policy's terms. The identity and the kind stay: the store refuses
/// a rewrite that would make it decide on something else.
pub async fn rework_policy(
    transaction: &Transaction<'_>,
    server_id: &str,
    policy_id: &str,
    by: &str,
    terms: PolicyTerms,
) -> Result<PolicyModel, Unwritable> {
    let held = match authz_policies::load(transaction, server_id, policy_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)?
    {
        StoredPolicy::Read(policy) => policy,
        // A row nothing can read is still a row an administrator may rewrite:
        // that is how one is repaired.
        StoredPolicy::Unreadable { .. } => {
            return Err(Unwritable::Refused(
                "this policy's rule cannot be read; delete it rather than editing it".to_owned(),
            ));
        }
    };
    let mut policy = held;
    policy.terms = terms;
    policy.metadata.updated_by = Some(by.to_owned());
    authz_policies::update(transaction, &policy)
        .await
        .map_err(carried)?
        .then_some(policy)
        .ok_or(Unwritable::NotFound)
}

pub async fn remove_policy(
    transaction: &Transaction<'_>,
    policy_id: &str,
) -> Result<(), Unwritable> {
    authz_policies::delete(transaction, policy_id)
        .await
        .map_err(carried)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}
