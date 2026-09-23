use crypto::provider::CryptoProvider;
use models::auditable::AuditableModel;
use models::entities::client::{ProtocolMapperModel, ProtocolMapperMutationModel};
use store::providers::{client_scopes, clients};
use store::tenancy::UnitOfWork;

use crate::mappers::KNOWN_TYPES;

/// Why a mapper could not be written. Verified before writing, like the
/// directory: the store underneath flattens every refusal into a backend
/// error.
#[derive(Debug, thiserror::Error)]
pub enum Unwritable {
    #[error("no such mapper")]
    NotFound,
    /// The owner of an attachment, named apart so attaching a real mapper to
    /// a missing scope or client is not reported as the mapper missing.
    #[error("no such scope")]
    NoSuchScope,
    #[error("no such client")]
    NoSuchClient,
    /// A rule this build does not run. Recording it would configure nothing
    /// while looking like it does, so the plane refuses it instead.
    #[error("no rule of this name runs here; one of: {0}")]
    UnknownRule(String),
    /// The rule runs, but its configuration names a key it never reads or
    /// lacks one it cannot work without. Either way the row would sit in the
    /// store reading as configured while writing nothing.
    #[error("{0}")]
    BadRule(#[from] crate::mappers::BadConfig),
    /// Deletion refused while a client holds the mapper or a scope carries
    /// it. Both joins cascade, so deleting anyway would strip the rule from
    /// every token silently rather than the deletion being told no.
    #[error("still attached, so not deleted")]
    StillHeld,
    #[error("the store could not be written")]
    Backend,
}

/// Two questions, in order: is this a rule this build runs, and does its
/// configuration say something that rule would read. The second is worth
/// asking at the door because nothing downstream ever complains: an
/// unreadable key is simply never looked at.
fn check_rule(asked: &ProtocolMapperMutationModel) -> Result<(), Unwritable> {
    if !KNOWN_TYPES.contains(&asked.mapper_type.as_str()) {
        return Err(Unwritable::UnknownRule(KNOWN_TYPES.join(", ")));
    }
    crate::mappers::check_configs(&asked.mapper_type, &asked.configs)?;
    Ok(())
}

fn draw(provider: &dyn CryptoProvider) -> Result<String, Unwritable> {
    let mut bytes = [0_u8; 16];
    provider
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Unwritable::Backend)?;
    Ok(crypto::provider::uuid_from(bytes))
}

pub async fn mappers(transaction: &UnitOfWork) -> Result<Vec<ProtocolMapperModel>, Unwritable> {
    client_scopes::list_mappers(transaction)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn get_mapper(
    transaction: &UnitOfWork,
    mapper_id: &str,
) -> Result<ProtocolMapperModel, Unwritable> {
    client_scopes::load_mapper(transaction, mapper_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)
}

pub async fn create_mapper(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    asked: ProtocolMapperMutationModel,
) -> Result<ProtocolMapperModel, Unwritable> {
    check_rule(&asked)?;
    let mapper = asked.into_model(
        draw(provider)?,
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    client_scopes::create_mapper(transaction, &mapper)
        .await
        .map_err(|_| Unwritable::Backend)?;
    Ok(mapper)
}

pub async fn update_mapper(
    transaction: &UnitOfWork,
    mapper_id: &str,
    by: &str,
    asked: ProtocolMapperMutationModel,
) -> Result<ProtocolMapperModel, Unwritable> {
    check_rule(&asked)?;
    let standing = get_mapper(transaction, mapper_id).await?;
    let mut mapper = asked.into_model(
        mapper_id.to_owned(),
        standing.realm_id.clone(),
        standing.metadata.clone(),
    );
    mapper.metadata.updated_by = Some(by.to_owned());
    if !client_scopes::update_mapper(transaction, &mapper)
        .await
        .map_err(|_| Unwritable::Backend)?
    {
        return Err(Unwritable::NotFound);
    }
    get_mapper(transaction, mapper_id).await
}

pub async fn delete_mapper(transaction: &UnitOfWork, mapper_id: &str) -> Result<(), Unwritable> {
    get_mapper(transaction, mapper_id).await?;
    if client_scopes::mapper_still_attached(transaction, mapper_id)
        .await
        .map_err(|_| Unwritable::Backend)?
    {
        return Err(Unwritable::StillHeld);
    }
    client_scopes::delete_mapper(transaction, mapper_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

async fn scope_exists(transaction: &UnitOfWork, client_scope_id: &str) -> Result<(), Unwritable> {
    client_scopes::load_scope(transaction, client_scope_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .map(|_| ())
        .ok_or(Unwritable::NoSuchScope)
}

async fn client_exists(transaction: &UnitOfWork, client_id: &str) -> Result<(), Unwritable> {
    clients::load(transaction, client_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .map(|_| ())
        .ok_or(Unwritable::NoSuchClient)
}

pub async fn mappers_of_scope(
    transaction: &UnitOfWork,
    client_scope_id: &str,
) -> Result<Vec<ProtocolMapperModel>, Unwritable> {
    scope_exists(transaction, client_scope_id).await?;
    client_scopes::mappers_of_scope(transaction, client_scope_id)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn mappers_of_client(
    transaction: &UnitOfWork,
    client_id: &str,
) -> Result<Vec<ProtocolMapperModel>, Unwritable> {
    client_exists(transaction, client_id).await?;
    client_scopes::mappers_of_client(transaction, client_id)
        .await
        .map_err(|_| Unwritable::Backend)
}

/// Attaching twice is attaching once; the join carries nothing to correct.
pub async fn attach_to_scope(
    transaction: &UnitOfWork,
    client_scope_id: &str,
    mapper_id: &str,
) -> Result<(), Unwritable> {
    scope_exists(transaction, client_scope_id).await?;
    get_mapper(transaction, mapper_id).await?;
    client_scopes::attach_mapper_to_scope(transaction, client_scope_id, mapper_id)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn detach_from_scope(
    transaction: &UnitOfWork,
    client_scope_id: &str,
    mapper_id: &str,
) -> Result<(), Unwritable> {
    scope_exists(transaction, client_scope_id).await?;
    get_mapper(transaction, mapper_id).await?;
    client_scopes::detach_mapper_from_scope(transaction, client_scope_id, mapper_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

pub async fn attach_to_client(
    transaction: &UnitOfWork,
    client_id: &str,
    mapper_id: &str,
) -> Result<(), Unwritable> {
    client_exists(transaction, client_id).await?;
    get_mapper(transaction, mapper_id).await?;
    client_scopes::attach_mapper_to_client(transaction, client_id, mapper_id)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn detach_from_client(
    transaction: &UnitOfWork,
    client_id: &str,
    mapper_id: &str,
) -> Result<(), Unwritable> {
    client_exists(transaction, client_id).await?;
    get_mapper(transaction, mapper_id).await?;
    client_scopes::detach_mapper_from_client(transaction, client_id, mapper_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}
