use crypto::provider::CryptoProvider;
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::client::{ClientScopeModel, ClientScopeMutationModel};
use store::providers::{client_scopes, clients};

/// Why a scope could not be written. The store underneath flattens every
/// refusal into a backend error, so this manager verifies before writing,
/// like the directory's and unlike the authorization one.
#[derive(Debug, thiserror::Error)]
pub enum Unwritable {
    #[error("one with this name already exists for this protocol")]
    AlreadyExists,
    #[error("no such scope")]
    NotFound,
    /// The other end of an attachment: named apart so attaching a real scope
    /// to a missing client is not reported as the scope missing.
    #[error("no such client")]
    NoSuchClient,
    /// Deletion refused while a client holds the scope or a policy reads it.
    /// Both joins cascade, so deleting anyway would strip the scope from
    /// every holder silently rather than the deletion being told no.
    #[error("still attached, so not deleted")]
    StillHeld,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("the store could not be written")]
    Backend,
}

/// A name requests will spell in the space-delimited `scope` parameter, where
/// whitespace is the separator: a name containing any could never be asked
/// for whole.
fn check_name(name: &str) -> Result<(), Unwritable> {
    let shaped = !name.is_empty()
        && name.len() <= 255
        && !name.chars().any(char::is_whitespace)
        && !name.chars().any(char::is_control);
    shaped.then_some(()).ok_or(Unwritable::Invalid(
        "a name has no spaces and no control characters",
    ))
}

/// A drawn identifier, so a rename never changes what attachments point at.
fn draw(provider: &dyn CryptoProvider) -> Result<String, Unwritable> {
    let mut bytes = [0_u8; 16];
    provider
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Unwritable::Backend)?;
    Ok(format!("scope-{}", BASE64URL_NOPAD.encode(&bytes)))
}

pub async fn scopes(transaction: &Transaction<'_>) -> Result<Vec<ClientScopeModel>, Unwritable> {
    client_scopes::list_scopes(transaction)
        .await
        .map_err(|_| Unwritable::Backend)
}

pub async fn get_scope(
    transaction: &Transaction<'_>,
    client_scope_id: &str,
) -> Result<ClientScopeModel, Unwritable> {
    client_scopes::load_scope(transaction, client_scope_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .ok_or(Unwritable::NotFound)
}

pub async fn create_scope(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    asked: ClientScopeMutationModel,
) -> Result<ClientScopeModel, Unwritable> {
    check_name(&asked.name)?;
    if client_scopes::load_scope_by_name(transaction, asked.protocol, &asked.name)
        .await
        .map_err(|_| Unwritable::Backend)?
        .is_some()
    {
        return Err(Unwritable::AlreadyExists);
    }

    let scope = asked.into_model(
        draw(provider)?,
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    client_scopes::create_scope(transaction, &scope)
        .await
        .map_err(|_| Unwritable::Backend)?;
    Ok(scope)
}

pub async fn update_scope(
    transaction: &Transaction<'_>,
    client_scope_id: &str,
    by: &str,
    asked: ClientScopeMutationModel,
) -> Result<ClientScopeModel, Unwritable> {
    check_name(&asked.name)?;
    let standing = get_scope(transaction, client_scope_id).await?;

    // The name is only contested when it moves: a rewrite keeping its own
    // name would otherwise be refused for colliding with itself.
    if (asked.protocol, asked.name.as_str()) != (standing.protocol, standing.name.as_str())
        && client_scopes::load_scope_by_name(transaction, asked.protocol, &asked.name)
            .await
            .map_err(|_| Unwritable::Backend)?
            .is_some()
    {
        return Err(Unwritable::AlreadyExists);
    }

    let mut scope = asked.into_model(
        client_scope_id.to_owned(),
        standing.realm_id.clone(),
        standing.metadata.clone(),
    );
    scope.metadata.updated_by = Some(by.to_owned());
    if !client_scopes::update_scope(transaction, &scope)
        .await
        .map_err(|_| Unwritable::Backend)?
    {
        return Err(Unwritable::NotFound);
    }
    get_scope(transaction, client_scope_id).await
}

pub async fn delete_scope(
    transaction: &Transaction<'_>,
    client_scope_id: &str,
) -> Result<(), Unwritable> {
    get_scope(transaction, client_scope_id).await?;
    if client_scopes::scope_still_attached(transaction, client_scope_id)
        .await
        .map_err(|_| Unwritable::Backend)?
    {
        return Err(Unwritable::StillHeld);
    }
    client_scopes::delete_scope(transaction, client_scope_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}

async fn client_exists(transaction: &Transaction<'_>, client_id: &str) -> Result<(), Unwritable> {
    clients::load(transaction, client_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .map(|_| ())
        .ok_or(Unwritable::NoSuchClient)
}

/// The scopes a client holds, each marked optional or not.
pub async fn scopes_of_client(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> Result<Vec<(ClientScopeModel, bool)>, Unwritable> {
    client_exists(transaction, client_id).await?;
    client_scopes::scopes_of_client(transaction, client_id)
        .await
        .map_err(|_| Unwritable::Backend)
}

/// Give a client a scope. Attaching again corrects how it is held.
pub async fn attach_scope(
    transaction: &Transaction<'_>,
    client_id: &str,
    client_scope_id: &str,
    optional: bool,
) -> Result<(), Unwritable> {
    client_exists(transaction, client_id).await?;
    get_scope(transaction, client_scope_id).await?;
    client_scopes::attach_scope(transaction, client_id, client_scope_id, optional)
        .await
        .map_err(|_| Unwritable::Backend)
}

/// Take a scope away from a client. An attachment that was never made is
/// reported missing rather than silently confirmed.
pub async fn detach_scope(
    transaction: &Transaction<'_>,
    client_id: &str,
    client_scope_id: &str,
) -> Result<(), Unwritable> {
    client_exists(transaction, client_id).await?;
    get_scope(transaction, client_scope_id).await?;
    client_scopes::detach_scope(transaction, client_id, client_scope_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}
