use crypto::provider::CryptoProvider;
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::brokering::{
    ClaimSourceKind, UserClaimSourceModel, UserClaimSourceMutationModel,
};
use store::providers::{brokering, users};

/// Why a source could not be written. Verified before writing; the store
/// underneath flattens every refusal into a backend error.
#[derive(Debug, thiserror::Error)]
pub enum Unwritable {
    #[error("no such user")]
    NoSuchUser,
    #[error("no such claim source")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
    #[error("the store could not be written")]
    Backend,
}

async fn user_exists(transaction: &Transaction<'_>, user_id: &str) -> Result<(), Unwritable> {
    users::load(transaction, user_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .map(|_| ())
        .ok_or(Unwritable::NoSuchUser)
}

pub async fn sources_of(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> Result<Vec<UserClaimSourceModel>, Unwritable> {
    user_exists(transaction, user_id).await?;
    brokering::claim_sources_of(transaction, user_id)
        .await
        .map_err(|_| Unwritable::Backend)
}

/// Refuse what the release would skip over: a source of one kind missing
/// that kind's document, a name no claim could carry, and a name another
/// source of this person already answers for, since only the first would
/// ever speak.
fn check(
    standing: &[UserClaimSourceModel],
    asked: &UserClaimSourceMutationModel,
) -> Result<(), Unwritable> {
    if asked.claims.is_empty() {
        return Err(Unwritable::Invalid(
            "a source answers for at least one claim".to_owned(),
        ));
    }
    if asked
        .claims
        .iter()
        .any(|name| name.trim().is_empty() || name.chars().any(char::is_whitespace))
    {
        return Err(Unwritable::Invalid(
            "a claim name has no spaces and is not blank".to_owned(),
        ));
    }
    for source in standing {
        if let Some(taken) = asked
            .claims
            .iter()
            .find(|name| source.claims.contains(name))
        {
            return Err(Unwritable::Invalid(format!(
                "{taken} is already answered by {}",
                source.source_id
            )));
        }
    }
    match asked.kind {
        ClaimSourceKind::Jwt => {
            let Some(jwt) = asked.jwt.as_deref().filter(|held| !held.is_empty()) else {
                return Err(Unwritable::Invalid(
                    "a jwt source carries the signed document".to_owned(),
                ));
            };
            if jwt.split('.').count() != 3 {
                return Err(Unwritable::Invalid(
                    "the document is a compact JWS: three parts".to_owned(),
                ));
            }
        }
        ClaimSourceKind::Endpoint => {
            let Some(endpoint) = asked.endpoint.as_deref().filter(|held| !held.is_empty()) else {
                return Err(Unwritable::Invalid(
                    "an endpoint source says where to fetch".to_owned(),
                ));
            };
            if !endpoint.starts_with("https://") {
                return Err(Unwritable::Invalid(
                    "a relying party fetches claims over https".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

pub async fn add(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    user_id: &str,
    asked: UserClaimSourceMutationModel,
) -> Result<UserClaimSourceModel, Unwritable> {
    user_exists(transaction, user_id).await?;
    let standing = brokering::claim_sources_of(transaction, user_id)
        .await
        .map_err(|_| Unwritable::Backend)?;
    check(&standing, &asked)?;

    let mut bytes = [0_u8; 16];
    provider
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Unwritable::Backend)?;
    let source = UserClaimSourceModel {
        source_id: format!("src-{}", BASE64URL_NOPAD.encode(&bytes)),
        realm_id: realm_id.to_owned(),
        user_id: user_id.to_owned(),
        claims: asked.claims,
        kind: asked.kind,
        jwt: asked.jwt,
        endpoint: asked.endpoint,
        endpoint_token: asked.endpoint_token,
        metadata: AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    };
    brokering::create_claim_source(transaction, &source)
        .await
        .map_err(|_| Unwritable::Backend)?;
    Ok(source)
}

pub async fn remove(
    transaction: &Transaction<'_>,
    user_id: &str,
    source_id: &str,
) -> Result<(), Unwritable> {
    user_exists(transaction, user_id).await?;
    brokering::delete_claim_source(transaction, user_id, source_id)
        .await
        .map_err(|_| Unwritable::Backend)?
        .then_some(())
        .ok_or(Unwritable::NotFound)
}
