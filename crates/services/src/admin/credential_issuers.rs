use chrono::{DateTime, Utc};
use crypto::provider::CryptoProvider;
use data_encoding::HEXLOWER;
use models::entities::credential_issuers::{CredentialIssuer, IssuerTrust};
use serde_json::Value;
use store::error::StoreError;
use store::providers::realms::credential_issuers;
use store::tenancy::UnitOfWork;

/// How many issuers a realm may name: more than one trust framework lists,
/// and a bound on what one verification looks through.
pub const MAX_ISSUERS: i64 = 50;

/// The longest name an administrator gives an issuer.
pub const MAX_NAME_CHARS: usize = 200;

/// Why an issuer was not named, read again or forgotten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unnamable {
    #[error("give the issuer a name of at most 200 characters")]
    BadName,
    #[error("this issuer is already named in this realm")]
    AlreadyNamed,
    #[error("a realm names at most 50 credential issuers")]
    TooMany,
    #[error("this realm names no such credential issuer")]
    NotFound,
    #[error("the credential issuers could not be read or written")]
    Unwritable,
}

/// The keys read from an issuer, and where they were read.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadKeys {
    pub keys: Vec<Value>,
    pub read_from: String,
}

/// Every issuer the realm names.
pub async fn list(transaction: &UnitOfWork) -> Result<Vec<CredentialIssuer>, Unnamable> {
    credential_issuers::list(transaction)
        .await
        .map_err(|_| Unnamable::Unwritable)
}

/// One issuer the realm names.
pub async fn named(
    transaction: &UnitOfWork,
    issuer_id: &str,
) -> Result<CredentialIssuer, Unnamable> {
    credential_issuers::load(transaction, issuer_id)
        .await
        .map_err(|_| Unnamable::Unwritable)?
        .ok_or(Unnamable::NotFound)
}

/// Name an issuer, with the keys already read from it.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one issuer"
)]
pub async fn name(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    name: &str,
    issuer: &str,
    read: ReadKeys,
    by: &str,
    now: DateTime<Utc>,
) -> Result<CredentialIssuer, Unnamable> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return Err(Unnamable::BadName);
    }
    credential_issuers::hold_names(transaction)
        .await
        .map_err(|_| Unnamable::Unwritable)?;
    if credential_issuers::count(transaction)
        .await
        .map_err(|_| Unnamable::Unwritable)?
        >= MAX_ISSUERS
    {
        return Err(Unnamable::TooMany);
    }
    let mut drawn = [0u8; 16];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unnamable::Unwritable)?;
    let named = CredentialIssuer {
        issuer_id: HEXLOWER.encode(&drawn),
        name: name.to_owned(),
        issuer: issuer.to_owned(),
        trust: IssuerTrust::Metadata {
            keys: read.keys,
            read_from: read.read_from,
            read_at: now,
        },
        created_by: by.to_owned(),
        created_at: now,
    };
    match credential_issuers::name(transaction, &named).await {
        Ok(()) => Ok(named),
        Err(StoreError::AlreadyExists) => Err(Unnamable::AlreadyNamed),
        Err(_) => Err(Unnamable::Unwritable),
    }
}

/// Keep the keys read from an issuer again.
pub async fn read_again(
    transaction: &UnitOfWork,
    issuer_id: &str,
    read: ReadKeys,
    now: DateTime<Utc>,
) -> Result<CredentialIssuer, Unnamable> {
    if !credential_issuers::replace_keys(transaction, issuer_id, &read.keys, &read.read_from, &now)
        .await
        .map_err(|_| Unnamable::Unwritable)?
    {
        return Err(Unnamable::NotFound);
    }
    named(transaction, issuer_id).await
}

/// Stop naming one issuer.
pub async fn forget(transaction: &UnitOfWork, issuer_id: &str) -> Result<(), Unnamable> {
    credential_issuers::forget(transaction, issuer_id)
        .await
        .map_err(|_| Unnamable::Unwritable)?
        .then_some(())
        .ok_or(Unnamable::NotFound)
}
