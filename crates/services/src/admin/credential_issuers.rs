use chrono::{DateTime, Utc};
use crypto::provider::CryptoProvider;
use data_encoding::HEXLOWER;
use models::entities::credential_issuers::{CredentialIssuer, IssuerTrust};
use models::entities::trust_anchors::TrustAnchorRole;
use serde_json::Value;
use store::error::StoreError;
use store::providers::realms::{credential_issuers, trust_anchors};
use store::tenancy::UnitOfWork;

/// How many issuers a realm may name: more than one trust framework lists,
/// and a bound on what one verification looks through.
pub const MAX_ISSUERS: i64 = 50;

/// The longest name an administrator gives an issuer.
pub const MAX_NAME_CHARS: usize = 200;

/// The most authorities an issuer is trusted through, and the most types it
/// is trusted to issue, each of so many characters at most.
pub const MAX_ISSUER_ANCHORS: usize = 10;
pub const MAX_ISSUER_TYPES: usize = 20;
const MAX_TYPE_CHARS: usize = 256;

/// Why an issuer was not named, read again or forgotten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unnamable {
    #[error("give the issuer a name of at most 200 characters")]
    BadName,
    #[error("this issuer is already named in this realm")]
    AlreadyNamed,
    #[error("name the issuer as its credentials name it: an https address")]
    BadIssuer,
    #[error("trust the issuer through one to ten of the authorities this realm trusts")]
    NoAuthority,
    #[error("name the one to twenty credential types the issuer issues")]
    BadTypes,
    #[error("this issuer is trusted by its metadata, not by certificate")]
    NotByCertificate,
    #[error("this issuer is trusted by certificate: it publishes no keys to read")]
    NotByMetadata,
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

/// The authorities an issuer is trusted through, and the types it issues.
pub struct CertificateTrust {
    /// The realm's trust anchors, by identifier.
    pub anchors: Vec<String>,
    /// The credential types it issues, as vct values.
    pub credential_types: Vec<String>,
}

/// Name an issuer the realm trusts by certificate: a credential naming it is
/// then verified by the chain it carries, up to one of the authorities named,
/// and only for the types named. Nothing is read from the issuer.
pub async fn name_by_certificate(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    name: &str,
    issuer: &str,
    trust: CertificateTrust,
    by: &str,
    now: DateTime<Utc>,
) -> Result<CredentialIssuer, Unnamable> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return Err(Unnamable::BadName);
    }
    let issuer = issuer.trim();
    if issuer.chars().count() > 2048 || !commons::address::is_https_or_loopback(issuer) {
        return Err(Unnamable::BadIssuer);
    }
    credential_issuers::hold_names(transaction)
        .await
        .map_err(|_| Unnamable::Unwritable)?;
    let (anchors, credential_types) = check_certificate_trust(transaction, trust).await?;
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
        trust: IssuerTrust::Certificate {
            anchors,
            credential_types,
        },
        created_by: by.to_owned(),
        created_at: now,
    };
    match credential_issuers::name(transaction, &named).await {
        Ok(()) => Ok(named),
        Err(StoreError::AlreadyExists) => Err(Unnamable::AlreadyNamed),
        Err(StoreError::BrokenRule { rule }) if rule == "credential_issuer_anchors_anchor" => {
            Err(Unnamable::NoAuthority)
        }
        Err(_) => Err(Unnamable::Unwritable),
    }
}

/// Trust an issuer the realm trusts by certificate through other authorities,
/// or for other types.
pub async fn replace_certificate_trust(
    transaction: &UnitOfWork,
    issuer_id: &str,
    trust: CertificateTrust,
) -> Result<CredentialIssuer, Unnamable> {
    credential_issuers::hold_names(transaction)
        .await
        .map_err(|_| Unnamable::Unwritable)?;
    let held = named(transaction, issuer_id).await?;
    if !matches!(held.trust, IssuerTrust::Certificate { .. }) {
        return Err(Unnamable::NotByCertificate);
    }
    let (anchors, credential_types) = check_certificate_trust(transaction, trust).await?;
    match credential_issuers::replace_certificate_trust(
        transaction,
        issuer_id,
        &anchors,
        &credential_types,
    )
    .await
    {
        Ok(true) => named(transaction, issuer_id).await,
        Ok(false) => Err(Unnamable::NotFound),
        Err(StoreError::BrokenRule { rule }) if rule == "credential_issuer_anchors_anchor" => {
            Err(Unnamable::NoAuthority)
        }
        Err(_) => Err(Unnamable::Unwritable),
    }
}

/// The authorities and the types as they are kept: each trimmed and named
/// once, the authorities among those the realm trusts for credential issuers.
async fn check_certificate_trust(
    transaction: &UnitOfWork,
    trust: CertificateTrust,
) -> Result<(Vec<String>, Vec<String>), Unnamable> {
    let named_once = |mut names: Vec<String>| {
        names = names
            .into_iter()
            .map(|name| name.trim().to_owned())
            .collect();
        names.sort();
        names.dedup();
        names
    };
    let anchors = named_once(trust.anchors);
    if anchors.is_empty() || anchors.len() > MAX_ISSUER_ANCHORS {
        return Err(Unnamable::NoAuthority);
    }
    let trusted = trust_anchors::list(transaction)
        .await
        .map_err(|_| Unnamable::Unwritable)?;
    let known = |anchor: &String| {
        trusted
            .iter()
            .any(|held| held.anchor_id == *anchor && held.role == TrustAnchorRole::CredentialIssuer)
    };
    if !anchors.iter().all(known) {
        return Err(Unnamable::NoAuthority);
    }
    let credential_types = named_once(trust.credential_types);
    let typed = !credential_types.is_empty()
        && credential_types.len() <= MAX_ISSUER_TYPES
        && credential_types
            .iter()
            .all(|vct| !vct.is_empty() && vct.chars().count() <= MAX_TYPE_CHARS);
    if !typed {
        return Err(Unnamable::BadTypes);
    }
    Ok((anchors, credential_types))
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
