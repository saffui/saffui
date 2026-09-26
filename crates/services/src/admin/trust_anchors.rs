use chrono::{DateTime, TimeZone, Utc};
use crypto::provider::{CryptoProvider, HashAlg};
use crypto::x509::{
    CertifiedKey, is_authority, read_certificate_facts, read_pem_certificates, subject_dn,
    subject_key_identifier,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use models::entities::trust_anchors::{TrustAnchor, TrustAnchorRole};
use store::error::StoreError;
use store::providers::realms::trust_anchors;
use store::tenancy::UnitOfWork;

/// How many authorities a realm may trust for one purpose: more than any trust
/// framework names, and a bound on what one verification walks.
pub const MAX_ANCHORS: i64 = 50;

/// Why an authority was not deposited, or not withdrawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Undepositable {
    #[error("send one certificate, PEM encoded")]
    NotOneCertificate,
    #[error(
        "this certificate is not a certification authority's: deposit the authority that issued it"
    )]
    NotAnAuthority,
    #[error("the authority's RSA key is shorter than 2048 bits")]
    WeakKey,
    #[error("this certificate has expired")]
    Expired,
    #[error("this authority is already trusted for that")]
    AlreadyTrusted,
    #[error("a realm trusts at most 50 authorities for one purpose")]
    TooMany,
    #[error("this realm trusts no such authority")]
    NotFound,
    #[error("the authorities could not be read or written")]
    Unwritable,
}

/// Every authority the realm trusts, whatever for.
pub async fn list(transaction: &UnitOfWork) -> Result<Vec<TrustAnchor>, Undepositable> {
    trust_anchors::list(transaction)
        .await
        .map_err(|_| Undepositable::Unwritable)
}

/// Deposit an authority the realm will trust for `role`, refused in words
/// when it could not serve as one.
///
/// Only an authority is taken: a leaf deposited in its issuer's place would
/// anchor no chain but its own, which is rarely what was meant. Its key is
/// weighed, its validity read against `now`, and its fingerprint kept so the
/// same certificate is never trusted twice for one purpose.
pub async fn deposit(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    role: TrustAnchorRole,
    pem: &str,
    by: &str,
    now: DateTime<Utc>,
) -> Result<TrustAnchor, Undepositable> {
    let certificates =
        read_pem_certificates(pem.as_bytes()).ok_or(Undepositable::NotOneCertificate)?;
    let [certificate] =
        <[Vec<u8>; 1]>::try_from(certificates).map_err(|_| Undepositable::NotOneCertificate)?;
    if !is_authority(&certificate) {
        return Err(Undepositable::NotAnAuthority);
    }
    let facts = read_certificate_facts(&certificate).ok_or(Undepositable::NotOneCertificate)?;
    if matches!(facts.key, CertifiedKey::Rsa { bits } if bits < 2048) {
        return Err(Undepositable::WeakKey);
    }
    let not_after = Utc
        .timestamp_opt(facts.not_after, 0)
        .single()
        .ok_or(Undepositable::NotOneCertificate)?;
    if not_after <= now {
        return Err(Undepositable::Expired);
    }
    trust_anchors::hold_deposits(transaction)
        .await
        .map_err(|_| Undepositable::Unwritable)?;
    if trust_anchors::count(transaction, role)
        .await
        .map_err(|_| Undepositable::Unwritable)?
        >= MAX_ANCHORS
    {
        return Err(Undepositable::TooMany);
    }

    let digest = provider
        .digest()
        .hash(HashAlg::Sha256, &certificate)
        .map_err(|_| Undepositable::Unwritable)?;
    let mut drawn = [0u8; 16];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Undepositable::Unwritable)?;
    let anchor = TrustAnchor {
        anchor_id: HEXLOWER.encode(&drawn),
        role,
        fingerprint: HEXLOWER.encode(&digest),
        subject: subject_dn(&certificate).unwrap_or_default(),
        key_identifier: subject_key_identifier(&certificate)
            .map(|identifier| BASE64URL_NOPAD.encode(&identifier)),
        not_after,
        created_by: by.to_owned(),
        created_at: now,
        certificate,
    };
    match trust_anchors::deposit(transaction, &anchor).await {
        Ok(()) => Ok(anchor),
        Err(StoreError::AlreadyExists) => Err(Undepositable::AlreadyTrusted),
        Err(_) => Err(Undepositable::Unwritable),
    }
}

/// Stop trusting one authority.
pub async fn withdraw(transaction: &UnitOfWork, anchor_id: &str) -> Result<(), Undepositable> {
    trust_anchors::withdraw(transaction, anchor_id)
        .await
        .map_err(|_| Undepositable::Unwritable)?
        .then_some(())
        .ok_or(Undepositable::NotFound)
}
