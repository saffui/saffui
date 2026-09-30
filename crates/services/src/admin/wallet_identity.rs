//! How a realm knows people by a credential their wallet presents: the one
//! credential a login asks for, the issuer that vouches for identities, and
//! the claim that identifies somebody.

use chrono::{DateTime, Utc};
use crypto::provider::CryptoProvider;
use serde_json::{Value, json};
use store::keyring::Signing;
use store::providers::realms::credential_issuers;
use store::providers::realms::wallet_identity;
pub use store::providers::realms::wallet_identity::WalletIdentity;
use store::tenancy::UnitOfWork;

use crate::verifier::presentation::{Unaskable, check_query};

/// How long the key an identity is digested under is, in bytes.
const DIGEST_KEY_BYTES: usize = 32;

/// Why a profile was not kept or read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unsettable {
    #[error("this realm does not know people by a wallet credential")]
    NotFound,
    #[error("{0}")]
    NotAQuery(&'static str),
    #[error("no issuer this realm names answers to {0}")]
    UnknownIssuer(String),
    #[error("the identifier is one of the claims the credential is asked for, by its path")]
    NotAClaimAsked,
    #[error("the profile could not be read or written")]
    Unwritable,
}

/// What an administrator wrote.
pub struct Wanted {
    pub credential_query: Value,
    pub issuer: String,
    pub identifier_path: Vec<String>,
}

pub async fn read(transaction: &UnitOfWork) -> Result<WalletIdentity, Unsettable> {
    wallet_identity::load(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .ok_or(Unsettable::NotFound)
}

/// Keep how the realm knows people. The credential is one this verifier can
/// check, the issuer one the realm names, and the identifier a claim the
/// credential is asked for: a claim left out of the query is one a wallet
/// never discloses. The key identities are digested under is drawn the first
/// time and kept through every rewrite.
pub async fn write(
    transaction: &UnitOfWork,
    signing: &Signing<'_>,
    wanted: Wanted,
    by: &str,
    now: DateTime<Utc>,
) -> Result<WalletIdentity, Unsettable> {
    check_query(&json!({ "credentials": [wanted.credential_query] })).map_err(|why| match why {
        Unaskable::NotAQuery(said) => Unsettable::NotAQuery(said),
        _ => Unsettable::Unwritable,
    })?;
    let issuer = wanted.issuer.trim().to_owned();
    if credential_issuers::by_issuer(transaction, &issuer)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .is_none()
    {
        return Err(Unsettable::UnknownIssuer(issuer));
    }
    let asked_for = wanted
        .credential_query
        .get("claims")
        .and_then(Value::as_array)
        .is_some_and(|claims| {
            claims
                .iter()
                .any(|claim| claim.get("path") == Some(&json!(wanted.identifier_path)))
        });
    if !asked_for {
        return Err(Unsettable::NotAClaimAsked);
    }

    let profile = WalletIdentity {
        credential_query: wanted.credential_query,
        issuer,
        identifier_path: wanted.identifier_path,
        updated_by: by.to_owned(),
        updated_at: now,
    };
    let drawn = draw_digest_key(signing.provider)?;
    wallet_identity::keep(
        transaction,
        signing.ring,
        signing.envelope,
        &profile,
        &drawn,
    )
    .await
    .map_err(|_| Unsettable::Unwritable)?;
    Ok(profile)
}

fn draw_digest_key(provider: &dyn CryptoProvider) -> Result<[u8; DIGEST_KEY_BYTES], Unsettable> {
    let mut drawn = [0u8; DIGEST_KEY_BYTES];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unsettable::Unwritable)?;
    Ok(drawn)
}
