use std::collections::HashMap;

use chrono::{DateTime, Utc};
use crypto::provider::{CryptoProvider, HashAlg};
use data_encoding::HEXLOWER;
use jsonld::built_in::{HeldContexts, built_in_contexts};
use jsonld::json::parse_strict;
use jsonld::{Unreadable, check_context_document};
use models::entities::jsonld_contexts::JsonLdContext;
use serde_json::Value;
use store::error::StoreError;
use store::providers::realms::jsonld_contexts;
use store::tenancy::UnitOfWork;

/// How many contexts a realm may pin: more than its issuers' credentials name,
/// and a bound on what one presentation is read under.
pub const MAX_CONTEXTS: i64 = 50;

/// The longest address a context is pinned under.
pub const MAX_URL_CHARS: usize = 2048;

/// Why a context was not pinned, read again or unpinned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unpinnable {
    #[error("pin a context by an absolute http or https address of at most 2048 characters")]
    BadUrl,
    #[error("this context is built in, and every realm holds it")]
    BuiltIn,
    #[error("the document read there is no context this server reads: {0}")]
    Unreadable(Unreadable),
    #[error("this context is already pinned in this realm")]
    AlreadyPinned,
    #[error("a realm pins at most 50 contexts")]
    TooMany,
    #[error("this realm pins no such context")]
    NotFound,
    #[error("the contexts could not be read or written")]
    Unwritable,
}

/// The contexts built into the server, by the address documents name them with.
pub fn built_in_urls() -> Vec<String> {
    let mut urls: Vec<String> = built_in_contexts().keys().cloned().collect();
    urls.sort();
    urls
}

/// Every context the realm pins.
pub async fn list(transaction: &UnitOfWork) -> Result<Vec<JsonLdContext>, Unpinnable> {
    jsonld_contexts::list(transaction)
        .await
        .map_err(|_| Unpinnable::Unwritable)
}

/// One context the realm pins.
pub async fn pinned(
    transaction: &UnitOfWork,
    context_id: &str,
) -> Result<JsonLdContext, Unpinnable> {
    jsonld_contexts::load(transaction, context_id)
        .await
        .map_err(|_| Unpinnable::Unwritable)?
        .ok_or(Unpinnable::NotFound)
}

/// Whether `url` is one a context may be pinned under. The egress policy then
/// decides whether the server may read it.
pub fn check_url(url: &str) -> Result<(), Unpinnable> {
    // An http or https address always carries a host: the parser refuses one
    // without.
    let absolute = url.chars().count() <= MAX_URL_CHARS
        && url::Url::parse(url).is_ok_and(|parsed| matches!(parsed.scheme(), "http" | "https"));
    if !absolute {
        return Err(Unpinnable::BadUrl);
    }
    if built_in_contexts().contains_key(url) {
        return Err(Unpinnable::BuiltIn);
    }
    Ok(())
}

/// Pin a context, with the document already read for it. The document must
/// read the way a document naming it would read it, under the contexts built
/// in and those the realm already pins.
pub async fn pin(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    url: &str,
    document: &str,
    by: &str,
    now: DateTime<Utc>,
) -> Result<JsonLdContext, Unpinnable> {
    check_url(url)?;
    jsonld_contexts::hold_pins(transaction)
        .await
        .map_err(|_| Unpinnable::Unwritable)?;
    if jsonld_contexts::count(transaction)
        .await
        .map_err(|_| Unpinnable::Unwritable)?
        >= MAX_CONTEXTS
    {
        return Err(Unpinnable::TooMany);
    }
    check_document(transaction, document).await?;
    let mut drawn = [0u8; 16];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unpinnable::Unwritable)?;
    let context = JsonLdContext {
        context_id: HEXLOWER.encode(&drawn),
        url: url.to_owned(),
        digest: digest_of(provider, document)?,
        octets: i32::try_from(document.len()).map_err(|_| Unpinnable::Unwritable)?,
        read_at: now,
        created_by: by.to_owned(),
        created_at: now,
    };
    match jsonld_contexts::pin(transaction, &context, document).await {
        Ok(()) => Ok(context),
        Err(StoreError::AlreadyExists) => Err(Unpinnable::AlreadyPinned),
        Err(_) => Err(Unpinnable::Unwritable),
    }
}

/// Keep the document read for a context again, once it reads.
pub async fn read_again(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    context_id: &str,
    document: &str,
    now: DateTime<Utc>,
) -> Result<JsonLdContext, Unpinnable> {
    check_document(transaction, document).await?;
    let digest = digest_of(provider, document)?;
    if !jsonld_contexts::replace_document(transaction, context_id, document, &digest, &now)
        .await
        .map_err(|_| Unpinnable::Unwritable)?
    {
        return Err(Unpinnable::NotFound);
    }
    pinned(transaction, context_id).await
}

/// Unpin one context.
pub async fn forget(transaction: &UnitOfWork, context_id: &str) -> Result<(), Unpinnable> {
    jsonld_contexts::forget(transaction, context_id)
        .await
        .map_err(|_| Unpinnable::Unwritable)?
        .then_some(())
        .ok_or(Unpinnable::NotFound)
}

/// The documents the realm pins, read, by the address documents name them with.
pub async fn pinned_documents(
    transaction: &UnitOfWork,
) -> Result<HashMap<String, Value>, Unpinnable> {
    Ok(jsonld_contexts::documents(transaction)
        .await
        .map_err(|_| Unpinnable::Unwritable)?
        .into_iter()
        .filter_map(|(url, document)| Some((url, parse_strict(document.as_bytes()).ok()?)))
        .collect())
}

async fn check_document(transaction: &UnitOfWork, document: &str) -> Result<(), Unpinnable> {
    let read = parse_strict(document.as_bytes()).map_err(Unpinnable::Unreadable)?;
    let pinned = pinned_documents(transaction).await?;
    check_context_document(&read, &HeldContexts::new(&pinned)).map_err(Unpinnable::Unreadable)
}

fn digest_of(provider: &dyn CryptoProvider, document: &str) -> Result<String, Unpinnable> {
    provider
        .digest()
        .hash(HashAlg::Sha256, document.as_bytes())
        .map(|digest| HEXLOWER.encode(&digest))
        .map_err(|_| Unpinnable::Unwritable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_context_is_pinned_by_an_absolute_http_address_not_built_in() {
        assert_eq!(check_url("https://issuer.example/contexts/v1.json"), Ok(()));
        assert_eq!(check_url("http://127.0.0.1:8080/context"), Ok(()));
        for url in [
            "ftp://issuer.example/context",
            "/contexts/v1.json",
            "https://",
            "did:web:issuer.example",
        ] {
            assert_eq!(check_url(url), Err(Unpinnable::BadUrl), "{url}");
        }
        let longest = format!("https://issuer.example/{}", "a".repeat(MAX_URL_CHARS - 23));
        assert_eq!(longest.chars().count(), MAX_URL_CHARS);
        assert_eq!(check_url(&longest), Ok(()));
        assert_eq!(check_url(&format!("{longest}a")), Err(Unpinnable::BadUrl));
        for url in built_in_urls() {
            assert_eq!(check_url(&url), Err(Unpinnable::BuiltIn), "{url}");
        }
    }
}
