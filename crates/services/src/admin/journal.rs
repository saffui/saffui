//! The realm's audit journal: the chain the plane's work is written into, read
//! a page at a time, verified link by link, and anchored with a witness.

use crypto::provider::DigestProvider;
use serde_json::Value;
pub use store::audit::{Anchor, Appended, JournalEntry, Verified};
use store::error::StoreError;
use store::tenancy::UnitOfWork;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unjournalled {
    /// Nothing has been journalled in this realm yet.
    #[error("nothing has been journalled yet")]
    NoChain,
    #[error("the journal could not be read or written")]
    Backend,
}

fn unjournalled(why: StoreError) -> Unjournalled {
    match why {
        StoreError::NoChain => Unjournalled::NoChain,
        _ => Unjournalled::Backend,
    }
}

/// Open this realm's chain. False when it was already open, which two first
/// writers racing each other both read as done.
pub async fn start_chain(
    transaction: &UnitOfWork,
    digest: &dyn DigestProvider,
    tenant: &str,
    realm_id: &str,
) -> Result<bool, Unjournalled> {
    store::audit::start(transaction, digest, tenant, realm_id)
        .await
        .map_err(unjournalled)
}

/// Record one entry at the end of the chain in scope.
pub async fn append_entry(
    transaction: &UnitOfWork,
    entry: &Value,
) -> Result<Appended, Unjournalled> {
    store::audit::append(transaction, entry)
        .await
        .map_err(unjournalled)
}

/// The newest entries first, one page at a time, of one trace when one is
/// named, and how many there are when asked.
pub async fn read_entries(
    transaction: &UnitOfWork,
    first: i64,
    max: i64,
    count: bool,
    trace: Option<&str>,
) -> Result<(Vec<JournalEntry>, Option<i64>), Unjournalled> {
    store::audit::list_entries(transaction, first, max, count, trace)
        .await
        .map_err(unjournalled)
}

/// Recompute every link and say where the chain first breaks. A realm that
/// has journalled nothing yet holds an empty record, and an empty record is a
/// whole one.
pub async fn verify_chain(
    transaction: &UnitOfWork,
    digest: &dyn DigestProvider,
) -> Result<Verified, Unjournalled> {
    match store::audit::verify(transaction, digest).await {
        Ok(verified) => Ok(verified),
        Err(StoreError::NoChain) => Ok(Verified {
            entries: 0,
            broken_at: None,
        }),
        Err(_) => Err(Unjournalled::Backend),
    }
}

/// Publish the chain's current head against a witness the writer does not
/// control, and remember where and what came back.
pub async fn anchor_head(
    transaction: &UnitOfWork,
    witness: &str,
    receipt: &str,
) -> Result<Appended, Unjournalled> {
    store::audit::anchor(transaction, witness, receipt)
        .await
        .map_err(unjournalled)
}

/// Every head this realm has published, newest first.
pub async fn read_anchors(transaction: &UnitOfWork) -> Result<Vec<Anchor>, Unjournalled> {
    store::audit::list_anchors(transaction)
        .await
        .map_err(unjournalled)
}
