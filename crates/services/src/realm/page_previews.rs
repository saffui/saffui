//! Drafts of a realm's page wording, kept for the minute a console previews
//! them.

use chrono::{DateTime, Utc};
use store::providers::realms::page_previews;
use store::tenancy::UnitOfWork;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the draft could not be kept")]
pub struct Unkept;

/// A draft while it still lives. Nothing once it has expired, or when nobody
/// kept one under that identifier.
pub async fn read_page_preview(
    transaction: &UnitOfWork,
    preview_id: &str,
) -> Result<Option<serde_json::Value>, crate::realm::Unreadable> {
    page_previews::read(transaction, preview_id)
        .await
        .map_err(|_| crate::realm::Unreadable)
}

/// Keep a draft under a drawn identifier until `expires_at`.
pub async fn keep_page_preview(
    transaction: &UnitOfWork,
    preview_id: &str,
    overrides: &serde_json::Value,
    expires_at: DateTime<Utc>,
) -> Result<(), Unkept> {
    page_previews::keep(transaction, preview_id, overrides, expires_at)
        .await
        .map_err(|_| Unkept)
}
