use chrono::{DateTime, Utc};

/// A JSON-LD context a realm pins, as it was read when it was pinned or read
/// again since. The document itself is loaded apart, where it is read.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonLdContext {
    pub context_id: String,
    /// The context as documents name it.
    pub url: String,
    /// The SHA-256 of the document, in lowercase hex.
    pub digest: String,
    /// The length of the document, in bytes.
    pub octets: i32,
    pub read_at: DateTime<Utc>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}
