use chrono::{DateTime, Utc};
use serde_json::Value;

/// A credential issuer a realm names, with the keys read from it when it was
/// named, or read again since.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialIssuer {
    pub issuer_id: String,
    /// What the realm's administrators call it.
    pub name: String,
    /// The issuer as its credentials name it: an https address or a `did:web`.
    pub issuer: String,
    /// Public keys as JWKs, each carrying the `kid` a credential names it by.
    pub keys: Vec<Value>,
    /// Where the keys were read.
    pub read_from: String,
    pub read_at: DateTime<Utc>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}
