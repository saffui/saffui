use chrono::{DateTime, Utc};
use serde_json::Value;

/// A credential issuer a realm names, and how the realm trusts it.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialIssuer {
    pub issuer_id: String,
    /// What the realm's administrators call it.
    pub name: String,
    /// The issuer as its credentials name it: an https address or a `did:web`.
    pub issuer: String,
    pub trust: IssuerTrust,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

/// How a realm trusts an issuer it names: one way, whatever a credential
/// carries.
#[derive(Debug, Clone, PartialEq)]
pub enum IssuerTrust {
    /// By the keys its metadata or its DID document publishes, read when it
    /// was named or since.
    Metadata {
        /// Public keys as JWKs, each carrying the `kid` a credential names it by.
        keys: Vec<Value>,
        read_from: String,
        read_at: DateTime<Utc>,
    },
    /// By the certificates the authorities named issue it, for the types
    /// named alone.
    Certificate {
        /// The realm's trust anchors, by identifier.
        anchors: Vec<String>,
        /// The credential types it issues, as vct values.
        credential_types: Vec<String>,
    },
}

impl IssuerTrust {
    /// The keys an issuer trusted by its metadata publishes; none otherwise.
    pub fn keys(&self) -> &[Value] {
        match self {
            Self::Metadata { keys, .. } => keys,
            Self::Certificate { .. } => &[],
        }
    }
}
