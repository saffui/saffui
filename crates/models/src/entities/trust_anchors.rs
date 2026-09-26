use chrono::{DateTime, Utc};

use crate::str_enum::str_enum;

str_enum! {
    /// What a realm trusts an authority to vouch for. An authority deposited
    /// for one role vouches for nothing else.
    pub enum TrustAnchorRole {
        /// The issuers of the credentials people present to the realm.
        CredentialIssuer => "credential-issuer",
    }
}

/// An authority a realm trusts, as its administrator deposited it.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustAnchor {
    pub anchor_id: String,
    pub role: TrustAnchorRole,
    /// The certificate as deposited, DER.
    pub certificate: Vec<u8>,
    /// SHA-256 of the DER, lowercase hex.
    pub fingerprint: String,
    /// The subject, as this build renders a distinguished name.
    pub subject: String,
    /// The subject key identifier, base64url, where the certificate states one.
    pub key_identifier: Option<String>,
    pub not_after: DateTime<Utc>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}
