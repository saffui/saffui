use chrono::{DateTime, Utc};
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::str_enum::str_enum;

str_enum! {
    /// How a realm presents itself to the wallets it asks for presentations.
    pub enum VerifierIdentity {
        /// By its did:web, which Inji's wallets resolve.
        DidWeb => "did-web",
        /// By the certificate an authority issued for its key, under the
        /// `x509_hash` prefix HAIP requires.
        X509Hash => "x509-hash",
    }
}

str_enum! {
    /// Where a key the realm's requests are signed with stands.
    pub enum VerifierKeyState {
        /// Drawn with its certificate request, and signing nothing yet.
        Awaiting => "awaiting",
        /// Certified, and signing the realm's requests while the realm
        /// presents itself by its certificate.
        Serving => "serving",
    }
}

/// How a realm presents itself as a verifier, and what the European profile
/// (ETSI TS 119 472-2) adds to the requests it signs.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifierSettings {
    pub identity: VerifierIdentity,
    /// What the realm's registrar holds of it, as TS 119 475 writes it.
    pub registrar_dataset: Option<Value>,
    /// The registration certificate, a JWS in compact serialization.
    pub registration_certificate: Option<String>,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

/// The subject a certificate request names, as an access certificate does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierSubject {
    pub common_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// The organization's registered identifier, as EN 319 412-1 writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_identifier: Option<String>,
    /// ISO 3166-1 alpha-2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// The certificate an authority issued for a key.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifierCertificate {
    /// DER, leaf first, the trust anchor left out.
    pub chain: Vec<Vec<u8>>,
    /// The base64url SHA-256 of the leaf, which `x509_hash` names it by.
    pub leaf_hash: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub certified_at: DateTime<Utc>,
}

/// A key the realm's requests are signed with, its private half left out.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifierKeyView {
    /// The RFC 7638 thumbprint of the public key.
    pub kid: String,
    pub state: VerifierKeyState,
    pub public_jwk: Value,
    pub subject: VerifierSubject,
    /// The PKCS#10 request, PEM.
    pub request_pem: String,
    /// Absent while the key awaits it.
    pub certificate: Option<VerifierCertificate>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

/// A key drawn with its certificate request, kept to await the certificate.
pub struct DrawnVerifierKey {
    pub kid: String,
    /// PKCS#8, PEM.
    pub private_pem: SecretBox<Vec<u8>>,
    pub public_jwk: Value,
    pub subject: VerifierSubject,
    pub request_pem: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

/// The key in service, private half opened, with its certificate.
pub struct ServingVerifierKey {
    pub kid: String,
    /// PKCS#8, PEM.
    pub private_pem: SecretBox<Vec<u8>>,
    pub certificate: VerifierCertificate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;

    #[test]
    fn the_identities_and_key_states_agree_with_their_own_spelling() {
        assert_eq!(VerifierIdentity::ALL.len(), 2);
        assert_round_trips(VerifierIdentity::ALL);
        assert_eq!(VerifierKeyState::ALL.len(), 2);
        assert_round_trips(VerifierKeyState::ALL);
    }
}
