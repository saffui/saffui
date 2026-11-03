//! The signing keys of a realm. A private key exists in clear only while it
//! is used: at rest it is sealed under the data key of its realm, for its own
//! row and no other.

pub mod generate;
pub mod jwks;
pub mod store;

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ports::crypto::SignatureAlgorithm;

/// What a sealed private signing key is sealed for.
pub const SIGNING_KEY_PURPOSE: &str = "signing-key";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKey {
    pub id: Uuid,
    /// The `kid` of the key: the RFC 7638 thumbprint of its public half.
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub public_jwk: Value,
    pub sealed_private_key: Vec<u8>,
    pub created_at: OffsetDateTime,
}
