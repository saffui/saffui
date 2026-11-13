//! The signing keys of a realm. A private key exists in clear only while it
//! is used: at rest it is sealed under the data key of its realm, for its own
//! row and no other.

pub mod generate;
pub mod jwks;
pub mod rotate;
pub mod shares;
pub mod store;

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ports::crypto::SignatureAlgorithm;

/// What a sealed private signing key is sealed for.
pub const SIGNING_KEY_PURPOSE: &str = "signing-key";

/// The most keys a realm holds, active and retired: each is published to
/// whoever asks, and read for each token verified.
pub const MAX_SIGNING_KEYS: usize = 20;

/// Whether a key still signs. A retired key verifies what it signed until it
/// is removed, and never signs again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Retired,
}

impl KeyStatus {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Active, Self::Retired]
            .into_iter()
            .find(|status| status.name() == name)
    }
}

/// A signing key as it is verified, published and listed: its public half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKey {
    pub id: Uuid,
    /// The `kid` of the key: the RFC 7638 thumbprint of its public half.
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub status: KeyStatus,
    pub public_jwk: Value,
    pub created_at: OffsetDateTime,
}

/// A key with its private half sealed: what is written once, and read back
/// only to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSigningKey {
    pub key: SigningKey,
    pub sealed_private_key: Vec<u8>,
}
