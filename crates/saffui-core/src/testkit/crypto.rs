//! Doubles of the cryptographic ports. They hide nothing and prove nothing:
//! they keep the shape of the real ones so that the heart can be tested
//! without a cryptographic library.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use serde_json::json;
use uuid::Uuid;

use super::digest::WeakDigester;
use crate::ports::crypto::{
    CryptoFailure, Digester, GeneratedSigningKey, PasswordHasher, PasswordHashingFailure,
    SealPlace, Sealer, SignatureAlgorithm, Signer, WrappedDataKey,
};
use crate::secret::Secret;

/// A sealer that writes the place in clear in front of the value, and opens
/// only where the place matches: a moved value fails as it would for real.
#[derive(Clone, Copy, Debug, Default)]
pub struct TransparentSealer;

fn write_place(data_key: &WrappedDataKey, place: &SealPlace) -> Vec<u8> {
    let mut written = data_key.wrapped.clone();
    written.extend_from_slice(place.tenant.as_bytes());
    written.extend_from_slice(place.realm.as_bytes());
    written.extend_from_slice(place.purpose.as_bytes());
    written.extend_from_slice(place.row.as_bytes());
    written.push(b'|');
    written
}

impl Sealer for TransparentSealer {
    fn make_data_key(
        &self,
        tenant: Uuid,
        realm: Uuid,
        generation: u32,
    ) -> Result<WrappedDataKey, CryptoFailure> {
        let mut wrapped = b"data-key:".to_vec();
        wrapped.extend_from_slice(tenant.as_bytes());
        wrapped.extend_from_slice(realm.as_bytes());
        Ok(WrappedDataKey {
            generation,
            wrapped,
        })
    }

    fn seal(
        &self,
        data_key: &WrappedDataKey,
        place: &SealPlace,
        plaintext: &Secret,
    ) -> Result<Vec<u8>, CryptoFailure> {
        let mut sealed = write_place(data_key, place);
        sealed.extend_from_slice(plaintext.expose());
        Ok(sealed)
    }

    fn open(
        &self,
        data_key: &WrappedDataKey,
        place: &SealPlace,
        sealed: &[u8],
    ) -> Result<Secret, CryptoFailure> {
        sealed
            .strip_prefix(write_place(data_key, place).as_slice())
            .map(|plaintext| Secret::new(plaintext.to_vec()))
            .ok_or(CryptoFailure)
    }

    fn digest_typed_name(
        &self,
        tenant: Uuid,
        realm: Uuid,
        typed: &[u8],
    ) -> Result<Vec<u8>, CryptoFailure> {
        let mut written = b"typed-name:".to_vec();
        written.extend_from_slice(tenant.as_bytes());
        written.extend_from_slice(realm.as_bytes());
        written.extend_from_slice(typed);
        Ok(written)
    }
}

/// A signer whose public key is a digest of its private key, and whose
/// signature is a digest of that public key and the message: anyone can
/// forge it. It only keeps the shape of a signature.
#[derive(Debug, Default)]
pub struct WeakSigner {
    generated: AtomicU64,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

fn sign_weakly(public: &str, message: &[u8]) -> Vec<u8> {
    let mut signed = public.as_bytes().to_vec();
    signed.push(0);
    signed.extend_from_slice(message);
    let half = WeakDigester.sha256(&signed);
    [half, half].concat()
}

impl Signer for WeakSigner {
    fn generate_key(
        &self,
        algorithm: SignatureAlgorithm,
    ) -> Result<GeneratedSigningKey, CryptoFailure> {
        let serial = self.generated.fetch_add(1, Ordering::Relaxed);
        let private = format!("weak-private-{serial}").into_bytes();
        let public = to_hex(&WeakDigester.sha256(&private));
        Ok(GeneratedSigningKey {
            algorithm,
            key_id: public[..16].to_owned(),
            public_jwk: json!({
                // Shaped as a public key: no member of it is one a private
                // key carries.
                "kty": "OKP",
                "crv": "weak",
                "x": public,
                "kid": public[..16],
                "use": "sig",
                "alg": algorithm.name(),
            }),
            private_key: Secret::new(private),
        })
    }

    fn sign(
        &self,
        _algorithm: SignatureAlgorithm,
        private_key: &Secret,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoFailure> {
        let public = to_hex(&WeakDigester.sha256(private_key.expose()));
        Ok(sign_weakly(&public, message))
    }

    fn verify(
        &self,
        _algorithm: SignatureAlgorithm,
        public_jwk: &serde_json::Value,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoFailure> {
        let public = public_jwk["x"].as_str().ok_or(CryptoFailure)?;
        Ok(sign_weakly(public, message) == signature)
    }
}

/// A hasher that answers at once. What it stores is the password itself
/// behind a prefix: it exists so that a test of the login does not wait.
#[derive(Clone, Copy, Debug, Default)]
pub struct InstantHasher;

#[async_trait]
impl PasswordHasher for InstantHasher {
    async fn hash_password(&self, password: Secret) -> Result<String, PasswordHashingFailure> {
        Ok(format!("$instant${}", to_hex(password.expose())))
    }

    async fn verify_password(
        &self,
        password: Secret,
        stored: String,
    ) -> Result<bool, PasswordHashingFailure> {
        Ok(stored == format!("$instant${}", to_hex(password.expose())))
    }
}
