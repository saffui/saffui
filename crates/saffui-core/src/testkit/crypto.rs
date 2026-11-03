//! Doubles of the cryptographic ports. They hide nothing and prove nothing:
//! they keep the shape of the real ones so that the heart can be tested
//! without a cryptographic library.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use serde_json::{Value, json};
use uuid::Uuid;

use super::digest::WeakDigester;
use crate::ports::crypto::{
    CryptoFailure, Digester, EnrolledKey, GeneratedSigningKey, KeyCeremony, KeyProof, KeyRefusal,
    OneTimeCodes, PasswordHasher, PasswordHashingFailure, SealPlace, Sealer, SecurityKeys,
    SignatureAlgorithm, Signer, TotpEnrollmentText, WrappedDataKey,
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
        // 32 bytes, as a MAC is: what reads it may hold it to its length.
        let mut written = b"typed-name:".to_vec();
        written.extend_from_slice(tenant.as_bytes());
        written.extend_from_slice(realm.as_bytes());
        written.extend_from_slice(typed);
        Ok(WeakDigester.sha256(&written).to_vec())
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

/// One-time codes anyone can compute: a code is a sum of the secret and of
/// the time step. It keeps what matters of the real ones: a code belongs
/// to one secret and to one step of thirty seconds.
#[derive(Debug, Default)]
pub struct PredictableCodes {
    made: AtomicU64,
}

impl PredictableCodes {
    /// The code of a secret for a time step.
    #[must_use]
    pub fn compute(secret: &[u8], step: u64) -> String {
        let sum: u64 = secret.iter().map(|byte| u64::from(*byte)).sum();
        format!("{:06}", (sum * 7919 + step * 104_729) % 1_000_000)
    }

    /// The code an application holding `typed_secret` shows at `unix_seconds`.
    ///
    /// # Panics
    ///
    /// Panics when the text is not a secret this double wrote.
    #[must_use]
    pub fn compute_from_text(typed_secret: &str, unix_seconds: u64) -> String {
        let secret: Vec<u8> = (0..typed_secret.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&typed_secret[at..at + 2], 16).expect("hexadecimal"))
            .collect();
        Self::compute(&secret, unix_seconds / 30)
    }
}

impl OneTimeCodes for PredictableCodes {
    fn make_totp_secret(&self) -> Result<Secret, CryptoFailure> {
        // Each secret differs from the one before: two people never share one.
        let made = self.made.fetch_add(1, Ordering::Relaxed) + 1;
        let mut secret = vec![0x5a_u8; 12];
        secret.extend_from_slice(&made.to_be_bytes());
        Ok(Secret::new(secret))
    }

    fn find_totp_step(
        &self,
        secret: &Secret,
        code: &str,
        unix_seconds: u64,
    ) -> Result<Option<u64>, CryptoFailure> {
        let current = unix_seconds / 30;
        Ok((current.saturating_sub(1)..=current + 1)
            .find(|step| Self::compute(secret.expose(), *step) == code))
    }

    fn write_totp_enrollment(
        &self,
        issuer: &str,
        account: &str,
        secret: &Secret,
    ) -> Result<TotpEnrollmentText, CryptoFailure> {
        let typed_secret = to_hex(secret.expose());
        Ok(TotpEnrollmentText {
            uri: format!("otpauth://totp/{issuer}:{account}?secret={typed_secret}"),
            typed_secret,
        })
    }
}

/// Security keys that sign nothing: a key answers a challenge by repeating
/// it, with its name and a counter. It keeps what matters of the real ones:
/// an answer serves for one challenge, a key must be held to be believed,
/// and a counter that does not move forward tells a copy, unless the key
/// counts nothing.
#[derive(Debug, Default)]
pub struct TrustingKeys {
    started: AtomicU64,
}

impl TrustingKeys {
    fn draw_challenge(&self) -> String {
        format!("challenge-{}", self.started.fetch_add(1, Ordering::Relaxed))
    }

    fn write_record(credential_id: &str, counter: u64) -> Vec<u8> {
        format!("{credential_id}|{counter}").into_bytes()
    }

    fn read_record(record: &[u8]) -> Option<(String, u64)> {
        let text = std::str::from_utf8(record).ok()?;
        let (credential_id, counter) = text.split_once('|')?;
        Some((credential_id.to_owned(), counter.parse().ok()?))
    }

    /// What a key named `credential_id` hands back to enroll.
    #[must_use]
    pub fn answer_enrollment(options: &Value, credential_id: &str) -> Value {
        json!({ "challenge": options["challenge"], "credential_id": credential_id })
    }

    /// What a key named `credential_id` hands back to prove itself, its
    /// counter at `counter`.
    #[must_use]
    pub fn answer_proof(options: &Value, credential_id: &str, counter: u64) -> Value {
        json!({
            "challenge": options["challenge"],
            "counter": counter,
            "credential_id": credential_id,
        })
    }
}

impl SecurityKeys for TrustingKeys {
    fn start_enrollment(
        &self,
        _person: Uuid,
        username: &str,
        held: &[Vec<u8>],
    ) -> Result<KeyCeremony, CryptoFailure> {
        let challenge = self.draw_challenge();
        let excluded: Vec<String> = held
            .iter()
            .filter_map(|record| Self::read_record(record))
            .map(|(credential_id, _)| credential_id)
            .collect();
        Ok(KeyCeremony {
            options: json!({ "challenge": challenge, "excluded": excluded, "user": username }),
            state: challenge.into_bytes(),
        })
    }

    fn finish_enrollment(&self, state: &[u8], answer: &Value) -> Result<EnrolledKey, KeyRefusal> {
        let echoed = answer["challenge"].as_str().map(str::as_bytes);
        let credential_id = answer["credential_id"].as_str();
        match (echoed, credential_id) {
            (Some(echoed), Some(credential_id)) if echoed == state => Ok(EnrolledKey {
                credential_id: credential_id.as_bytes().to_vec(),
                record: Self::write_record(credential_id, 0),
            }),
            _ => Err(KeyRefusal::Refused),
        }
    }

    fn start_proof(&self, held: &[Vec<u8>]) -> Result<KeyCeremony, CryptoFailure> {
        let challenge = self.draw_challenge();
        let allowed: Vec<String> = held
            .iter()
            .filter_map(|record| Self::read_record(record))
            .map(|(credential_id, _)| credential_id)
            .collect();
        Ok(KeyCeremony {
            options: json!({ "allowed": allowed, "challenge": challenge }),
            state: challenge.into_bytes(),
        })
    }

    fn finish_proof(
        &self,
        state: &[u8],
        answer: &Value,
        held: &[Vec<u8>],
    ) -> Result<KeyProof, KeyRefusal> {
        let refused = KeyRefusal::Refused;
        if answer["challenge"].as_str().map(str::as_bytes) != Some(state) {
            return Err(refused);
        }
        let credential_id = answer["credential_id"].as_str().ok_or(refused)?;
        let counter = answer["counter"].as_u64().ok_or(refused)?;
        let (_, last) = held
            .iter()
            .filter_map(|record| Self::read_record(record))
            .find(|(known, _)| known == credential_id)
            .ok_or(refused)?;
        // As the adapter does: a key that counts nothing answers zero forever,
        // and its record does not move.
        if (counter > 0 || last > 0) && counter <= last {
            return Err(KeyRefusal::CopySuspected);
        }
        Ok(KeyProof {
            credential_id: credential_id.as_bytes().to_vec(),
            record: (counter > last).then(|| Self::write_record(credential_id, counter)),
        })
    }
}
