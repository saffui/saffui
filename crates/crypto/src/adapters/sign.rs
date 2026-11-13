use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use saffui_core::ports::crypto::{
    CryptoFailure, GeneratedSigningKey, KeyMakingFailure, KeyMakingGuard, SignatureAlgorithm,
    Signer,
};
use saffui_core::secret::Secret;
use serde_json::{Map, Value};
use tokio::sync::{Semaphore, TryAcquireError};
use tokio::task::spawn_blocking;

use super::SharedProvider;
use crate::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
use crate::jose::jwk::alg::ed::{EdCurve, EdKeyPair};
use crate::jose::jwk::alg::rsa::RsaKeyPair;
use crate::jose::jwk::{Jwk, KeyPair};
use crate::jose::jws::alg::ecdsa::EcdsaJwsAlgorithm;
use crate::jose::jws::alg::eddsa::EddsaJwsAlgorithm;
use crate::jose::jws::alg::rsassa::RsassaJwsAlgorithm;
use crate::jose::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm;
use crate::jose::jws::{JwsSigner, JwsVerifier};
use crate::provider::CryptoProvider;
use crate::thumbprint::jwk_sha256_thumbprint;

/// The length of a generated RSA key: above the floor of 2048 bits the JOSE
/// layer holds, for keys that outlive their first years.
const RSA_KEY_BITS: u32 = 3072;

/// How many keys are made at once. A key is made with a realm or by an
/// administrator, and an RSA key keeps a core busy while it is found.
const KEY_MAKERS: usize = 2;

/// The longest RSA modulus read: 4096 bits.
const MAX_RSA_MODULUS_BYTES: usize = 512;

/// The keys and signatures of the JOSE layer of this crate, behind the
/// signing port of the core. A private key is carried as PKCS#8 DER, a
/// public key as a JWK.
pub struct JoseSigner {
    provider: SharedProvider,
    makers: Arc<Semaphore>,
}

impl JoseSigner {
    #[must_use]
    pub fn new(provider: SharedProvider) -> Self {
        Self {
            provider,
            makers: Arc::new(Semaphore::new(KEY_MAKERS)),
        }
    }
}

/// Whether this build signs in `algorithm`. A `fips-strict` build keeps to
/// the signatures of FIPS 186-4, which has no Ed25519.
fn admits(algorithm: SignatureAlgorithm) -> bool {
    match algorithm {
        SignatureAlgorithm::EdDsa => !cfg!(feature = "fips-strict"),
        SignatureAlgorithm::Es256
        | SignatureAlgorithm::Es384
        | SignatureAlgorithm::Rs256
        | SignatureAlgorithm::Ps256 => true,
    }
}

/// Generates a key pair for `algorithm`. A PS256 key is an RSA-PSS key: it
/// signs in PS256 and in nothing else, and is read in place to sign. Its
/// public half is the JWK of an RSA key, and its `alg` says which one reads it.
fn generate_pair(algorithm: SignatureAlgorithm) -> Result<Box<dyn KeyPair>, CryptoFailure> {
    let pair: Box<dyn KeyPair> = match algorithm {
        SignatureAlgorithm::Es256 => {
            Box::new(EcKeyPair::generate(EcCurve::P256).map_err(|_| CryptoFailure)?)
        }
        SignatureAlgorithm::Es384 => {
            Box::new(EcKeyPair::generate(EcCurve::P384).map_err(|_| CryptoFailure)?)
        }
        SignatureAlgorithm::Rs256 => {
            Box::new(RsaKeyPair::generate(RSA_KEY_BITS).map_err(|_| CryptoFailure)?)
        }
        SignatureAlgorithm::Ps256 => Box::new(
            RsassaPssJwsAlgorithm::Ps256
                .generate_key_pair(RSA_KEY_BITS)
                .map_err(|_| CryptoFailure)?,
        ),
        SignatureAlgorithm::EdDsa => {
            Box::new(EdKeyPair::generate(EdCurve::Ed25519).map_err(|_| CryptoFailure)?)
        }
    };
    Ok(pair)
}

fn make_key(
    provider: &dyn CryptoProvider,
    algorithm: SignatureAlgorithm,
) -> Result<GeneratedSigningKey, CryptoFailure> {
    let pair = generate_pair(algorithm)?;
    let mut public = pair.to_jwk_public_key();
    // The identifier is the thumbprint of the key alone (RFC 7638): it is
    // computed before anything else is written on the key.
    let key_id = jwk_sha256_thumbprint(provider, &public).map_err(|_| CryptoFailure)?;
    public.set_key_id(&key_id);
    public.set_algorithm(algorithm.name());
    public.set_key_use("sig");
    Ok(GeneratedSigningKey {
        algorithm,
        key_id,
        private_key: Secret::new(pair.to_der_private_key()),
        public_jwk: Value::Object(public.into()),
    })
}

fn sign_with(
    algorithm: SignatureAlgorithm,
    private_der: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, CryptoFailure> {
    let signed = match algorithm {
        SignatureAlgorithm::Es256 => EcdsaJwsAlgorithm::Es256
            .signer_from_der(private_der)
            .and_then(|signer| signer.sign(message)),
        SignatureAlgorithm::Es384 => EcdsaJwsAlgorithm::Es384
            .signer_from_der(private_der)
            .and_then(|signer| signer.sign(message)),
        SignatureAlgorithm::Rs256 => RsassaJwsAlgorithm::Rs256
            .signer_from_der(private_der)
            .and_then(|signer| signer.sign(message)),
        SignatureAlgorithm::Ps256 => RsassaPssJwsAlgorithm::Ps256
            .signer_from_der(private_der)
            .and_then(|signer| signer.sign(message)),
        SignatureAlgorithm::EdDsa => EddsaJwsAlgorithm::Eddsa
            .signer_from_der(private_der)
            .and_then(|signer| signer.sign(message)),
    };
    signed.map_err(|_| CryptoFailure)
}

/// Whether an RSA key is one a signer makes: the exponent 65537 and a
/// modulus of 4096 bits at most. A key built to make the verifier work, with
/// a huge exponent or modulus, is refused before any arithmetic.
fn is_ordinary_rsa_key(members: &Map<String, Value>) -> bool {
    let modulus_fits = members
        .get("n")
        .and_then(Value::as_str)
        .is_some_and(|written| {
            // Measured before it is decoded, which bounds the work of the
            // decoding: four characters carry three bytes.
            written.len() <= MAX_RSA_MODULUS_BYTES.div_ceil(3) * 4
                && URL_SAFE_NO_PAD.decode(written).is_ok_and(|modulus| {
                    modulus.iter().skip_while(|byte| **byte == 0).count() <= MAX_RSA_MODULUS_BYTES
                })
        });
    members.get("e").and_then(Value::as_str) == Some("AQAB") && modulus_fits
}

/// Reads a public key for `algorithm`. A key of another type, or another
/// curve, does not read: the algorithm is never taken from the key.
fn read_verifier(
    algorithm: SignatureAlgorithm,
    key: &Jwk,
) -> Result<Box<dyn JwsVerifier>, CryptoFailure> {
    let verifier: Box<dyn JwsVerifier> = match algorithm {
        SignatureAlgorithm::Es256 => Box::new(
            EcdsaJwsAlgorithm::Es256
                .verifier_from_jwk(key)
                .map_err(|_| CryptoFailure)?,
        ),
        SignatureAlgorithm::Es384 => Box::new(
            EcdsaJwsAlgorithm::Es384
                .verifier_from_jwk(key)
                .map_err(|_| CryptoFailure)?,
        ),
        SignatureAlgorithm::Rs256 => Box::new(
            RsassaJwsAlgorithm::Rs256
                .verifier_from_jwk(key)
                .map_err(|_| CryptoFailure)?,
        ),
        SignatureAlgorithm::Ps256 => Box::new(
            RsassaPssJwsAlgorithm::Ps256
                .verifier_from_jwk(key)
                .map_err(|_| CryptoFailure)?,
        ),
        SignatureAlgorithm::EdDsa => Box::new(
            EddsaJwsAlgorithm::Eddsa
                .verifier_from_jwk(key)
                .map_err(|_| CryptoFailure)?,
        ),
    };
    Ok(verifier)
}

#[async_trait]
impl Signer for JoseSigner {
    fn signs_in(&self, algorithm: SignatureAlgorithm) -> bool {
        admits(algorithm)
    }

    async fn generate_key(
        &self,
        algorithm: SignatureAlgorithm,
        guard: KeyMakingGuard,
    ) -> Result<GeneratedSigningKey, KeyMakingFailure> {
        if !admits(algorithm) {
            return Err(KeyMakingFailure::Failed);
        }
        // Taken now or not at all: a request never waits behind the keys of
        // other tenants. The permit and the guard go with the work: a caller
        // that gives up frees neither a maker nor its share while it works.
        let maker = match Arc::clone(&self.makers).try_acquire_owned() {
            Ok(maker) => maker,
            Err(TryAcquireError::NoPermits) => return Err(KeyMakingFailure::Busy),
            Err(TryAcquireError::Closed) => return Err(KeyMakingFailure::Failed),
        };
        let provider = Arc::clone(&self.provider);
        spawn_blocking(move || {
            // The share first, then its maker: one asked meanwhile is at worst refused as busy.
            let _held = (guard, maker);
            make_key(provider.as_ref(), algorithm)
        })
        .await
        .map_err(|_| KeyMakingFailure::Failed)?
        .map_err(|_| KeyMakingFailure::Failed)
    }

    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        private_key: &Secret,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoFailure> {
        if !admits(algorithm) {
            return Err(CryptoFailure);
        }
        sign_with(algorithm, private_key.expose(), message)
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        public_jwk: &Value,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoFailure> {
        if !admits(algorithm) {
            return Err(CryptoFailure);
        }
        let members = public_jwk.as_object().ok_or(CryptoFailure)?;
        let reads_rsa = matches!(
            algorithm,
            SignatureAlgorithm::Rs256 | SignatureAlgorithm::Ps256
        );
        if reads_rsa && !is_ordinary_rsa_key(members) {
            return Err(CryptoFailure);
        }
        let key = Jwk::from_map(members.clone()).map_err(|_| CryptoFailure)?;
        let verifier = read_verifier(algorithm, &key)?;
        // A key that cannot be read is a failure. A signature that does not
        // verify, whatever its shape, is an answer.
        Ok(verifier.verify(message, signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::task::{Context, Waker};
    use std::time::{Duration, Instant};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use saffui_core::ports::crypto::{KeyMakingFailure, SignatureAlgorithm, Signer};
    use saffui_core::secret::Secret;
    use serde_json::{Value, json};

    use tokio::sync::Semaphore;

    use super::{JoseSigner, KEY_MAKERS};
    use crate::adapters::{SharedProvider, open_provider};
    use crate::provider::{
        AeadProvider, CbcProvider, CryptoProvider, DigestProvider, HashAlg, HmacProvider,
        KdfProvider, KeyStoreProvider, KeyTransportProvider, LegacyDigestProvider,
        PasswordProvider, RandProvider, SignerProvider, XofAlg,
    };

    const ES256: SignatureAlgorithm = SignatureAlgorithm::Es256;
    const MESSAGE: &[u8] = b"header.payload";

    fn open_signer() -> JoseSigner {
        JoseSigner::new(open_provider().expect("a provider"))
    }

    /// The algorithms of the catalog this build signs in.
    fn list_served() -> Vec<SignatureAlgorithm> {
        SignatureAlgorithm::ALL
            .into_iter()
            .filter(|algorithm| {
                cfg!(not(feature = "fips-strict")) || *algorithm != SignatureAlgorithm::EdDsa
            })
            .collect()
    }

    /// An RSA public key of `modulus` and `exponent`, written as bytes.
    fn write_rsa_key(modulus: &[u8], exponent: &[u8]) -> Value {
        json!({
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode(modulus),
            "e": URL_SAFE_NO_PAD.encode(exponent),
        })
    }

    /// The members a published key holds, sorted, by its type: none of them
    /// is one a private key carries.
    fn list_members(public_jwk: &Value) -> (String, Vec<String>) {
        let mut names: Vec<String> = public_jwk
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        names.sort_unstable();
        (public_jwk["kty"].as_str().expect("a kty").to_owned(), names)
    }

    fn expect_members(kty: &str) -> Vec<String> {
        let names: &[&str] = match kty {
            "RSA" => &["alg", "e", "kid", "kty", "n", "use"],
            "EC" => &["alg", "crv", "kid", "kty", "use", "x", "y"],
            "OKP" => &["alg", "crv", "kid", "kty", "use", "x"],
            other => panic!("no key of type {other} is made"),
        };
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// A modulus of `bytes` bytes, its highest bit set.
    fn make_modulus(bytes: usize) -> Vec<u8> {
        let mut modulus = vec![0_u8; bytes];
        modulus[0] = 0x80;
        modulus[bytes - 1] = 1;
        modulus
    }

    #[tokio::test]
    async fn a_generated_key_publishes_no_private_member_and_is_named_by_its_thumbprint() {
        let signer = open_signer();

        let key = signer
            .generate_key(ES256, Box::new(()))
            .await
            .expect("a key");
        let other = signer
            .generate_key(ES256, Box::new(()))
            .await
            .expect("another key");

        let members = key.public_jwk.as_object().expect("an object");
        let mut names: Vec<&str> = members.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, ["alg", "crv", "kid", "kty", "use", "x", "y"]);
        assert_eq!(key.public_jwk["kty"], "EC");
        assert_eq!(key.public_jwk["crv"], "P-256");
        assert_eq!(key.public_jwk["alg"], "ES256");
        assert_eq!(key.public_jwk["use"], "sig");
        assert_eq!(key.public_jwk["kid"], key.key_id.as_str());
        assert_eq!(key.key_id.len(), 43, "32 bytes in base64url");
        assert_ne!(key.key_id, other.key_id);
    }

    #[tokio::test]
    async fn a_signature_is_64_raw_bytes_and_verifies_under_its_key_only() {
        let signer = open_signer();
        let key = signer
            .generate_key(ES256, Box::new(()))
            .await
            .expect("a key");
        let other = signer
            .generate_key(ES256, Box::new(()))
            .await
            .expect("another key");

        let signature = signer
            .sign(ES256, &key.private_key, MESSAGE)
            .expect("a signature");

        assert_eq!(signature.len(), 64, "r and s, as a JWS carries them");
        assert_eq!(
            signer.verify(ES256, &key.public_jwk, MESSAGE, &signature),
            Ok(true)
        );
        assert_eq!(
            signer.verify(ES256, &other.public_jwk, MESSAGE, &signature),
            Ok(false)
        );
        assert_eq!(
            signer.verify(ES256, &key.public_jwk, b"header.payloae", &signature),
            Ok(false)
        );
    }

    #[tokio::test]
    async fn an_altered_a_truncated_or_an_empty_signature_does_not_verify() {
        let signer = open_signer();
        let key = signer
            .generate_key(ES256, Box::new(()))
            .await
            .expect("a key");
        let signature = signer
            .sign(ES256, &key.private_key, MESSAGE)
            .expect("a signature");
        let mut altered = signature.clone();
        altered[10] ^= 1;

        for forged in [&altered[..], &signature[..63], &[][..], &[0_u8; 64][..]] {
            assert_eq!(
                signer.verify(ES256, &key.public_jwk, MESSAGE, forged),
                Ok(false),
                "{} bytes",
                forged.len()
            );
        }
    }

    #[tokio::test]
    async fn a_key_that_is_not_one_fails_instead_of_answering() {
        let signer = open_signer();
        let key = signer
            .generate_key(ES256, Box::new(()))
            .await
            .expect("a key");
        let signature = signer
            .sign(ES256, &key.private_key, MESSAGE)
            .expect("a signature");

        for not_a_key in [
            json!("text"),
            json!({ "kty": "EC", "crv": "P-256", "x": "AA", "y": "AA" }),
            json!({ "kty": "RSA", "n": "AQAB", "e": "AQAB" }),
        ] {
            assert!(
                signer
                    .verify(ES256, &not_a_key, MESSAGE, &signature)
                    .is_err(),
                "{not_a_key}"
            );
        }
        assert!(
            signer
                .sign(ES256, &Secret::new(vec![1, 2, 3]), MESSAGE)
                .is_err()
        );
    }

    #[tokio::test]
    async fn every_algorithm_served_generates_signs_and_verifies_under_its_own_key_only() {
        let signer = open_signer();
        for algorithm in list_served() {
            let key = signer
                .generate_key(algorithm, Box::new(()))
                .await
                .expect("a key");
            let other = signer
                .generate_key(algorithm, Box::new(()))
                .await
                .expect("another key");

            let signature = signer
                .sign(algorithm, &key.private_key, MESSAGE)
                .expect("a signature");

            assert_eq!(key.public_jwk["alg"], algorithm.name());
            assert_eq!(key.public_jwk["kid"], key.key_id.as_str());
            let (kty, members) = list_members(&key.public_jwk);
            assert_eq!(members, expect_members(&kty), "{algorithm:?}");
            assert_eq!(
                signer.verify(algorithm, &key.public_jwk, MESSAGE, &signature),
                Ok(true),
                "{algorithm:?}"
            );
            assert_eq!(
                signer.verify(algorithm, &other.public_jwk, MESSAGE, &signature),
                Ok(false),
                "{algorithm:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_key_is_never_read_for_an_algorithm_it_is_not_of() {
        let signer = open_signer();
        let rsa = signer
            .generate_key(SignatureAlgorithm::Rs256, Box::new(()))
            .await
            .expect("a key");
        let p384 = signer
            .generate_key(SignatureAlgorithm::Es384, Box::new(()))
            .await
            .expect("a key");
        let signature = signer
            .sign(SignatureAlgorithm::Rs256, &rsa.private_key, MESSAGE)
            .expect("a signature");

        for (algorithm, key) in [
            (ES256, &rsa.public_jwk),
            (SignatureAlgorithm::Rs256, &p384.public_jwk),
            (ES256, &p384.public_jwk),
            (SignatureAlgorithm::Ps256, &rsa.public_jwk),
        ] {
            assert!(
                signer.verify(algorithm, key, MESSAGE, &signature).is_err(),
                "{algorithm:?} does not read {key}"
            );
        }
    }

    #[test]
    fn an_rsa_key_built_to_cost_the_verifier_is_refused_before_any_arithmetic() {
        let signer = open_signer();
        let mut huge_exponent = make_modulus(384);
        huge_exponent[0] = 0x40;
        let mut just_over = make_modulus(513);
        just_over[0] = 1;

        // Refused, not answered: the key was never read.
        for (key, why) in [
            (
                write_rsa_key(&make_modulus(384), &huge_exponent),
                "an exponent of 3070 bits",
            ),
            (write_rsa_key(&make_modulus(384), &[3]), "the exponent 3"),
            (
                write_rsa_key(&just_over, &[1, 0, 1]),
                "a modulus of 4097 bits",
            ),
            (
                // Zero bytes decode from whole groups of four: read whole,
                // this is an ordinary modulus, and only its length refuses it.
                json!({
                    "kty": "RSA",
                    "n": format!("{}{}", "A".repeat(9316), URL_SAFE_NO_PAD.encode(make_modulus(512))),
                    "e": "AQAB",
                }),
                "an ordinary modulus behind 9316 characters of zeros",
            ),
            (
                write_rsa_key(&make_modulus(1024), &[1, 0, 1]),
                "a modulus of 8192 bits",
            ),
        ] {
            for algorithm in [SignatureAlgorithm::Rs256, SignatureAlgorithm::Ps256] {
                assert!(
                    signer.verify(algorithm, &key, MESSAGE, &[1; 512]).is_err(),
                    "{why}, read for {algorithm:?}"
                );
            }
        }
        let mut leading_zero = vec![0_u8];
        leading_zero.extend(make_modulus(512));
        for (key, why) in [
            (write_rsa_key(&make_modulus(512), &[1, 0, 1]), "4096 bits"),
            (
                write_rsa_key(&leading_zero, &[1, 0, 1]),
                "4096 bits behind a zero byte",
            ),
        ] {
            assert_eq!(
                signer.verify(SignatureAlgorithm::Rs256, &key, MESSAGE, &[1; 512]),
                Ok(false),
                "an ordinary key of {why} is read, and a wrong signature is an answer"
            );
        }
    }

    #[tokio::test]
    async fn a_key_asked_while_every_maker_is_at_work_is_refused_at_once() {
        let signer = open_signer();
        let at_work = Arc::clone(&signer.makers)
            .try_acquire_many_owned(u32::try_from(KEY_MAKERS).expect("a count"))
            .expect("every maker");

        assert_eq!(
            signer.generate_key(ES256, Box::new(())).await.map(|_| ()),
            Err(KeyMakingFailure::Busy)
        );
        drop(at_work);
        assert!(
            signer.generate_key(ES256, Box::new(())).await.is_ok(),
            "a maker is free again"
        );
    }

    #[tokio::test]
    async fn a_ps256_key_signs_in_ps256_and_in_nothing_else() {
        let signer = open_signer();
        let pss = signer
            .generate_key(SignatureAlgorithm::Ps256, Box::new(()))
            .await
            .expect("a key");

        let signature = signer
            .sign(SignatureAlgorithm::Ps256, &pss.private_key, MESSAGE)
            .expect("a signature");

        assert_eq!(
            signer.verify(
                SignatureAlgorithm::Ps256,
                &pss.public_jwk,
                MESSAGE,
                &signature
            ),
            Ok(true)
        );
        assert!(
            signer
                .sign(SignatureAlgorithm::Rs256, &pss.private_key, MESSAGE)
                .is_err(),
            "an RSA-PSS key does not sign in RS256"
        );
    }

    /// The provider of this machine, which counts the digests it makes: the
    /// thumbprint that names a key is the one digest made with it, once the
    /// key is made.
    struct CountingProvider {
        inner: SharedProvider,
        digest: CountingDigest,
    }

    struct CountingDigest {
        inner: SharedProvider,
        made: Arc<AtomicUsize>,
    }

    impl DigestProvider for CountingDigest {
        fn hash(&self, alg: HashAlg, data: &[u8]) -> crate::provider::Result<Vec<u8>> {
            self.made.fetch_add(1, Ordering::SeqCst);
            self.inner.digest().hash(alg, data)
        }

        fn xof(&self, alg: XofAlg, data: &[u8], len: usize) -> crate::provider::Result<Vec<u8>> {
            self.made.fetch_add(1, Ordering::SeqCst);
            self.inner.digest().xof(alg, data, len)
        }
    }

    impl CryptoProvider for CountingProvider {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn version(&self) -> &str {
            self.inner.version()
        }
        fn is_fips_enabled(&self) -> bool {
            self.inner.is_fips_enabled()
        }
        fn hmac(&self) -> &dyn HmacProvider {
            self.inner.hmac()
        }
        fn aead(&self) -> &dyn AeadProvider {
            self.inner.aead()
        }
        fn cbc(&self) -> &dyn CbcProvider {
            self.inner.cbc()
        }
        fn key_transport(&self) -> &dyn KeyTransportProvider {
            self.inner.key_transport()
        }
        fn signer(&self) -> &dyn SignerProvider {
            self.inner.signer()
        }
        fn kdf(&self) -> &dyn KdfProvider {
            self.inner.kdf()
        }
        fn rand(&self) -> &dyn RandProvider {
            self.inner.rand()
        }
        fn password(&self) -> &dyn PasswordProvider {
            self.inner.password()
        }
        fn key_store(&self) -> &dyn KeyStoreProvider {
            self.inner.key_store()
        }
        fn legacy_digest(&self) -> &dyn LegacyDigestProvider {
            self.inner.legacy_digest()
        }
        fn digest(&self) -> &dyn DigestProvider {
            &self.digest
        }
        #[cfg(feature = "pq-hybrid")]
        fn pq_signature(&self) -> &dyn crate::provider::PqSignatureProvider {
            self.inner.pq_signature()
        }
        #[cfg(feature = "pq-hybrid")]
        fn pq_kem(&self) -> &dyn crate::provider::PqKemProvider {
            self.inner.pq_kem()
        }
    }

    /// The guard of a caller. As it is dropped, it tells how many digests
    /// were made by then and how many makers were free; it is alive as long
    /// as its token is.
    struct Watch {
        digests: Arc<AtomicUsize>,
        makers: Arc<Semaphore>,
        told: mpsc::Sender<(usize, usize)>,
        _alive: Arc<()>,
    }

    impl Drop for Watch {
        fn drop(&mut self) {
            let seen = (
                self.digests.load(Ordering::SeqCst),
                self.makers.available_permits(),
            );
            let _ = self.told.send(seen);
        }
    }

    /// The only blocking thread is held, so that the key waits to be made;
    /// the caller hangs up meanwhile. The guard of the caller is dropped once
    /// the key is made and named, while its maker is still taken; the maker
    /// is free again after.
    #[test]
    fn a_key_maker_and_the_guard_of_its_caller_are_held_until_the_key_is_made() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .build()
            .expect("a runtime");
        let _inside = runtime.enter();
        let digests = Arc::new(AtomicUsize::new(0));
        let inner = open_provider().expect("a provider");
        let signer = JoseSigner::new(Arc::new(CountingProvider {
            inner: Arc::clone(&inner),
            digest: CountingDigest {
                inner,
                made: Arc::clone(&digests),
            },
        }));
        let alive = Arc::new(());
        let (told, seen) = mpsc::channel();
        let guard = Watch {
            digests: Arc::clone(&digests),
            makers: Arc::clone(&signer.makers),
            told,
            _alive: Arc::clone(&alive),
        };
        let (release, held) = mpsc::channel::<()>();
        let blocker = runtime.spawn_blocking(move || held.recv());
        {
            let mut making = pin!(signer.generate_key(SignatureAlgorithm::Rs256, Box::new(guard)));
            let polled = making
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()));
            assert!(polled.is_pending(), "the key waits for a blocking thread");
        }

        assert_eq!(
            Arc::strong_count(&alive),
            2,
            "the guard waits with the work"
        );
        assert_eq!(
            signer.makers.available_permits(),
            KEY_MAKERS - 1,
            "and so does the maker"
        );
        release.send(()).expect("the blocking thread let go");
        let deadline = Instant::now() + Duration::from_mins(1);
        while Arc::strong_count(&alive) == 2 {
            assert!(Instant::now() < deadline, "the key is made in time");
            assert_eq!(
                signer.makers.available_permits(),
                KEY_MAKERS - 1,
                "the maker is never free while the guard is held"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            seen.recv_timeout(Duration::from_secs(1)),
            Ok((1, KEY_MAKERS - 1)),
            "the guard went once the key was named, its maker still taken"
        );
        while signer.makers.available_permits() < KEY_MAKERS {
            assert!(Instant::now() < deadline, "the maker is given back");
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(blocker);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_rsa_key_is_made_away_from_the_thread_that_waits_for_it() {
        let signer = open_signer();
        let order = Mutex::new(Vec::new());
        let note = |what: &'static str| order.lock().expect("the order").push(what);

        // One thread serves both: a key made on it would let nothing else run.
        let making = async {
            signer
                .generate_key(SignatureAlgorithm::Rs256, Box::new(()))
                .await
                .expect("a key");
            note("key");
        };
        let ticking = async {
            tokio::task::yield_now().await;
            note("tick");
        };
        tokio::join!(making, ticking);

        assert_eq!(*order.lock().expect("the order"), ["tick", "key"]);
    }

    #[cfg(not(feature = "fips-strict"))]
    #[test]
    fn every_algorithm_of_the_catalog_is_served_by_a_build_that_is_not_fips_strict() {
        let signer = open_signer();

        for algorithm in SignatureAlgorithm::ALL {
            assert!(signer.signs_in(algorithm), "{algorithm:?}");
        }
    }

    #[cfg(feature = "fips-strict")]
    #[tokio::test]
    async fn a_fips_strict_build_neither_makes_signs_nor_reads_in_eddsa() {
        use crate::jose::jwk::KeyPair;
        use crate::jose::jwk::alg::ed::{EdCurve, EdKeyPair};
        use crate::jose::jws::JwsSigner;
        use crate::jose::jws::alg::eddsa::EddsaJwsAlgorithm;

        let signer = open_signer();
        let eddsa = SignatureAlgorithm::EdDsa;
        // A key and a signature of EdDSA, made under the layer itself.
        let pair = EdKeyPair::generate(EdCurve::Ed25519).expect("a pair");
        let private_key = Secret::new(pair.to_der_private_key());
        let public_jwk = Value::Object(pair.to_jwk_public_key().into());
        let signature = EddsaJwsAlgorithm::Eddsa
            .signer_from_der(private_key.expose())
            .and_then(|made| made.sign(MESSAGE))
            .expect("a signature");

        assert!(!signer.signs_in(eddsa));
        assert!(signer.generate_key(eddsa, Box::new(())).await.is_err());
        assert!(signer.sign(eddsa, &private_key, MESSAGE).is_err());
        assert!(
            signer
                .verify(eddsa, &public_jwk, MESSAGE, &signature)
                .is_err()
        );
        for algorithm in [
            SignatureAlgorithm::Es256,
            SignatureAlgorithm::Es384,
            SignatureAlgorithm::Rs256,
            SignatureAlgorithm::Ps256,
        ] {
            assert!(signer.signs_in(algorithm), "{algorithm:?}");
        }
    }
}
