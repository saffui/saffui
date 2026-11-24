use std::ops::RangeInclusive;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::bn::{BigNum, BigNumContext, BigNumContextRef, BigNumRef};
use openssl::error::ErrorStack;
use saffui_core::ports::crypto::{
    CryptoFailure, GeneratedSigningKey, KeyCheckLane, KeyMakingFailure, KeyMakingGuard,
    SignatureAlgorithm, Signer,
};
use saffui_core::secret::Secret;
use serde_json::{Map, Value};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
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

/// The length of a generated RSA key: above the floor of [`RSA_MODULUS_BITS`],
/// for keys that outlive their first years.
const RSA_KEY_BITS: u32 = 3072;

/// How many keys are made, or keys of clients checked, at once: an RSA key
/// keeps a core busy while it is found or its modulus checked.
const KEY_MAKERS: usize = 2;

/// How many sets of keys of clients that register themselves are checked
/// at once, apart from the key makers: anyone may ask for one where a realm
/// is open, and none takes a maker the realms need.
const REGISTRATION_CHECKERS: usize = 1;

/// The lengths of an RSA modulus read, in bits, the zeros in front aside. The
/// JOSE layer counts its floor in bytes, and 2041 bits fill 256 of them.
const RSA_MODULUS_BITS: RangeInclusive<usize> = 2048..=4096;

/// The keys and signatures of the JOSE layer of this crate, behind the
/// signing port of the core. A private key is carried as PKCS#8 DER, a
/// public key as a JWK.
pub struct JoseSigner {
    provider: SharedProvider,
    makers: Arc<Semaphore>,
    registration_checkers: Arc<Semaphore>,
}

/// Takes a place of `places` now or not at all: a request never waits
/// behind the keys of other tenants.
fn take_place(places: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, KeyMakingFailure> {
    match Arc::clone(places).try_acquire_owned() {
        Ok(place) => Ok(place),
        Err(TryAcquireError::NoPermits) => Err(KeyMakingFailure::Busy),
        Err(TryAcquireError::Closed) => Err(KeyMakingFailure::Failed),
    }
}

impl JoseSigner {
    #[must_use]
    pub fn new(provider: SharedProvider) -> Self {
        Self {
            provider,
            makers: Arc::new(Semaphore::new(KEY_MAKERS)),
            registration_checkers: Arc::new(Semaphore::new(REGISTRATION_CHECKERS)),
        }
    }

    fn take_maker(&self) -> Result<OwnedSemaphorePermit, KeyMakingFailure> {
        take_place(&self.makers)
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

/// The length in bits of a big-endian number, the zeros in front aside.
fn count_bits(number: &[u8]) -> usize {
    let mut digits = number.iter().skip_while(|byte| **byte == 0);
    digits.next().map_or(0, |top| {
        (u8::BITS - top.leading_zeros()) as usize + 8 * digits.count()
    })
}

/// Whether an RSA key is one a signer makes: the exponent 65537 and a
/// modulus of [`RSA_MODULUS_BITS`]. A key built to make the verifier work,
/// with a huge exponent or modulus, is refused before any arithmetic.
fn is_ordinary_rsa_key(members: &Map<String, Value>) -> bool {
    let modulus_fits = members
        .get("n")
        .and_then(Value::as_str)
        .is_some_and(|written| {
            // Measured before it is decoded, which bounds the work of the
            // decoding: four characters carry three bytes.
            written.len() <= (RSA_MODULUS_BITS.end() / 8).div_ceil(3) * 4
                && URL_SAFE_NO_PAD
                    .decode(written)
                    .is_ok_and(|modulus| RSA_MODULUS_BITS.contains(&count_bits(&modulus)))
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

/// The encodings of the points of Ed25519 of small order, the sign of `x`
/// aside: a key of one of them verifies a signature made without any
/// private half, whatever the message.
const SMALL_ORDER_ED25519: [[u8; 32]; 7] = [
    // 0, of order 4.
    [0; 32],
    // 1, the neutral point.
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // Two points of order 8.
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    // p - 1, of order 2, then p and p + 1, which encode 0 and 1 again.
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Whether a key of `EdDSA` is one a signer makes: on Ed25519, which alone
/// this product signs and reads (`EdDSA` names Ed448 too), and not a point of
/// small order.
fn is_ordinary_ed25519_key(members: &Map<String, Value>) -> bool {
    let on_ed25519 = members.get("crv").and_then(Value::as_str) == Some("Ed25519");
    let point = members
        .get("x")
        .and_then(Value::as_str)
        .filter(|written| written.len() == 43)
        .and_then(|written| URL_SAFE_NO_PAD.decode(written).ok())
        .and_then(|decoded| <[u8; 32]>::try_from(decoded).ok());
    on_ed25519
        && point.is_some_and(|mut point| {
            point[31] &= 0x7f;
            !SMALL_ORDER_ED25519.contains(&point)
        })
}

/// The bound below which a prime factor of a modulus is looked for.
const SMALL_FACTOR_BOUND: u32 = 1 << 16;

/// The product of the primes below [`SMALL_FACTOR_BOUND`], some 94 000 bits.
static SMALL_PRIMES: OnceLock<BigNum> = OnceLock::new();

/// Multiplies the primes below [`SMALL_FACTOR_BOUND`], once for the process.
fn multiply_small_primes() -> Result<&'static BigNum, ErrorStack> {
    if let Some(product) = SMALL_PRIMES.get() {
        return Ok(product);
    }
    let mut product = BigNum::from_u32(1)?;
    for candidate in 2..SMALL_FACTOR_BOUND {
        if (2..candidate)
            .take_while(|divisor| divisor * divisor <= candidate)
            .all(|divisor| candidate % divisor != 0)
        {
            product.mul_word(candidate)?;
        }
    }
    Ok(SMALL_PRIMES.get_or_init(|| product))
}

/// The integer square root of `number`, by Newton's iteration from above,
/// which falls to the root in a dozen steps for 4096 bits.
fn find_square_root(
    number: &BigNumRef,
    context: &mut BigNumContextRef,
) -> Result<BigNum, ErrorStack> {
    let mut root = BigNum::new()?;
    if number.num_bits() == 0 {
        return Ok(root);
    }
    // Two to the half of its length, rounded up, is above the root.
    root.set_bit((number.num_bits() + 1) / 2)?;
    loop {
        let mut quotient = BigNum::new()?;
        quotient.checked_div(number, &root, context)?;
        let mut sum = BigNum::new()?;
        sum.checked_add(&root, &quotient)?;
        let mut next = BigNum::new()?;
        next.rshift1(&sum)?;
        if next >= root {
            return Ok(root);
        }
        root = next;
    }
}

fn is_square(number: &BigNumRef, context: &mut BigNumContextRef) -> Result<bool, ErrorStack> {
    let root = find_square_root(number, context)?;
    let mut square = BigNum::new()?;
    square.sqr(&root, context)?;
    Ok(square == *number)
}

/// Whether an RSA modulus withstands four cheap ways to factor it, each of
/// which would give anyone its private exponent: it has no prime factor
/// below 2^16, it is not a square, it is not split by one step of Fermat's
/// method (two primes too close), and it fails Fermat's test in base 2
/// (a prime passes it, a product of two primes almost never does). A few
/// exponentiations at most, whatever the key.
fn check_modulus_against_cheap_factoring(written: &str) -> bool {
    let checked = || -> Result<bool, ErrorStack> {
        let Ok(bytes) = URL_SAFE_NO_PAD.decode(written) else {
            return Ok(false);
        };
        let modulus = BigNum::from_slice(&bytes)?;
        let mut context = BigNumContext::new()?;
        let one = BigNum::from_u32(1)?;
        // Reduced first: a gcd takes the time of its longer operand.
        let mut reduced = BigNum::new()?;
        reduced.nnmod(multiply_small_primes()?, &modulus, &mut context)?;
        let mut common = BigNum::new()?;
        common.gcd(&modulus, &reduced, &mut context)?;
        if common != one {
            return Ok(false);
        }
        let mut above = find_square_root(&modulus, &mut context)?;
        let mut square = BigNum::new()?;
        square.sqr(&above, &mut context)?;
        if square == modulus {
            return Ok(false);
        }
        // One step of Fermat's method: with a the root rounded up, a² - n a
        // square b² splits n into (a - b)(a + b).
        above.add_word(1)?;
        square.sqr(&above, &mut context)?;
        let mut gap = BigNum::new()?;
        gap.checked_sub(&square, &modulus)?;
        if is_square(&gap, &mut context)? {
            return Ok(false);
        }
        let (two, mut exponent) = (BigNum::from_u32(2)?, modulus.to_owned()?);
        exponent.sub_word(1)?;
        let mut witness = BigNum::new()?;
        witness.mod_exp(&two, &exponent, &modulus, &mut context)?;
        Ok(witness != one)
    };
    checked().unwrap_or(false)
}

/// Reads a public key for `algorithm`, as every verification reads it. An
/// RSA key that is not ordinary, and a key of `EdDSA` that is not, are
/// refused before the library reads them.
fn read_public_key(
    algorithm: SignatureAlgorithm,
    public_jwk: &Value,
) -> Result<Box<dyn JwsVerifier>, CryptoFailure> {
    if !admits(algorithm) {
        return Err(CryptoFailure);
    }
    let members = public_jwk.as_object().ok_or(CryptoFailure)?;
    let fits = match algorithm {
        SignatureAlgorithm::Rs256 | SignatureAlgorithm::Ps256 => is_ordinary_rsa_key(members),
        SignatureAlgorithm::EdDsa => is_ordinary_ed25519_key(members),
        SignatureAlgorithm::Es256 | SignatureAlgorithm::Es384 => true,
    };
    if !fits {
        return Err(CryptoFailure);
    }
    let key = Jwk::from_map(members.clone()).map_err(|_| CryptoFailure)?;
    read_verifier(algorithm, &key)
}

/// Whether a key of a client is read as a verification reads it and, for
/// RSA, withstands cheap factoring: tried only once it is known ordinary.
fn reads_client_key(algorithm: SignatureAlgorithm, public_jwk: &Value) -> bool {
    if read_public_key(algorithm, public_jwk).is_err() {
        return false;
    }
    match algorithm {
        SignatureAlgorithm::Rs256 | SignatureAlgorithm::Ps256 => public_jwk
            .get("n")
            .and_then(Value::as_str)
            .is_some_and(check_modulus_against_cheap_factoring),
        SignatureAlgorithm::Es256 | SignatureAlgorithm::Es384 | SignatureAlgorithm::EdDsa => true,
    }
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
        // The permit and the guard go with the work: a caller that gives up
        // frees neither a maker nor its share while it works.
        let maker = self.take_maker()?;
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

    async fn check_client_keys(
        &self,
        keys: Vec<(SignatureAlgorithm, Value)>,
        lane: KeyCheckLane,
        guard: KeyMakingGuard,
    ) -> Result<bool, KeyMakingFailure> {
        let place = match lane {
            KeyCheckLane::KeyMakers => self.take_maker()?,
            KeyCheckLane::Registration => take_place(&self.registration_checkers)?,
        };
        spawn_blocking(move || {
            let _held = (guard, place);
            keys.iter()
                .all(|(algorithm, key)| reads_client_key(*algorithm, key))
        })
        .await
        .map_err(|_| KeyMakingFailure::Failed)
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        public_jwk: &Value,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoFailure> {
        let verifier = read_public_key(algorithm, public_jwk)?;
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
    use openssl::bn::{BigNum, BigNumContext, BigNumRef};

    use saffui_core::ports::crypto::{KeyCheckLane, KeyMakingFailure, SignatureAlgorithm, Signer};
    use saffui_core::secret::Secret;
    use serde_json::{Value, json};

    use tokio::sync::Semaphore;

    use super::{JoseSigner, KEY_MAKERS, REGISTRATION_CHECKERS};
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

    /// Whether `key` is kept as a key of a client, for `algorithm`.
    async fn check_key(signer: &JoseSigner, algorithm: SignatureAlgorithm, key: &Value) -> bool {
        signer
            .check_client_keys(
                vec![(algorithm, key.clone())],
                KeyCheckLane::KeyMakers,
                Box::new(()),
            )
            .await
            .expect("a check")
    }

    /// A prime of `bits` bits, drawn as a signer draws one.
    fn draw_prime(bits: i32) -> BigNum {
        let mut prime = BigNum::new().expect("a number");
        prime
            .generate_prime(bits, false, None, None)
            .expect("a prime");
        prime
    }

    fn multiply(left: &BigNumRef, right: &BigNumRef) -> BigNum {
        let mut product = BigNum::new().expect("a number");
        let mut context = BigNumContext::new().expect("a context");
        product
            .checked_mul(left, right, &mut context)
            .expect("a product");
        product
    }

    /// The first number after `prime` that Fermat's test in base 2 takes
    /// for a prime: past 2048 bits, the next prime.
    fn find_next_prime(prime: &BigNumRef) -> BigNum {
        let mut context = BigNumContext::new().expect("a context");
        let (one, two) = (
            BigNum::from_u32(1).expect("one"),
            BigNum::from_u32(2).expect("two"),
        );
        let mut candidate = prime.to_owned().expect("a copy");
        loop {
            candidate.add_word(2).expect("the next odd number");
            let mut exponent = candidate.to_owned().expect("a copy");
            exponent.sub_word(1).expect("one less");
            let mut witness = BigNum::new().expect("a number");
            witness
                .mod_exp(&two, &exponent, &candidate, &mut context)
                .expect("a power");
            if witness == one {
                return candidate;
            }
        }
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
    async fn a_key_is_read_for_its_algorithm_as_a_verification_reads_it() {
        let signer = open_signer();
        for algorithm in list_served() {
            let key = signer
                .generate_key(algorithm, Box::new(()))
                .await
                .expect("a key");
            assert!(
                check_key(&signer, algorithm, &key.public_jwk).await,
                "{algorithm:?}"
            );
        }
        let p384 = signer
            .generate_key(SignatureAlgorithm::Es384, Box::new(()))
            .await
            .expect("a key");
        assert!(
            !check_key(&signer, ES256, &p384.public_jwk).await,
            "another curve"
        );
        for (key, why) in [
            (write_rsa_key(&make_modulus(384), &[3]), "the exponent 3"),
            (
                write_rsa_key(&make_modulus(1024), &[1, 0, 1]),
                "a modulus of 8192 bits",
            ),
            (json!("text"), "no key"),
        ] {
            for algorithm in [SignatureAlgorithm::Rs256, SignatureAlgorithm::Ps256] {
                assert!(
                    !check_key(&signer, algorithm, &key).await,
                    "{why}, read for {algorithm:?}"
                );
            }
        }
        let modulus = multiply(&draw_prime(2048), &draw_prime(2048));
        assert!(
            check_key(
                &signer,
                SignatureAlgorithm::Rs256,
                &write_rsa_key(&modulus.to_vec(), &[1, 0, 1])
            )
            .await,
            "an ordinary key of 4096 bits"
        );
        let set = vec![
            (SignatureAlgorithm::Es384, p384.public_jwk.clone()),
            (ES256, p384.public_jwk),
        ];
        assert_eq!(
            signer
                .check_client_keys(set, KeyCheckLane::KeyMakers, Box::new(()))
                .await,
            Ok(false),
            "one key refused refuses the set"
        );
    }

    /// Each modulus is read by a verification, which refuses none of them:
    /// only the check at registration does.
    #[tokio::test]
    async fn a_modulus_cheap_to_factor_is_refused_at_registration_and_read_to_verify() {
        let signer = open_signer();
        let (prime, other) = (draw_prime(2048), draw_prime(2048));
        let below_old_bound = BigNum::from_u32(8209).expect("a prime above 2^13");
        let below_bound = BigNum::from_u32(65_521).expect("the last prime below 2^16");

        for (modulus, why) in [
            (prime.to_owned().expect("a copy"), "a prime of 2048 bits"),
            (multiply(&prime, &prime), "the square of a prime"),
            (multiply(&below_old_bound, &other), "8209 times a prime"),
            (multiply(&below_bound, &other), "65521 times a prime"),
            (
                multiply(&prime, &find_next_prime(&prime)),
                "a prime times the next one",
            ),
        ] {
            let key = write_rsa_key(&modulus.to_vec(), &[1, 0, 1]);
            for algorithm in [SignatureAlgorithm::Rs256, SignatureAlgorithm::Ps256] {
                assert!(
                    !check_key(&signer, algorithm, &key).await,
                    "{why}, kept for {algorithm:?}"
                );
                assert_eq!(
                    signer.verify(algorithm, &key, MESSAGE, &[1; 512]),
                    Ok(false),
                    "{why}: a verification of {algorithm:?} reads it, and does not factor"
                );
            }
        }
        let ordinary = write_rsa_key(
            &multiply(&draw_prime(1024), &draw_prime(1024)).to_vec(),
            &[1, 0, 1],
        );
        for algorithm in [SignatureAlgorithm::Rs256, SignatureAlgorithm::Ps256] {
            assert!(
                check_key(&signer, algorithm, &ordinary).await,
                "an ordinary modulus of 2048 bits, for {algorithm:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_rsa_modulus_of_2047_bits_is_refused_though_it_fills_256_bytes() {
        let signer = open_signer();
        let mut short = make_modulus(256);
        short[0] = 0x7f;
        let mut behind_a_zero = vec![0_u8];
        behind_a_zero.extend(&short);
        let made = multiply(&draw_prime(1023), &draw_prime(1024));
        assert_eq!(made.num_bits(), 2047, "two primes as a signer draws them");

        for (key, why) in [
            (write_rsa_key(&short, &[1, 0, 1]), "2047 bits"),
            (
                write_rsa_key(&behind_a_zero, &[1, 0, 1]),
                "2047 bits behind a zero byte",
            ),
            (
                write_rsa_key(&made.to_vec(), &[1, 0, 1]),
                "2047 bits of two primes",
            ),
        ] {
            for algorithm in [SignatureAlgorithm::Rs256, SignatureAlgorithm::Ps256] {
                assert!(
                    signer.verify(algorithm, &key, MESSAGE, &[1; 256]).is_err(),
                    "{why}, read for {algorithm:?}"
                );
                assert!(
                    !check_key(&signer, algorithm, &key).await,
                    "{why}, kept for {algorithm:?}"
                );
            }
        }
        let mut leading_zero = vec![0_u8];
        leading_zero.extend(make_modulus(256));
        for key in [make_modulus(256), leading_zero] {
            assert_eq!(
                signer.verify(
                    SignatureAlgorithm::Rs256,
                    &write_rsa_key(&key, &[1, 0, 1]),
                    MESSAGE,
                    &[1; 256]
                ),
                Ok(false),
                "a modulus of 2048 bits is read, {} bytes written",
                key.len()
            );
        }
    }

    #[cfg(not(feature = "fips-strict"))]
    #[tokio::test]
    async fn a_key_of_small_order_is_refused_and_the_signature_anyone_makes_verifies_nothing() {
        use super::SMALL_ORDER_ED25519;

        let signer = open_signer();
        let eddsa = SignatureAlgorithm::EdDsa;
        let point_key = |point: &[u8]| {
            json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(point),
                "alg": "EdDSA",
            })
        };
        // R the neutral point, S zero: a signature of every message under
        // the neutral point, made without any private half.
        let mut trivial = vec![0_u8; 64];
        trivial[0] = 1;
        let neutral = point_key(&SMALL_ORDER_ED25519[1]);
        assert_eq!(neutral["x"], "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        assert_ne!(
            signer.verify(eddsa, &neutral, MESSAGE, &trivial),
            Ok(true),
            "the neutral point takes no signature for a proof"
        );
        for point in SMALL_ORDER_ED25519 {
            let mut negated = point;
            negated[31] |= 0x80;
            for encoded in [point, negated] {
                assert!(
                    !check_key(&signer, eddsa, &point_key(&encoded)).await,
                    "{encoded:02x?}"
                );
            }
        }
    }

    #[cfg(not(feature = "fips-strict"))]
    #[tokio::test]
    async fn a_key_on_ed448_is_neither_read_nor_verified_under_the_name_eddsa() {
        use crate::jose::jwk::KeyPair;
        use crate::jose::jwk::alg::ed::{EdCurve, EdKeyPair};
        use crate::jose::jws::alg::eddsa::EddsaJwsAlgorithm;
        use crate::jose::jws::{JwsSigner, JwsVerifier};

        let signer = open_signer();
        let pair = EdKeyPair::generate(EdCurve::Ed448).expect("a pair");
        let public_jwk = Value::Object(pair.to_jwk_public_key().into());
        let signature = EddsaJwsAlgorithm::Eddsa
            .signer_from_der(pair.to_der_private_key())
            .and_then(|made| made.sign(MESSAGE))
            .expect("a signature");
        // The layer reads it under the name EdDSA: only the product refuses it.
        let read_by_the_layer = EddsaJwsAlgorithm::Eddsa
            .verifier_from_jwk(&pair.to_jwk_public_key())
            .expect("a verifier");
        assert!(read_by_the_layer.verify(MESSAGE, &signature).is_ok());

        assert_eq!(public_jwk["crv"], "Ed448");
        assert!(!check_key(&signer, SignatureAlgorithm::EdDsa, &public_jwk).await);
        assert!(
            signer
                .verify(SignatureAlgorithm::EdDsa, &public_jwk, MESSAGE, &signature)
                .is_err()
        );
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
    async fn a_check_asked_while_every_maker_is_at_work_is_refused_at_once() {
        let signer = open_signer();
        let key = signer
            .generate_key(ES256, Box::new(()))
            .await
            .expect("a key");
        let at_work = Arc::clone(&signer.makers)
            .try_acquire_many_owned(u32::try_from(KEY_MAKERS).expect("a count"))
            .expect("every maker");

        assert_eq!(
            signer
                .check_client_keys(
                    vec![(ES256, key.public_jwk.clone())],
                    KeyCheckLane::KeyMakers,
                    Box::new(())
                )
                .await,
            Err(KeyMakingFailure::Busy)
        );
        drop(at_work);
        assert!(check_key(&signer, ES256, &key.public_jwk).await);
        assert_eq!(
            signer.makers.available_permits(),
            KEY_MAKERS,
            "its maker is given back once the check is done"
        );
    }

    #[tokio::test]
    async fn a_registration_checks_keys_on_its_own_lane_one_set_at_a_time() {
        let signer = open_signer();
        let key = signer
            .generate_key(ES256, Box::new(()))
            .await
            .expect("a key");
        let check = |lane| {
            signer.check_client_keys(vec![(ES256, key.public_jwk.clone())], lane, Box::new(()))
        };
        let makers_at_work = Arc::clone(&signer.makers)
            .try_acquire_many_owned(u32::try_from(KEY_MAKERS).expect("a count"))
            .expect("every maker");

        assert_eq!(
            check(KeyCheckLane::Registration).await,
            Ok(true),
            "no maker is taken"
        );
        let checking = Arc::clone(&signer.registration_checkers)
            .try_acquire_owned()
            .expect("the place of a registration");
        drop(makers_at_work);
        assert_eq!(
            check(KeyCheckLane::Registration).await,
            Err(KeyMakingFailure::Busy),
            "one registration at a time"
        );
        assert_eq!(
            check(KeyCheckLane::KeyMakers).await,
            Ok(true),
            "an administrator is not held up by it"
        );
        drop(checking);
        assert_eq!(check(KeyCheckLane::Registration).await, Ok(true));
        assert_eq!(
            signer.registration_checkers.available_permits(),
            REGISTRATION_CHECKERS,
            "its place is given back once the check is done"
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

    /// As for a key made: the check waits for the only blocking thread, and
    /// the caller hangs up meanwhile. The guard of the caller goes with the
    /// check, and is dropped while its maker is still taken.
    #[test]
    fn a_checking_maker_and_the_guard_of_its_caller_are_held_until_the_check_is_done() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .build()
            .expect("a runtime");
        let _inside = runtime.enter();
        let signer = open_signer();
        let key = write_rsa_key(
            &multiply(&draw_prime(1024), &draw_prime(1024)).to_vec(),
            &[1, 0, 1],
        );
        let alive = Arc::new(());
        let (told, seen) = mpsc::channel();
        let guard = Watch {
            digests: Arc::new(AtomicUsize::new(0)),
            makers: Arc::clone(&signer.makers),
            told,
            _alive: Arc::clone(&alive),
        };
        let (release, held) = mpsc::channel::<()>();
        let blocker = runtime.spawn_blocking(move || held.recv());
        {
            let mut checking = pin!(signer.check_client_keys(
                vec![(SignatureAlgorithm::Rs256, key)],
                KeyCheckLane::KeyMakers,
                Box::new(guard)
            ));
            let polled = checking
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()));
            assert!(polled.is_pending(), "the check waits for a blocking thread");
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
            assert!(Instant::now() < deadline, "the check is done in time");
            assert_eq!(
                signer.makers.available_permits(),
                KEY_MAKERS - 1,
                "the maker is never free while the guard is held"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            seen.recv_timeout(Duration::from_secs(1))
                .map(|(_, free)| free),
            Ok(KEY_MAKERS - 1),
            "the guard went with the check, its maker still taken"
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

    /// The one blocking thread waits until a tick has passed: a modulus
    /// checked on the thread that serves would be checked before the tick.
    #[test]
    fn a_modulus_is_checked_away_from_the_thread_that_waits_for_it() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .build()
            .expect("a runtime");
        let signer = open_signer();
        let key = write_rsa_key(&draw_prime(4096).to_vec(), &[1, 0, 1]);
        let (release, held) = mpsc::channel::<()>();
        let blocker = runtime.spawn_blocking(move || held.recv());
        let order = Mutex::new(Vec::new());
        let note = |what: &'static str| order.lock().expect("the order").push(what);

        let checked = runtime.block_on(async {
            let checking = async {
                let checked = signer
                    .check_client_keys(
                        vec![(SignatureAlgorithm::Rs256, key)],
                        KeyCheckLane::KeyMakers,
                        Box::new(()),
                    )
                    .await;
                note("checked");
                checked
            };
            let ticking = async {
                tokio::task::yield_now().await;
                note("tick");
                release.send(()).expect("the blocking thread let go");
            };
            tokio::join!(checking, ticking).0
        });

        assert_eq!(checked, Ok(false), "a prime of 4096 bits is refused");
        assert_eq!(*order.lock().expect("the order"), ["tick", "checked"]);
        drop(blocker);
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
        assert!(!check_key(&signer, eddsa, &public_jwk).await);
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
